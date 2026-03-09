//! Offline ceremony tool for OPRF key management.
//!
//! Two modes of operation:
//!
//! 1. **Initial ceremony** — generates a new OPRF key, splits it into
//!    admin shares (3-of-5) for offline vault storage AND node shares
//!    (2-of-3) for loading into TEEs.
//!
//!    toprf-keygen init \
//!      --admin-threshold 3 --admin-shares 5 \
//!      --node-threshold 2 --node-shares 3 \
//!      --output-dir ./ceremony
//!
//! 2. **Node-shares ceremony** — admins bring their shares, reconstruct
//!    the key, and produce new node shares for new TEEs. Used for
//!    infrastructure migration.
//!
//!    toprf-keygen node-shares \
//!      --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
//!      --node-threshold 2 --node-shares 3 \
//!      --output-dir ./new-node-shares
//!
//! SECURITY:
//!   - Run on an air-gapped machine.
//!   - After the ceremony, DESTROY THE MACHINE.
//!   - The original key exists only in memory during the ceremony.
//!   - Admin shares go into physically secure vaults (bank safe deposit boxes, etc).
//!   - Node shares are loaded into TEEs over attested TLS, then destroyed.

use std::env;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use toprf_core::shamir::{split_key, share_to_scalar};
use toprf_core::combine::lagrange_coefficient;
use toprf_core::{point_to_hex, NodeKeyShare};

/// Write a file containing secret key material with restrictive permissions (0600).
/// This ensures key shares and admin keys are not world-readable.
fn write_secret_file(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    opts.mode(0o600);

    let mut file = opts.open(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "init" => cmd_init(&args[2..]),
        "node-shares" => cmd_node_shares(&args[2..]),
        other => {
            eprintln!("Unknown command: {other}");
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: toprf-keygen <COMMAND> [OPTIONS]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  init          Initial ceremony — generate key + admin shares + node shares");
    eprintln!("  node-shares   Migration ceremony — reconstruct from admin shares, produce new node shares");
    eprintln!();
    eprintln!("Run `toprf-keygen <COMMAND> --help` for details.");
}

/// Initial ceremony: generate a new OPRF key and split into admin + node shares.
fn cmd_init(args: &[String]) {
    let mut admin_threshold = 3u16;
    let mut admin_total = 5u16;
    let mut node_threshold = 2u16;
    let mut node_total = 3u16;
    let mut output_dir = String::from("./ceremony");
    let mut existing_key: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-threshold" => { i += 1; admin_threshold = args[i].parse().expect("invalid admin-threshold"); }
            "--admin-shares" => { i += 1; admin_total = args[i].parse().expect("invalid admin-shares"); }
            "--node-threshold" => { i += 1; node_threshold = args[i].parse().expect("invalid node-threshold"); }
            "--node-shares" => { i += 1; node_total = args[i].parse().expect("invalid node-shares"); }
            "--output-dir" | "-o" => { i += 1; output_dir = args[i].to_string(); }
            "--existing-key-file" => {
                i += 1;
                let path = &args[i];
                let key_hex = std::fs::read_to_string(path)
                    .expect("failed to read key file")
                    .trim()
                    .to_string();
                existing_key = Some(key_hex);
            }
            "--existing-key" | "-k" => {
                eprintln!("WARNING: passing keys via CLI is insecure (visible in ps output). Use --existing-key-file instead.");
                i += 1;
                existing_key = Some(args[i].clone());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen init [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --admin-threshold <N>      Admin quorum threshold (default: 3)");
                eprintln!("  --admin-shares <N>         Total admin shares (default: 5)");
                eprintln!("  --node-threshold <N>       Node quorum threshold (default: 2)");
                eprintln!("  --node-shares <N>          Total node shares (default: 3)");
                eprintln!("  -o, --output-dir <DIR>     Output directory (default: ./ceremony)");
                eprintln!("  --existing-key-file <PATH> Read existing key (hex) from file");
                eprintln!("  -k, --existing-key <HEX>   Split an existing key (INSECURE — use --existing-key-file)");
                eprintln!("  -h, --help                 Show this help");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    assert!(admin_threshold >= 2, "admin threshold must be >= 2");
    assert!(admin_total >= admin_threshold, "admin shares must be >= admin threshold");
    assert!(node_threshold >= 2, "node threshold must be >= 2");
    assert!(node_total >= node_threshold, "node shares must be >= node threshold");

    // Generate or use existing key
    let secret = Zeroizing::new(match existing_key {
        Some(hex_key) => {
            eprintln!("[*] Using existing key");
            toprf_core::hex_to_scalar(&hex_key).expect("invalid hex key")
        }
        None => {
            eprintln!("[*] Generating new random OPRF secret key");
            Scalar::random(&mut OsRng)
        }
    });

    let group_pk = ProjectivePoint::mul_by_generator(&*secret);
    let group_pk_hex = point_to_hex(&group_pk);
    eprintln!("[*] Group public key: {group_pk_hex}");

    let out_path = Path::new(&output_dir);
    fs::create_dir_all(out_path).expect("failed to create output directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o700))
            .expect("failed to set output directory permissions");
    }

    // -- Admin shares (3-of-5) --
    eprintln!("[*] Splitting into {admin_threshold}-of-{admin_total} admin shares...");
    let admin_result = split_key(&*secret, admin_threshold, admin_total)
        .expect("admin key split failed");

    let admin_dir = out_path.join("admin-shares");
    fs::create_dir_all(&admin_dir).expect("failed to create admin-shares directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&admin_dir, std::fs::Permissions::from_mode(0o700))
            .expect("failed to set admin-shares directory permissions");
    }

    for share in &admin_result.shares {
        let filename = format!("admin-{}.json", share.node_id);
        let filepath = admin_dir.join(&filename);
        let json = serde_json::to_string_pretty(share).expect("failed to serialize");
        write_secret_file(&filepath, &json).expect("failed to write admin share");
        eprintln!("[+] Wrote {}", filepath.display());
    }

    // -- Node shares (2-of-3) --
    eprintln!("[*] Splitting into {node_threshold}-of-{node_total} node shares...");
    let node_result = split_key(&*secret, node_threshold, node_total)
        .expect("node key split failed");

    let node_dir = out_path.join("node-shares");
    fs::create_dir_all(&node_dir).expect("failed to create node-shares directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&node_dir, std::fs::Permissions::from_mode(0o700))
            .expect("failed to set node-shares directory permissions");
    }

    for share in &node_result.shares {
        let filename = format!("node-{}-share.json", share.node_id);
        let filepath = node_dir.join(&filename);
        let json = serde_json::to_string_pretty(share).expect("failed to serialize");
        write_secret_file(&filepath, &json).expect("failed to write node share");
        eprintln!("[+] Wrote {}", filepath.display());
    }

    // -- Public config (node verification shares for coordinator) --
    let public_config = serde_json::json!({
        "group_public_key": node_result.group_public_key,
        "threshold": node_result.threshold,
        "total_shares": node_result.total_shares,
        "verification_shares": node_result.shares.iter().map(|s| {
            serde_json::json!({
                "node_id": s.node_id,
                "verification_share": s.verification_share,
            })
        }).collect::<Vec<_>>(),
    });
    let config_path = out_path.join("public-config.json");
    let json = serde_json::to_string_pretty(&public_config).expect("failed to serialize config");
    fs::write(&config_path, &json).expect("failed to write config");
    eprintln!("[+] Wrote {}", config_path.display());

    // Fingerprint
    let mut hasher = Sha256::new();
    for share in &admin_result.shares {
        hasher.update(&share.verification_share);
    }
    for share in &node_result.shares {
        hasher.update(&share.verification_share);
    }
    let fingerprint = hex::encode(hasher.finalize());

    eprintln!();
    eprintln!("[*] Ceremony fingerprint: {fingerprint}");
    eprintln!("[*] Admin shares: {admin_threshold}-of-{admin_total} — store in physically secure vaults");
    eprintln!("[*] Node shares: {node_threshold}-of-{node_total} — load into TEEs over attested TLS");
    eprintln!();
    eprintln!("[!] DESTROY THIS MACHINE. The secret key existed in memory during this process.");
}

/// Migration ceremony: reconstruct key from admin shares, produce new node shares.
fn cmd_node_shares(args: &[String]) {
    let mut admin_share_files: Vec<String> = Vec::new();
    let mut node_threshold = 2u16;
    let mut node_total = 3u16;
    let mut output_dir = String::from("./new-node-shares");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-share" | "-a" => { i += 1; admin_share_files.push(args[i].to_string()); }
            "--node-threshold" => { i += 1; node_threshold = args[i].parse().expect("invalid node-threshold"); }
            "--node-shares" => { i += 1; node_total = args[i].parse().expect("invalid node-shares"); }
            "--output-dir" | "-o" => { i += 1; output_dir = args[i].to_string(); }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen node-shares [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -a, --admin-share <F>   Path to an admin share JSON (repeat for each share)");
                eprintln!("  --node-threshold <N>    Node quorum threshold (default: 2)");
                eprintln!("  --node-shares <N>       Total node shares (default: 3)");
                eprintln!("  -o, --output-dir <DIR>  Output directory (default: ./new-node-shares)");
                eprintln!("  -h, --help              Show this help");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if admin_share_files.is_empty() {
        eprintln!("Error: at least one --admin-share is required");
        std::process::exit(1);
    }

    // Load admin shares
    let mut admin_shares: Vec<NodeKeyShare> = Vec::new();
    for path in &admin_share_files {
        let json = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        let share: NodeKeyShare = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
        eprintln!("[*] Loaded admin share {} (node_id={})", path, share.node_id);
        admin_shares.push(share);
    }

    // Verify all shares reference the same group public key
    let expected_gpk = &admin_shares[0].group_public_key;
    let admin_threshold = admin_shares[0].threshold;
    for share in &admin_shares[1..] {
        if share.group_public_key != *expected_gpk {
            eprintln!("Error: admin shares have mismatched group public keys");
            std::process::exit(1);
        }
    }

    if admin_shares.len() < admin_threshold as usize {
        eprintln!(
            "Error: need at least {} admin shares (got {})",
            admin_threshold, admin_shares.len()
        );
        std::process::exit(1);
    }

    // Reconstruct the secret key via Lagrange interpolation
    eprintln!("[*] Reconstructing key from {} admin shares (threshold={})...",
        admin_shares.len(), admin_threshold);

    let node_ids: Vec<u16> = admin_shares.iter().map(|s| s.node_id).collect();
    let mut secret = Zeroizing::new(Scalar::ZERO);
    for share in &admin_shares {
        let scalar = Zeroizing::new(share_to_scalar(share)
            .unwrap_or_else(|e| panic!("invalid share for admin {}: {e}", share.node_id)));
        let lambda = lagrange_coefficient(share.node_id, &node_ids)
            .unwrap_or_else(|e| panic!("lagrange coefficient error for node {}: {e}", share.node_id));
        *secret = *secret + lambda * *scalar;
    }

    // Verify reconstruction by checking against expected group public key
    let reconstructed_pk = ProjectivePoint::mul_by_generator(&*secret);
    let reconstructed_pk_hex = point_to_hex(&reconstructed_pk);

    if reconstructed_pk_hex != *expected_gpk {
        eprintln!("FATAL: reconstructed key does not match expected group public key!");
        eprintln!("  Expected: {expected_gpk}");
        eprintln!("  Got:      {reconstructed_pk_hex}");
        eprintln!("  This likely means the admin shares are corrupted or from different ceremonies.");
        std::process::exit(1);
    }

    eprintln!("[*] Key reconstructed successfully — group public key: {reconstructed_pk_hex}");

    // Split into new node shares
    assert!(node_threshold >= 2, "node threshold must be >= 2");
    assert!(node_total >= node_threshold, "node shares must be >= node threshold");

    eprintln!("[*] Splitting into {node_threshold}-of-{node_total} node shares...");
    let node_result = split_key(&*secret, node_threshold, node_total)
        .expect("node key split failed");

    // Verify the new split produces the same group public key
    assert_eq!(
        node_result.group_public_key, *expected_gpk,
        "new node split group key mismatch"
    );

    let out_path = Path::new(&output_dir);
    fs::create_dir_all(out_path).expect("failed to create output directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o700))
            .expect("failed to set output directory permissions");
    }

    for share in &node_result.shares {
        let filename = format!("node-{}-share.json", share.node_id);
        let filepath = out_path.join(&filename);
        let json = serde_json::to_string_pretty(share).expect("failed to serialize");
        write_secret_file(&filepath, &json).expect("failed to write node share");
        eprintln!("[+] Wrote {}", filepath.display());
    }

    // Public config for coordinator
    let public_config = serde_json::json!({
        "group_public_key": node_result.group_public_key,
        "threshold": node_result.threshold,
        "total_shares": node_result.total_shares,
        "verification_shares": node_result.shares.iter().map(|s| {
            serde_json::json!({
                "node_id": s.node_id,
                "verification_share": s.verification_share,
            })
        }).collect::<Vec<_>>(),
    });
    let config_path = out_path.join("public-config.json");
    let json = serde_json::to_string_pretty(&public_config).expect("failed to serialize config");
    fs::write(&config_path, &json).expect("failed to write config");
    eprintln!("[+] Wrote {}", config_path.display());

    // Fingerprint
    let mut hasher = Sha256::new();
    for share in &node_result.shares {
        hasher.update(&share.verification_share);
    }
    let fingerprint = hex::encode(hasher.finalize());

    eprintln!();
    eprintln!("[*] Node shares fingerprint: {fingerprint}");
    eprintln!("[*] Load these shares into TEEs over attested TLS, then destroy the files.");
    eprintln!();
    eprintln!("[!] DESTROY THIS MACHINE. The secret key existed in memory during this process.");
}
