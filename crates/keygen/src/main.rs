//! Offline ceremony tool for OPRF key management.
//!
//! Two commands, run separately:
//!
//! 1. **`init`** — one-time. Generates a new OPRF key and splits it into
//!    admin shares (3-of-5) for offline vault storage.
//!
//!    ```sh
//!    toprf-keygen init \
//!        --admin-threshold 3 --admin-shares 5 \
//!        --output-dir ./ceremony
//!    ```
//!
//!    Output:
//!    ceremony/admin-{1..5}.json   ← store in physically secure vaults
//!
//! 2. **`node-shares`** — repeatable. Admins bring their shares, reconstruct
//!    the key, and produce node shares (2-of-3) for TEE deployment. Run this
//!    for every deployment or key rotation.
//!
//!    ```sh
//!    toprf-keygen node-shares \
//!        --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
//!        --node-threshold 2 --node-shares 3 \
//!        --output-dir ./node-shares
//!    ```
//!
//!    Output:
//!    node-shares/node-{1..3}-share.json  ← deploy to TEEs
//!    node-shares/public-config.json       ← consumed by deploy.sh
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

use toprf_core::combine::lagrange_coefficient;
use toprf_core::shamir::{share_to_scalar, split_key};
use toprf_core::{hex_to_point, point_to_hex, NodeKeyShare};

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
        "verify" => cmd_verify(&args[2..]),
        "evaluate" => cmd_evaluate(&args[2..]),
        "simulate" => cmd_simulate(&args[2..]),
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
    eprintln!("  init          One-time — generate OPRF key + admin shares");
    eprintln!("  node-shares   Repeatable — reconstruct from admin shares, produce node shares");
    eprintln!("  verify        Cross-verify admin and node shares reconstruct the same key");
    eprintln!("  evaluate      Reconstruct key from admin shares and evaluate a blinded point");
    eprintln!("  simulate      Full OPRF simulation: hash → blind → evaluate → unblind → derive ruonId");
    eprintln!();
    eprintln!("Run `toprf-keygen <COMMAND> --help` for details.");
}

/// Initial ceremony: generate a new OPRF key and split into admin shares only.
/// Node shares are produced separately via `toprf-keygen node-shares`.
fn cmd_init(args: &[String]) {
    let mut admin_threshold = 3u16;
    let mut admin_total = 5u16;
    let mut output_dir = String::from("./admin-shares");
    let mut existing_key: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-threshold" => {
                i += 1;
                admin_threshold = args[i].parse().expect("invalid admin-threshold");
            }
            "--admin-shares" => {
                i += 1;
                admin_total = args[i].parse().expect("invalid admin-shares");
            }
            "--output-dir" | "-o" => {
                i += 1;
                output_dir = args[i].to_string();
            }
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
                eprintln!("Error: --existing-key / -k is removed (keys visible in ps output).");
                eprintln!("Use --existing-key-file <PATH> instead.");
                std::process::exit(1);
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen init [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --admin-threshold <N>      Admin quorum threshold (default: 3)");
                eprintln!("  --admin-shares <N>         Total admin shares (default: 5)");
                eprintln!(
                    "  -o, --output-dir <DIR>     Output directory (default: ./admin-shares)"
                );
                eprintln!("  --existing-key-file <PATH> Read existing key (hex) from file");
                eprintln!("  -k, --existing-key <HEX>   (REMOVED — use --existing-key-file)");
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
    assert!(
        admin_total >= admin_threshold,
        "admin shares must be >= admin threshold"
    );

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

    // Split into admin shares
    eprintln!("[*] Splitting into {admin_threshold}-of-{admin_total} admin shares...");
    let admin_result =
        split_key(&secret, admin_threshold, admin_total).expect("admin key split failed");

    for share in &admin_result.shares {
        let filename = format!("admin-{}.json", share.node_id);
        let filepath = out_path.join(&filename);
        let json = serde_json::to_string_pretty(share).expect("failed to serialize");
        write_secret_file(&filepath, &json).expect("failed to write admin share");
        eprintln!("[+] Wrote {}", filepath.display());
    }

    // Fingerprint
    let mut hasher = Sha256::new();
    for share in &admin_result.shares {
        hasher.update(&share.verification_share);
    }
    let fingerprint = hex::encode(hasher.finalize());

    eprintln!();
    eprintln!("[*] Ceremony fingerprint: {fingerprint}");
    eprintln!(
        "[*] Admin shares: {admin_threshold}-of-{admin_total} — store in physically secure vaults"
    );
    eprintln!();
    eprintln!("[*] Next: run `toprf-keygen node-shares` to produce node shares for deployment.");
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
            "--admin-share" | "-a" => {
                i += 1;
                admin_share_files.push(args[i].to_string());
            }
            "--node-threshold" => {
                i += 1;
                node_threshold = args[i].parse().expect("invalid node-threshold");
            }
            "--node-shares" => {
                i += 1;
                node_total = args[i].parse().expect("invalid node-shares");
            }
            "--output-dir" | "-o" => {
                i += 1;
                output_dir = args[i].to_string();
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen node-shares [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  -a, --admin-share <F>   Path to an admin share JSON (repeat for each share)"
                );
                eprintln!("  --node-threshold <N>    Node quorum threshold (default: 2)");
                eprintln!("  --node-shares <N>       Total node shares (default: 3)");
                eprintln!(
                    "  -o, --output-dir <DIR>  Output directory (default: ./new-node-shares)"
                );
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
        let json =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        let share: NodeKeyShare =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
        eprintln!(
            "[*] Loaded admin share {} (node_id={})",
            path, share.node_id
        );
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
            admin_threshold,
            admin_shares.len()
        );
        std::process::exit(1);
    }

    // Reconstruct the secret key via Lagrange interpolation
    eprintln!(
        "[*] Reconstructing key from {} admin shares (threshold={})...",
        admin_shares.len(),
        admin_threshold
    );

    let node_ids: Vec<u16> = admin_shares.iter().map(|s| s.node_id).collect();
    let mut secret = Zeroizing::new(Scalar::ZERO);
    for share in &admin_shares {
        let scalar = Zeroizing::new(
            share_to_scalar(share)
                .unwrap_or_else(|e| panic!("invalid share for admin {}: {e}", share.node_id)),
        );
        let lambda = lagrange_coefficient(share.node_id, &node_ids).unwrap_or_else(|e| {
            panic!("lagrange coefficient error for node {}: {e}", share.node_id)
        });
        *secret += lambda * *scalar;
    }

    // Verify reconstruction by checking against expected group public key
    let reconstructed_pk = ProjectivePoint::mul_by_generator(&*secret);
    let reconstructed_pk_hex = point_to_hex(&reconstructed_pk);

    if reconstructed_pk_hex != *expected_gpk {
        eprintln!("FATAL: reconstructed key does not match expected group public key!");
        eprintln!("  Expected: {expected_gpk}");
        eprintln!("  Got:      {reconstructed_pk_hex}");
        eprintln!(
            "  This likely means the admin shares are corrupted or from different ceremonies."
        );
        std::process::exit(1);
    }

    eprintln!("[*] Key reconstructed successfully — group public key: {reconstructed_pk_hex}");

    // Split into new node shares
    assert!(node_threshold >= 2, "node threshold must be >= 2");
    assert!(
        node_total >= node_threshold,
        "node shares must be >= node threshold"
    );

    eprintln!("[*] Splitting into {node_threshold}-of-{node_total} node shares...");
    let node_result =
        split_key(&secret, node_threshold, node_total).expect("node key split failed");

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

/// Reconstruct the secret key from a set of key shares via Lagrange interpolation.
fn reconstruct_key(shares: &[NodeKeyShare]) -> Zeroizing<Scalar> {
    let node_ids: Vec<u16> = shares.iter().map(|s| s.node_id).collect();
    let mut secret = Zeroizing::new(Scalar::ZERO);
    for share in shares {
        let scalar = Zeroizing::new(
            share_to_scalar(share)
                .unwrap_or_else(|e| panic!("invalid share for node {}: {e}", share.node_id)),
        );
        let lambda = lagrange_coefficient(share.node_id, &node_ids).unwrap_or_else(|e| {
            panic!("lagrange coefficient error for node {}: {e}", share.node_id)
        });
        *secret += lambda * *scalar;
    }
    secret
}

/// Load share files from disk.
fn load_shares(paths: &[String]) -> Vec<NodeKeyShare> {
    let mut shares = Vec::new();
    for path in paths {
        let json =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        let share: NodeKeyShare =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
        eprintln!("[*] Loaded share {} (node_id={})", path, share.node_id);
        shares.push(share);
    }
    shares
}

/// Cross-verify that admin shares and node shares reconstruct the same key.
fn cmd_verify(args: &[String]) {
    let mut admin_share_files: Vec<String> = Vec::new();
    let mut node_share_files: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-share" | "-a" => {
                i += 1;
                admin_share_files.push(args[i].to_string());
            }
            "--node-share" | "-n" => {
                i += 1;
                node_share_files.push(args[i].to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen verify [OPTIONS]");
                eprintln!();
                eprintln!("Cross-verify that admin shares and node shares reconstruct the same key.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -a, --admin-share <F>  Path to an admin share JSON (repeat for threshold)");
                eprintln!("  -n, --node-share <F>   Path to a node share JSON (repeat for threshold)");
                eprintln!("  -h, --help             Show this help");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if admin_share_files.is_empty() || node_share_files.is_empty() {
        eprintln!("Error: need at least --admin-share and --node-share arguments");
        std::process::exit(1);
    }

    eprintln!("[*] Loading admin shares...");
    let admin_shares = load_shares(&admin_share_files);
    let admin_threshold = admin_shares[0].threshold;

    if admin_shares.len() < admin_threshold as usize {
        eprintln!(
            "Error: need at least {} admin shares (got {})",
            admin_threshold,
            admin_shares.len()
        );
        std::process::exit(1);
    }

    eprintln!("[*] Loading node shares...");
    let node_shares = load_shares(&node_share_files);
    let node_threshold = node_shares[0].threshold;

    if node_shares.len() < node_threshold as usize {
        eprintln!(
            "Error: need at least {} node shares (got {})",
            node_threshold,
            node_shares.len()
        );
        std::process::exit(1);
    }

    // Reconstruct from admin shares
    eprintln!(
        "[*] Reconstructing from {} admin shares (threshold={})...",
        admin_shares.len(),
        admin_threshold
    );
    let admin_secret = reconstruct_key(&admin_shares);
    let admin_pk = ProjectivePoint::mul_by_generator(&*admin_secret);
    let admin_pk_hex = point_to_hex(&admin_pk);
    eprintln!("[*] Admin reconstruction → group public key: {admin_pk_hex}");

    // Verify against share metadata
    if admin_pk_hex != admin_shares[0].group_public_key {
        eprintln!("FATAL: admin reconstruction does not match share metadata!");
        eprintln!("  Metadata:       {}", admin_shares[0].group_public_key);
        eprintln!("  Reconstructed:  {admin_pk_hex}");
        std::process::exit(1);
    }

    // Reconstruct from node shares
    eprintln!(
        "[*] Reconstructing from {} node shares (threshold={})...",
        node_shares.len(),
        node_threshold
    );
    let node_secret = reconstruct_key(&node_shares);
    let node_pk = ProjectivePoint::mul_by_generator(&*node_secret);
    let node_pk_hex = point_to_hex(&node_pk);
    eprintln!("[*] Node reconstruction → group public key: {node_pk_hex}");

    // Compare
    use k256::elliptic_curve::subtle::ConstantTimeEq;
    if !bool::from(admin_secret.ct_eq(&*node_secret)) {
        eprintln!();
        eprintln!("FATAL: admin shares and node shares reconstruct DIFFERENT keys!");
        eprintln!("  Admin group public key: {admin_pk_hex}");
        eprintln!("  Node group public key:  {node_pk_hex}");
        std::process::exit(1);
    }

    eprintln!();
    eprintln!("[*] PASS: both share sets reconstruct the same key");
    eprintln!("[*] Group public key: {admin_pk_hex}");
}

/// Reconstruct the key from admin shares and evaluate a blinded point.
fn cmd_evaluate(args: &[String]) {
    let mut admin_share_files: Vec<String> = Vec::new();
    let mut blinded_point_hex: Option<String> = None;
    let mut expected_hex: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-share" | "-a" => {
                i += 1;
                admin_share_files.push(args[i].to_string());
            }
            "--blinded-point" | "-b" => {
                i += 1;
                blinded_point_hex = Some(args[i].to_string());
            }
            "--expected" | "-e" => {
                i += 1;
                expected_hex = Some(args[i].to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen evaluate [OPTIONS]");
                eprintln!();
                eprintln!("Reconstruct the key from admin shares and evaluate a blinded point.");
                eprintln!("Outputs the evaluation point (hex) to stdout.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -a, --admin-share <F>      Path to an admin share JSON (repeat for threshold)");
                eprintln!("  -b, --blinded-point <HEX>  Blinded point to evaluate (compressed SEC1 hex)");
                eprintln!("  -e, --expected <HEX>       Expected evaluation result (exits 1 on mismatch)");
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

    if admin_share_files.is_empty() {
        eprintln!("Error: at least one --admin-share is required");
        std::process::exit(1);
    }
    let blinded_hex = blinded_point_hex.unwrap_or_else(|| {
        eprintln!("Error: --blinded-point is required");
        std::process::exit(1);
    });

    // Load admin shares
    eprintln!("[*] Loading admin shares...");
    let admin_shares = load_shares(&admin_share_files);
    let admin_threshold = admin_shares[0].threshold;

    if admin_shares.len() < admin_threshold as usize {
        eprintln!(
            "Error: need at least {} admin shares (got {})",
            admin_threshold,
            admin_shares.len()
        );
        std::process::exit(1);
    }

    // Reconstruct key
    eprintln!(
        "[*] Reconstructing key from {} admin shares (threshold={})...",
        admin_shares.len(),
        admin_threshold
    );
    let secret = reconstruct_key(&admin_shares);
    let pk = ProjectivePoint::mul_by_generator(&*secret);
    let pk_hex = point_to_hex(&pk);
    eprintln!("[*] Group public key: {pk_hex}");

    // Verify reconstruction
    if pk_hex != admin_shares[0].group_public_key {
        eprintln!("FATAL: reconstructed key does not match share metadata!");
        std::process::exit(1);
    }

    // Parse blinded point
    let blinded_point = hex_to_point(&blinded_hex).unwrap_or_else(|e| {
        eprintln!("Error: invalid blinded point: {e}");
        std::process::exit(1);
    });

    // Evaluate: E = k * B
    let evaluation = blinded_point * &*secret;
    let eval_hex = point_to_hex(&evaluation);

    // Output to stdout (for scripting)
    println!("{eval_hex}");
    eprintln!("[*] Evaluation: {eval_hex}");

    // Compare with expected if provided
    if let Some(expected) = expected_hex {
        let expected = expected.trim().to_lowercase();
        if eval_hex == expected {
            eprintln!("[*] PASS: matches expected evaluation");
        } else {
            eprintln!();
            eprintln!("FATAL: evaluation does not match expected!");
            eprintln!("  Expected: {expected}");
            eprintln!("  Got:      {eval_hex}");
            std::process::exit(1);
        }
    }
}

/// Simulate the full mobile app OPRF flow:
///   hash_to_curve(nationality, nationalId) → H
///   blind: B = r * H
///   evaluate: E = k * B
///   unblind: U = r^{-1} * E = k * H
///   derive: ruonId = keccak256(U.x || U.y)
fn cmd_simulate(args: &[String]) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha3::Digest as _;

    let mut admin_share_files: Vec<String> = Vec::new();
    let mut nationality: Option<String> = None;
    let mut national_id: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-share" | "-a" => {
                i += 1;
                admin_share_files.push(args[i].to_string());
            }
            "--nationality" => {
                i += 1;
                nationality = Some(args[i].to_string());
            }
            "--national-id" => {
                i += 1;
                national_id = Some(args[i].to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-keygen simulate [OPTIONS]");
                eprintln!();
                eprintln!("Simulate the full mobile app OPRF flow locally.");
                eprintln!("hash_to_curve → blind → evaluate → unblind → derive ruonId");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  -a, --admin-share <F>    Path to an admin share JSON (repeat for threshold)"
                );
                eprintln!("  --nationality <STR>      Nationality (as passed to hashToCurve, e.g. \"Singapore\")");
                eprintln!("  --national-id <STR>      National ID number (e.g. \"S1234567A\")");
                eprintln!("  -h, --help               Show this help");
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
    let nationality = nationality.unwrap_or_else(|| {
        eprintln!("Error: --nationality is required");
        std::process::exit(1);
    });
    let national_id = national_id.unwrap_or_else(|| {
        eprintln!("Error: --national-id is required");
        std::process::exit(1);
    });

    // Load admin shares and reconstruct key
    eprintln!("[*] Loading admin shares...");
    let admin_shares = load_shares(&admin_share_files);
    let admin_threshold = admin_shares[0].threshold;

    if admin_shares.len() < admin_threshold as usize {
        eprintln!(
            "Error: need at least {} admin shares (got {})",
            admin_threshold,
            admin_shares.len()
        );
        std::process::exit(1);
    }

    eprintln!(
        "[*] Reconstructing key from {} admin shares (threshold={})...",
        admin_shares.len(),
        admin_threshold
    );
    let secret = reconstruct_key(&admin_shares);
    let pk = ProjectivePoint::mul_by_generator(&*secret);
    let pk_hex = point_to_hex(&pk);
    eprintln!("[*] Group public key: {pk_hex}");

    if pk_hex != admin_shares[0].group_public_key {
        eprintln!("FATAL: reconstructed key does not match share metadata!");
        std::process::exit(1);
    }

    // Step 1: hash_to_curve(nationality, nationalId) → H
    eprintln!();
    eprintln!("[*] Step 1: hash_to_curve(\"{nationality}\", \"{national_id}\")");
    let h = toprf_core::hash_to_curve::hash_to_curve(&nationality, &national_id).unwrap_or_else(
        |e| {
            eprintln!("Error: hash_to_curve failed: {e}");
            std::process::exit(1);
        },
    );
    eprintln!("[*]   H = {}", point_to_hex(&h));

    // Step 2: blind — B = r * H
    eprintln!("[*] Step 2: blind (B = r * H)");
    let r = Zeroizing::new(Scalar::random(&mut OsRng));
    let blinded = h * &*r;
    eprintln!("[*]   B = {}", point_to_hex(&blinded));

    // Step 3: evaluate — E = k * B
    eprintln!("[*] Step 3: evaluate (E = k * B)");
    let evaluation = blinded * &*secret;
    eprintln!("[*]   E = {}", point_to_hex(&evaluation));

    // Step 4: unblind — U = r^{-1} * E
    eprintln!("[*] Step 4: unblind (U = r^{{-1}} * E)");
    let r_inv = Zeroizing::new(r.invert().unwrap());
    let unblinded = evaluation * &*r_inv;
    let unblinded_hex = point_to_hex(&unblinded);
    eprintln!("[*]   U = {unblinded_hex}");

    // Consistency check: U should equal k * H (direct computation)
    let direct = h * &*secret;
    assert_eq!(
        unblinded_hex,
        point_to_hex(&direct),
        "blind/unblind consistency check failed"
    );
    eprintln!("[*]   Consistency check: PASS (U == k * H)");

    // Step 5: derive ruonId and identitySalt (matches app's deriveFromUnblinded)
    eprintln!("[*] Step 5: derive ruonId = keccak256(U.x || U.y)");

    let affine = unblinded.to_affine();
    let encoded = affine.to_encoded_point(false); // uncompressed: 04 || x(32) || y(32)
    let x_bytes = encoded.x().unwrap();
    let y_bytes = encoded.y().unwrap();

    // ruonId = keccak256(x || y)
    let mut hasher = sha3::Keccak256::new();
    hasher.update(x_bytes);
    hasher.update(y_bytes);
    let ruon_id_bytes = hasher.finalize();
    let ruon_id = format!("0x{}", hex::encode(ruon_id_bytes));

    // identitySalt = BigInt(keccak256("salt" || x || y))
    let mut salt_hasher = sha3::Keccak256::new();
    salt_hasher.update(b"salt");
    salt_hasher.update(x_bytes);
    salt_hasher.update(y_bytes);
    let salt_bytes = salt_hasher.finalize();
    let identity_salt = format!("0x{}", hex::encode(salt_bytes));

    eprintln!();
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  OPRF RESULT                                                 ║");
    eprintln!("╠═══════════════════════════════════════════════════════════════╣");
    eprintln!("║  Unblinded point:                                            ║");
    eprintln!("║    {unblinded_hex}  ║");
    eprintln!("║                                                              ║");
    eprintln!("║  ruonId:                                                     ║");
    eprintln!("║    {ruon_id}  ║");
    eprintln!("║                                                              ║");
    eprintln!("║  identitySalt:                                               ║");
    eprintln!("║    {identity_salt}  ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");

    // Output ruonId to stdout for scripting
    println!("{ruon_id}");
}
