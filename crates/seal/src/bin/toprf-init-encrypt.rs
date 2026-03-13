//! Operator-side tool for the S3-mediated init-seal ceremony.
//!
//! Fetches an attestation report, ephemeral public key, and certificate chain
//! from S3 (uploaded by the node in init-seal mode), verifies the attestation,
//! and encrypts a key share to the node's attested X25519 public key using ECIES.
//! The encrypted blob is uploaded to S3 for the node to pick up.
//!
//! Usage:
//!   toprf-init-encrypt \
//!       --attestation ./attestation.bin \
//!       --pubkey ./pubkey.bin \
//!       --certs ./certs.bin \
//!       --output ./encrypted-share.bin \
//!       --share-file ./node-shares/node-1-share.json \
//!       --expected-measurement <hex>

use std::env;
use std::process;

use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use toprf_seal::attestation::{parse_cert_table, AttestationVerifier};
use toprf_seal::ecies;
use toprf_seal::snp_report::SnpReport;

fn print_help() {
    eprintln!("Usage: toprf-init-encrypt [OPTIONS]");
    eprintln!();
    eprintln!("Encrypts a key share to a node's attested X25519 public key using ECIES.");
    eprintln!("(X25519 ECDH + HKDF-SHA256 + AES-256-GCM)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --attestation <PATH>       Path to attestation report (binary, 1184 bytes)");
    eprintln!("  --pubkey <PATH>            Path to node's ephemeral X25519 public key (32 bytes)");
    eprintln!("  --certs <PATH>             Path to certificate chain from extended report");
    eprintln!("  --output <PATH>            Path to write the ECIES-encrypted share");
    eprintln!("  --share-file <PATH>        Path to the node's key share JSON file");
    eprintln!("  --expected-measurement <HEX>  Expected measurement (96 hex chars)");
    eprintln!("  -h, --help                 Show this help");
    eprintln!();
    eprintln!("The operator downloads attestation.bin, pubkey.bin, and certs.bin from S3,");
    eprintln!("runs this tool locally, then uploads the output to S3.");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  aws s3 cp s3://bucket/init/attestation.bin ./attestation.bin");
    eprintln!("  aws s3 cp s3://bucket/init/pubkey.bin ./pubkey.bin");
    eprintln!("  aws s3 cp s3://bucket/init/certs.bin ./certs.bin");
    eprintln!("  toprf-init-encrypt \\");
    eprintln!("      --attestation ./attestation.bin \\");
    eprintln!("      --pubkey ./pubkey.bin \\");
    eprintln!("      --certs ./certs.bin \\");
    eprintln!("      --output ./encrypted-share.bin \\");
    eprintln!("      --share-file ./node-shares/node-1-share.json \\");
    eprintln!("      --expected-measurement <hex>");
    eprintln!("  aws s3 cp ./encrypted-share.bin s3://bucket/init/encrypted-share.bin");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut attestation_path: Option<String> = None;
    let mut pubkey_path: Option<String> = None;
    let mut certs_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut share_file: Option<String> = None;
    let mut expected_measurement: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--attestation" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: missing value for --attestation");
                    process::exit(1);
                }
                attestation_path = Some(args[i].clone());
            }
            "--pubkey" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: missing value for --pubkey");
                    process::exit(1);
                }
                pubkey_path = Some(args[i].clone());
            }
            "--certs" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: missing value for --certs");
                    process::exit(1);
                }
                certs_path = Some(args[i].clone());
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: missing value for --output");
                    process::exit(1);
                }
                output_path = Some(args[i].clone());
            }
            "--share-file" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: missing value for --share-file");
                    process::exit(1);
                }
                share_file = Some(args[i].clone());
            }
            "--expected-measurement" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: missing value for --expected-measurement");
                    process::exit(1);
                }
                expected_measurement = Some(args[i].clone());
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                eprintln!("Error: unknown argument '{other}'");
                eprintln!();
                print_help();
                process::exit(1);
            }
        }
        i += 1;
    }

    let attestation_path = attestation_path.unwrap_or_else(|| {
        eprintln!("Error: --attestation is required");
        process::exit(1);
    });
    let pubkey_path = pubkey_path.unwrap_or_else(|| {
        eprintln!("Error: --pubkey is required");
        process::exit(1);
    });
    let output_path = output_path.unwrap_or_else(|| {
        eprintln!("Error: --output is required");
        process::exit(1);
    });
    let share_file = share_file.unwrap_or_else(|| {
        eprintln!("Error: --share-file is required");
        process::exit(1);
    });
    let expected_measurement = expected_measurement.unwrap_or_else(|| {
        eprintln!("Error: --expected-measurement is required");
        process::exit(1);
    });

    // 1. Read the attestation report
    eprintln!("Reading attestation report from {attestation_path}");
    let attestation_bytes = std::fs::read(&attestation_path).unwrap_or_else(|e| {
        eprintln!("Error: failed to read attestation file: {e}");
        process::exit(1);
    });

    let report = SnpReport::from_bytes(&attestation_bytes).unwrap_or_else(|e| {
        eprintln!("Error: failed to parse attestation report: {e}");
        process::exit(1);
    });

    eprintln!("  Version:     {}", report.version);
    eprintln!("  Measurement: {}", hex::encode(report.measurement));
    eprintln!("  Policy:      {}", report.policy);
    eprintln!("  Chip ID:     {}", report.chip_id_hex());
    let (bl, tee, snp, ucode) = report.tcb_parts();
    eprintln!("  TCB:         bl={bl} tee={tee} snp={snp} ucode={ucode}");

    // 2. Verify measurement matches expected
    let actual_measurement = hex::encode(report.measurement);
    let expected_measurement = expected_measurement.trim().to_lowercase();
    if actual_measurement != expected_measurement {
        eprintln!("Error: measurement mismatch!");
        eprintln!("  Expected: {expected_measurement}");
        eprintln!("  Actual:   {actual_measurement}");
        process::exit(1);
    }
    eprintln!("  Measurement matches expected value.");

    // 2b. Verify VMPL == 0 (most privileged guest level)
    if report.vmpl != 0 {
        eprintln!(
            "Error: VMPL is {} — must be 0 for production nodes",
            report.vmpl
        );
        process::exit(1);
    }
    eprintln!("  VMPL: 0 (OK)");

    // 2c. Verify guest policy debug bit is NOT set (bit 19)
    if (report.policy >> 19) & 1 != 0 {
        eprintln!(
            "Error: guest policy has debug bit set (policy=0x{:x})",
            report.policy
        );
        eprintln!("  Debug-enabled VMs allow the hypervisor to read guest memory.");
        process::exit(1);
    }
    eprintln!("  Policy: 0x{:x} (debug disabled, OK)", report.policy);

    // 3. Verify attestation report signature (AMD certificate chain)
    if let Some(ref certs_file) = certs_path {
        // Use certificate chain from extended report (required for AWS EC2
        // where the chip ID is masked and AMD KDS is unavailable)
        eprintln!("  Reading certificate chain from {certs_file}");
        let cert_table_bytes = std::fs::read(certs_file).unwrap_or_else(|e| {
            eprintln!("Error: failed to read certs file: {e}");
            process::exit(1);
        });

        let certs = parse_cert_table(&cert_table_bytes).unwrap_or_else(|e| {
            eprintln!("Error: failed to parse certificate table: {e}");
            process::exit(1);
        });

        eprintln!(
            "  Certificates: VCEK={} bytes, ASK={} bytes, ARK={} bytes",
            certs.vcek.len(),
            certs.ask.len(),
            certs.ark.len()
        );
        eprintln!("  Verifying AMD certificate chain (VCEK -> ASK -> ARK)...");
        AttestationVerifier::verify_report_with_certs(&report, &certs).unwrap_or_else(|e| {
            eprintln!("Error: attestation verification failed: {e}");
            process::exit(1);
        });
        eprintln!("  Attestation report signature verified (using provided certs).");
    } else {
        // Fall back to fetching from AMD KDS (requires non-zero chip ID)
        eprintln!("  Verifying AMD certificate chain (fetching from AMD KDS)...");
        AttestationVerifier::verify_report(&report)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Error: attestation verification failed: {e}");
                eprintln!("  Hint: if chip ID is all zeros (AWS EC2), provide --certs from the node's extended report");
                process::exit(1);
            });
        eprintln!("  Attestation report signature verified (via AMD KDS).");
    }

    // 4. Read the node's ephemeral X25519 public key
    eprintln!("Reading ephemeral X25519 public key from {pubkey_path}");
    let pubkey_bytes = std::fs::read(&pubkey_path).unwrap_or_else(|e| {
        eprintln!("Error: failed to read pubkey file: {e}");
        process::exit(1);
    });

    if pubkey_bytes.len() != 32 {
        eprintln!(
            "Error: expected 32-byte X25519 public key, got {} bytes",
            pubkey_bytes.len()
        );
        process::exit(1);
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);
    let node_pubkey = PublicKey::from(pubkey_array);

    // 5. Verify REPORT_DATA binds to this public key
    //    The node puts SHA-256(pubkey) in the first 32 bytes of REPORT_DATA.
    let pubkey_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&pubkey_bytes);
        hasher.finalize()
    };

    if report.report_data[..32] != pubkey_hash[..] {
        eprintln!("Error: REPORT_DATA does not bind to the provided public key!");
        eprintln!(
            "  Expected SHA-256(pubkey): {}",
            hex::encode(&pubkey_hash[..])
        );
        eprintln!(
            "  REPORT_DATA[0..32]:      {}",
            hex::encode(&report.report_data[..32])
        );
        process::exit(1);
    }
    eprintln!("  Public key bound to attestation report (REPORT_DATA verified).");

    // 6. Read the key share
    eprintln!("Reading key share from {share_file}");
    let share_bytes = std::fs::read(&share_file).unwrap_or_else(|e| {
        eprintln!("Error: failed to read share file: {e}");
        process::exit(1);
    });

    // Validate it's parseable JSON (but don't hold the parsed struct)
    let _: serde_json::Value = serde_json::from_slice(&share_bytes).unwrap_or_else(|e| {
        eprintln!("Error: share file is not valid JSON: {e}");
        process::exit(1);
    });

    // 7. Encrypt with ECIES (X25519 + AES-256-GCM)
    eprintln!("Encrypting key share with ECIES (X25519 + AES-256-GCM)...");
    let encrypted = ecies::encrypt(&node_pubkey, &share_bytes).unwrap_or_else(|e| {
        eprintln!("Error: ECIES encryption failed: {e}");
        process::exit(1);
    });
    eprintln!(
        "  Encrypted blob: {} bytes (plaintext was {} bytes)",
        encrypted.len(),
        share_bytes.len()
    );

    // 8. Write the encrypted blob
    eprintln!("Writing encrypted share to {output_path}");
    std::fs::write(&output_path, &encrypted).unwrap_or_else(|e| {
        eprintln!("Error: failed to write output: {e}");
        process::exit(1);
    });

    eprintln!();
    eprintln!("Done. Upload the encrypted share to S3:");
    eprintln!("  aws s3 cp {output_path} s3://<bucket>/init/encrypted-share.bin");
}
