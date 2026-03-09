//! CLI tool to seal a node key share (v1 format, HKDF-based).
//!
//! Usage: toprf-seal --share <path> --measurement <hex> --policy <u64> --output <path>
//!
//! Creates a v1 sealed blob bound to measurement + policy. This can be
//! decrypted by ANY VM with the matching measurement (not chip-specific).
//!
//! For chip-specific sealing (v2, MSG_KEY_REQ), use `toprf-node --init-seal`
//! which runs inside the TEE and binds the blob to the specific physical CPU.

use std::env;
use std::fs;
use std::process;

use toprf_seal::sealing;

fn print_help() {
    eprintln!("Usage: toprf-seal --share <PATH> --measurement <HEX> --policy <U64> --output <PATH>");
    eprintln!();
    eprintln!("Seals a node key share file (as produced by toprf-keygen) so it can");
    eprintln!("only be decrypted by a VM with the given measurement.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --share <PATH>        Path to node share JSON file");
    eprintln!("  --measurement <HEX>   Expected VM measurement (96 hex chars = 48 bytes)");
    eprintln!("  --policy <U64>        Expected VM policy value");
    eprintln!("  --output <PATH>       Output path for sealed blob");
    eprintln!("  --help                Show this help");
}

fn parse_measurement(hex_str: &str) -> Result<[u8; 48], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 48 {
        return Err(format!(
            "measurement must be 48 bytes (96 hex chars), got {} bytes ({} hex chars)",
            bytes.len(),
            hex_str.len()
        ));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut share_path: Option<String> = None;
    let mut measurement_hex: Option<String> = None;
    let mut policy_str: Option<String> = None;
    let mut output_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--share" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --share requires a path");
                    process::exit(1);
                }
                share_path = Some(args[i].clone());
            }
            "--measurement" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --measurement requires a hex value");
                    process::exit(1);
                }
                measurement_hex = Some(args[i].clone());
            }
            "--policy" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --policy requires a value");
                    process::exit(1);
                }
                policy_str = Some(args[i].clone());
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --output requires a path");
                    process::exit(1);
                }
                output_path = Some(args[i].clone());
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

    let share_path = match share_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --share is required");
            eprintln!();
            print_help();
            process::exit(1);
        }
    };

    let measurement_hex = match measurement_hex {
        Some(h) => h,
        None => {
            eprintln!("Error: --measurement is required");
            eprintln!();
            print_help();
            process::exit(1);
        }
    };

    let policy_str = match policy_str {
        Some(p) => p,
        None => {
            eprintln!("Error: --policy is required");
            eprintln!();
            print_help();
            process::exit(1);
        }
    };

    let output_path = match output_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --output is required");
            eprintln!();
            print_help();
            process::exit(1);
        }
    };

    // Parse measurement
    let measurement = match parse_measurement(&measurement_hex) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    // Parse policy
    let policy: u64 = match policy_str.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: invalid policy value: {e}");
            process::exit(1);
        }
    };

    // Read the share file
    let share_bytes = match fs::read(&share_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: failed to read {share_path}: {e}");
            process::exit(1);
        }
    };

    // Seal
    let sealed = match sealing::seal(&share_bytes, &measurement, policy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: sealing failed: {e}");
            process::exit(1);
        }
    };

    // Write output
    if let Err(e) = fs::write(&output_path, &sealed) {
        eprintln!("Error: failed to write {output_path}: {e}");
        process::exit(1);
    }

    eprintln!("sealed {} bytes -> {} bytes", share_bytes.len(), sealed.len());
    eprintln!("measurement: {measurement_hex}");
    eprintln!("policy:      {policy}");
    eprintln!("output:      {output_path}");
}
