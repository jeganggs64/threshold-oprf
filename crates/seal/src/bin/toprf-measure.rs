//! CLI tool to capture the measurement from a running SEV-SNP VM.
//!
//! Usage: toprf-measure [--provider gcp|raw] [--json]
//!
//! Fetches an AMD SEV-SNP attestation report and prints the MEASUREMENT
//! and POLICY fields.

use std::env;
use std::process;

use toprf_seal::provider::{get_attestation_report, SnpProvider};

fn print_help() {
    eprintln!("Usage: toprf-measure [OPTIONS]");
    eprintln!();
    eprintln!("Fetches an AMD SEV-SNP attestation report and prints the MEASUREMENT");
    eprintln!("and POLICY fields.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --provider <gcp|raw>  Attestation provider (default: raw)");
    eprintln!("  --json                Output as JSON");
    eprintln!("  --help                Show this help");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let provider = SnpProvider::DevSevGuest;
    let mut json_output = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--provider" => {
                // Kept for backwards compatibility; value is ignored (auto-detected).
                i += 1;
            }
            "--json" => {
                json_output = true;
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

    let report = match get_attestation_report(provider, None).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: failed to get attestation report: {e}");
            process::exit(1);
        }
    };

    let measurement_hex = hex::encode(report.measurement());
    let policy = report.policy();
    let chip_id_hex = report.chip_id_hex();
    let (bl, tee, snp, ucode) = report.tcb_parts();

    if json_output {
        let json = serde_json::json!({
            "measurement": measurement_hex,
            "policy": policy,
            "chip_id": chip_id_hex,
            "version": report.version,
            "vmpl": report.vmpl,
            "tcb": {
                "bl_svn": bl,
                "tee_svn": tee,
                "snp_svn": snp,
                "ucode_svn": ucode
            },
            "build": {
                "major": report.current_major,
                "minor": report.current_minor,
                "build": report.current_build
            }
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!("measurement: {measurement_hex}");
        println!("policy:      {policy}");
        println!("chip_id:     {chip_id_hex}");
        println!("version:     {}", report.version);
        println!("vmpl:        {}", report.vmpl);
        println!("tcb:         bl={bl} tee={tee} snp={snp} ucode={ucode}");
        println!(
            "build:       {}.{}.{}",
            report.current_major, report.current_minor, report.current_build
        );
    }
}
