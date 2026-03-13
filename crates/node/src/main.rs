//! TOPRF node server — stateless TEE that evaluates OPRF requests.
//!
//! Key loading modes (at boot, never at runtime):
//!
//! 1. **Init-seal** (initial deployment) — `--init-seal --s3-bucket <BUCKET>`
//!    Generates an ephemeral secp256k1 keypair inside the enclave, gets an
//!    attestation report binding the public key via REPORT_DATA, uploads both
//!    to S3, then polls for the operator's ECIES-encrypted key share. Once
//!    received, decrypts, seals with MSG_KEY_REQ, uploads the sealed blob
//!    to S3, and exits.
//!
//! 2. **Auto-unseal** (production) — When `SEALED_KEY_URL` is set, the node
//!    fetches a sealed key blob from object storage at boot, derives the
//!    sealing key via MSG_KEY_REQ (hardware-derived key), and decrypts
//!    the share automatically. No admin interaction required after deployment.
//!
//! 3. **Key file** (testing/dev) — `--key-file <PATH>` loads a NodeKeyShare
//!    JSON file from disk at boot. No network endpoint is exposed for key
//!    loading.
//!
//! In all modes, the key exists only in memory after loading. If the TEE
//! restarts, auto-unseal re-derives the key from the sealed blob.
//!
//! Endpoints (normal mode):
//!   GET  /health           — liveness + key status
//!   GET  /info             — public info (only when key is loaded)
//!   POST /evaluate         — full OPRF evaluation (coordinator mode, requires --coordinator-config)
//!   POST /partial-evaluate — partial OPRF evaluation (peer mode, always available)
//!
//! Usage:
//!   toprf-node --port 3001 --key-file /path/to/share.json --coordinator-config /path/to/coord.json
//!   toprf-node --init-seal --s3-bucket my-node-bucket --upload-url s3://my-node-bucket/sealed.bin
//!
//! Supported storage URLs (--upload-url and SEALED_KEY_URL):
//!   gs://bucket/object             — GCP Cloud Storage (VM service account)
//!   s3://bucket/key                — AWS S3 (instance profile IAM role)
//!   https://<acct>.blob.../c/b     — Azure Blob Storage (managed identity)
//!   https://...                    — plain HTTPS (presigned URL, etc.)
//!   file:///path                   — local file (dev/testing only)
//!
//! Environment variables:
//!   PORT                        — HTTP listen port (default: 3001)
//!   SEALED_KEY_URL              — URL to a sealed key blob (see schemes above)
//!   EXPECTED_VERIFICATION_SHARE — hex-encoded k_i * G for key verification
//!   COORDINATOR_CONFIG          — path to coordinator config JSON (peer endpoints)
//!   (attestation uses /dev/sev-guest ioctl automatically)

mod cloud_storage;
mod coordinator;
mod reshare_handler;

use std::env;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use zeroize::{Zeroize, Zeroizing};

use toprf_core::partial_eval::partial_evaluate;
use toprf_core::{hex_to_point, hex_to_scalar, NodeKeyShare, PartialEvaluation};

use coordinator::CoordinatorConfig;

// -- Application state --

/// Maximum number of reshare attestation digests to track for replay protection.
/// After this many entries, the oldest are evicted. Each rotation cycle produces
/// at most N-1 entries (one per donor), so 256 covers ~85 full rotations.
const RESHARE_SEEN_MAX: usize = 256;

pub struct NodeState {
    /// The loaded key material. Set exactly once at boot.
    pub(crate) loaded_key: OnceLock<LoadedKey>,
    /// Coordinator config (peer endpoints). None if running as peer-only.
    pub coordinator: Option<CoordinatorConfig>,
    /// HTTP client for calling peer nodes.
    pub http_client: reqwest::Client,
    /// Tracks attestation report digests already processed by /reshare
    /// to prevent replay attacks. Bounded to RESHARE_SEEN_MAX entries.
    pub reshare_seen: std::sync::Mutex<Vec<[u8; 32]>>,
}

pub(crate) struct LoadedKey {
    pub(crate) node_id: u16,
    pub(crate) key_share: Scalar,
    pub(crate) verification_share: String,
    pub(crate) group_public_key: String,
    pub(crate) threshold: u16,
    pub(crate) total_shares: u16,
}

// Manual Debug to avoid leaking key_share
impl std::fmt::Debug for LoadedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedKey")
            .field("node_id", &self.node_id)
            .field("key_share", &"<redacted>")
            .finish()
    }
}

// Zeroize key material on drop (defense-in-depth; LoadedKey lives in OnceLock
// for the process lifetime, but this ensures cleanup if that ever changes).
impl Drop for LoadedKey {
    fn drop(&mut self) {
        self.key_share.zeroize();
    }
}

// -- Request/response types --

#[derive(Deserialize)]
struct EvalRequest {
    blinded_point: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<u16>,
    /// Whether this node can act as coordinator (has peer config).
    coordinator: bool,
}

#[derive(Serialize)]
struct InfoResponse {
    node_id: u16,
    verification_share: String,
    group_public_key: String,
    threshold: u16,
    total_shares: u16,
}

// -- Handlers --

async fn health(State(state): State<Arc<NodeState>>) -> Json<HealthResponse> {
    let is_coordinator = state.coordinator.is_some();
    match state.loaded_key.get() {
        Some(key) => Json(HealthResponse {
            status: "ready".into(),
            node_id: Some(key.node_id),
            coordinator: is_coordinator,
        }),
        None => Json(HealthResponse {
            status: "waiting_for_key".into(),
            node_id: None,
            coordinator: is_coordinator,
        }),
    }
}

async fn node_info(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<InfoResponse>, (StatusCode, String)> {
    let key = state
        .loaded_key
        .get()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "no key loaded".into()))?;

    Ok(Json(InfoResponse {
        node_id: key.node_id,
        verification_share: key.verification_share.clone(),
        group_public_key: key.group_public_key.clone(),
        threshold: key.threshold,
        total_shares: key.total_shares,
    }))
}

async fn eval(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<EvalRequest>,
) -> Result<Json<PartialEvaluation>, axum::response::Response> {
    let key = state.loaded_key.get().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "no key loaded".to_string()).into_response()
    })?;

    let blinded_point = match hex_to_point(&req.blinded_point) {
        Ok(p) => p,
        Err(e) => {
            warn!("invalid blinded_point in eval: {e}");
            return Err((StatusCode::BAD_REQUEST, "invalid input".to_string()).into_response());
        }
    };

    let partial = match partial_evaluate(key.node_id, &key.key_share, &blinded_point) {
        Ok(p) => p,
        Err(e) => {
            warn!("partial evaluation failed: {e}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "evaluation failed".to_string(),
            )
                .into_response());
        }
    };

    info!(node_id = key.node_id, "partial evaluation complete");

    Ok(Json(partial))
}

// -- Auto-unseal helpers --
// Cloud storage download/upload is in the `cloud_storage` module.

// -- Init-seal mode (S3-mediated ECIES) --

/// Run init-seal mode: generate ephemeral keypair, get attestation,
/// upload to S3, poll for encrypted share, decrypt, seal, upload sealed blob.
async fn run_init_seal(s3_bucket: &str, upload_url: &str) {
    info!("init-seal: starting S3-mediated ECIES init-seal mode");

    let s3_attestation_url = format!("s3://{s3_bucket}/init/attestation.bin");
    let s3_pubkey_url = format!("s3://{s3_bucket}/init/pubkey.bin");
    let s3_certs_url = format!("s3://{s3_bucket}/init/certs.bin");
    let s3_encrypted_share_url = format!("s3://{s3_bucket}/init/encrypted-share.bin");

    // Step 1: Generate ephemeral X25519 keypair
    info!("init-seal: generating ephemeral X25519 keypair");
    let (ephemeral_secret, pubkey_bytes) = toprf_seal::ecies::generate_keypair();
    info!(
        pubkey = %hex::encode(pubkey_bytes),
        "init-seal: ephemeral X25519 keypair generated"
    );

    // Step 2: Compute SHA-256(pubkey) for REPORT_DATA binding
    let pubkey_hash = {
        let mut hasher = Sha256::new();
        hasher.update(pubkey_bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    // Step 3: Get attestation report with pubkey hash as REPORT_DATA
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&pubkey_hash);

    info!("init-seal: requesting extended attestation report with pubkey hash as REPORT_DATA");
    let (report, cert_table) = toprf_seal::provider::get_ext_attestation_report(Some(&report_data))
        .await
        .expect("init-seal: failed to get extended attestation report");
    info!(
        cert_table_size = cert_table.len(),
        "init-seal: certificate chain obtained from host firmware"
    );

    // Serialize the full attestation report (body + signature, padded)
    let mut attestation_bytes = Vec::with_capacity(toprf_seal::snp_report::REPORT_TOTAL_SIZE);
    attestation_bytes.extend_from_slice(&report.body_bytes);
    while attestation_bytes.len() < toprf_seal::snp_report::REPORT_BODY_SIZE {
        attestation_bytes.push(0);
    }
    attestation_bytes.extend_from_slice(&report.signature_r);
    attestation_bytes.extend_from_slice(&report.signature_s);
    while attestation_bytes.len() < toprf_seal::snp_report::REPORT_TOTAL_SIZE {
        attestation_bytes.push(0);
    }

    info!(
        measurement = %hex::encode(report.measurement),
        "init-seal: attestation report obtained"
    );

    // Step 4: Upload attestation report and public key to S3
    info!("init-seal: uploading attestation report to {s3_attestation_url}");
    cloud_storage::upload_blob(&s3_attestation_url, attestation_bytes)
        .await
        .expect("init-seal: failed to upload attestation report to S3");

    info!("init-seal: uploading ephemeral X25519 public key to {s3_pubkey_url}");
    cloud_storage::upload_blob(&s3_pubkey_url, pubkey_bytes.to_vec())
        .await
        .expect("init-seal: failed to upload public key to S3");

    info!("init-seal: uploading certificate chain to {s3_certs_url}");
    cloud_storage::upload_blob(&s3_certs_url, cert_table)
        .await
        .expect("init-seal: failed to upload certificate chain to S3");

    info!("init-seal: waiting for operator to upload encrypted share to {s3_encrypted_share_url}");
    info!("init-seal: operator should run:");
    info!("  aws s3 cp {s3_attestation_url} ./attestation.bin");
    info!("  aws s3 cp {s3_pubkey_url} ./pubkey.bin");
    info!("  toprf-init-encrypt --attestation ./attestation.bin --pubkey ./pubkey.bin \\");
    info!("      --output ./encrypted-share.bin --share-file <share.json> --expected-measurement <hex>");
    info!("  aws s3 cp ./encrypted-share.bin {s3_encrypted_share_url}");

    // Step 5: Poll S3 for the encrypted share
    let encrypted_share = poll_s3_for_blob(&s3_encrypted_share_url).await;

    // Step 6: Decrypt with ECIES
    info!("init-seal: decrypting key share with ECIES");
    let mut share_bytes = toprf_seal::ecies::decrypt(&ephemeral_secret, &encrypted_share)
        .expect("init-seal: ECIES decryption failed");

    // Validate the decrypted data is a valid NodeKeyShare
    let _share: NodeKeyShare = serde_json::from_slice(&share_bytes)
        .expect("init-seal: decrypted data is not valid NodeKeyShare JSON");
    info!("init-seal: key share decrypted and validated");

    // Step 7: Seal with hardware-derived key and verify round-trip
    let derived_key = toprf_seal::get_derived_key(toprf_seal::SAFE_FIELD_SELECT)
        .expect("init-seal: failed to get hardware-derived key via MSG_KEY_REQ");
    info!("init-seal: hardware-derived key obtained");

    let sealed_blob =
        toprf_seal::seal_derived(&share_bytes, &derived_key, toprf_seal::SAFE_FIELD_SELECT)
            .expect("init-seal: sealing failed");

    // Verify we can unseal what we just sealed
    let unsealed = toprf_seal::unseal_derived(&sealed_blob, &derived_key)
        .expect("init-seal: unseal verification failed — sealed blob is corrupt");
    assert_eq!(
        unsealed,
        &share_bytes[..],
        "init-seal: unseal round-trip mismatch"
    );
    info!("init-seal: seal/unseal round-trip verified");
    info!(
        sealed_blob_size = sealed_blob.len(),
        "init-seal: key share sealed and verified"
    );

    // Zeroize the plaintext
    share_bytes.zeroize();
    drop(share_bytes);

    // Step 8: Upload the sealed blob
    info!(
        url = %cloud_storage::display_url(upload_url),
        "init-seal: uploading sealed blob"
    );
    cloud_storage::upload_blob(upload_url, sealed_blob)
        .await
        .expect("init-seal: failed to upload sealed blob");

    // Step 9: Clean up init artifacts from S3
    info!("init-seal: cleaning up init artifacts from S3");
    // Best-effort cleanup — don't fail if these can't be deleted
    let _ = cloud_storage::delete_blob(&s3_attestation_url).await;
    let _ = cloud_storage::delete_blob(&s3_pubkey_url).await;
    let _ = cloud_storage::delete_blob(&s3_certs_url).await;
    let _ = cloud_storage::delete_blob(&s3_encrypted_share_url).await;

    info!("init-seal: complete — sealed blob uploaded, node shutting down");
}

/// Poll S3 for a blob, waiting up to 30 minutes with 5-second intervals.
async fn poll_s3_for_blob(url: &str) -> Vec<u8> {
    let max_attempts = 360; // 30 minutes at 5s intervals
    for attempt in 1..=max_attempts {
        match cloud_storage::download_blob(url).await {
            Ok(data) if !data.is_empty() => {
                info!(
                    attempt,
                    size = data.len(),
                    "init-seal: encrypted share found"
                );
                return data;
            }
            Ok(_) => {
                // Empty response — not uploaded yet
            }
            Err(_) => {
                // 404 or other error — not uploaded yet
            }
        }
        if attempt % 12 == 0 {
            // Log every minute
            info!(
                minutes = attempt / 12,
                "init-seal: still waiting for encrypted share..."
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    panic!("init-seal: timed out waiting for encrypted share after 30 minutes");
}

// -- Init-reshare mode (S3-mediated reshare key receive) --

/// Run init-reshare mode: generate ephemeral keypair, get attestation,
/// upload to S3, poll for reshare contributions from donor nodes,
/// combine, seal, upload sealed blob.
async fn run_init_reshare(
    s3_bucket: &str,
    upload_url: &str,
    new_node_id: u16,
    new_threshold: u16,
    new_total_shares: u16,
    group_public_key: &str,
    min_contributions: u16,
) {
    #[cfg(not(target_os = "linux"))]
    {
        // Suppress unused parameter warnings
        let _ = (s3_bucket, upload_url, new_node_id, new_threshold, new_total_shares, group_public_key, min_contributions);
        panic!(
            "init-reshare: SEV-SNP attestation is only available on Linux. \
             This binary must run inside an AMD SEV-SNP VM."
        );
    }

    #[cfg(target_os = "linux")]
    {
    use toprf_core::reshare::{combine_recovery_contributions, SerializableReshareContribution};

    info!("init-reshare: starting S3-mediated reshare mode for node {new_node_id}");

    // Step 1: Generate ephemeral X25519 keypair for receiving contributions
    info!("init-reshare: generating ephemeral X25519 keypair");
    let (ephemeral_secret, pubkey_bytes) = toprf_seal::ecies::generate_keypair();
    info!(
        pubkey = %hex::encode(pubkey_bytes),
        "init-reshare: ephemeral X25519 keypair generated"
    );

    // Step 2: Compute SHA-256(pubkey) for REPORT_DATA binding
    let pubkey_hash = {
        let mut hasher = Sha256::new();
        hasher.update(pubkey_bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    // Step 3: Get attestation report
    let s3_attestation_url = format!("s3://{s3_bucket}/reshare/attestation.bin");
    let s3_pubkey_url = format!("s3://{s3_bucket}/reshare/pubkey.bin");
    let s3_certs_url = format!("s3://{s3_bucket}/reshare/certs.bin");
    {
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&pubkey_hash);

        info!("init-reshare: requesting extended attestation report");
        let (report, cert_table) =
            toprf_seal::provider::get_ext_attestation_report(Some(&report_data))
                .await
                .expect("init-reshare: failed to get extended attestation report");

        // Serialize attestation report
        let mut attestation_bytes = Vec::with_capacity(toprf_seal::snp_report::REPORT_TOTAL_SIZE);
        attestation_bytes.extend_from_slice(&report.body_bytes);
        while attestation_bytes.len() < toprf_seal::snp_report::REPORT_BODY_SIZE {
            attestation_bytes.push(0);
        }
        attestation_bytes.extend_from_slice(&report.signature_r);
        attestation_bytes.extend_from_slice(&report.signature_s);
        while attestation_bytes.len() < toprf_seal::snp_report::REPORT_TOTAL_SIZE {
            attestation_bytes.push(0);
        }

        // Upload attestation artifacts
        cloud_storage::upload_blob(&s3_attestation_url, attestation_bytes)
            .await
            .expect("init-reshare: failed to upload attestation");
        cloud_storage::upload_blob(&s3_certs_url, cert_table)
            .await
            .expect("init-reshare: failed to upload certs");

        // Upload pubkey (inside Linux block since non-Linux panics above)
        cloud_storage::upload_blob(&s3_pubkey_url, pubkey_bytes.to_vec())
            .await
            .expect("init-reshare: failed to upload pubkey");
    }

    info!("init-reshare: attestation and pubkey uploaded, polling for contributions...");

    // Step 4: Poll for contributions from donor nodes
    let mut contributions: Vec<SerializableReshareContribution> = Vec::new();
    let max_donor_id = 100u16; // reasonable upper bound
    let max_attempts = 360; // 30 minutes at 5s intervals

    for attempt in 1..=max_attempts {
        for donor_id in 1..=max_donor_id {
            let contrib_url = format!("s3://{s3_bucket}/reshare/contribution-from-{donor_id}.json");
            if let Ok(data) = cloud_storage::download_blob(&contrib_url).await {
                if !data.is_empty() {
                    // Check if we already have this donor's contribution
                    let already_have = contributions.iter().any(|c| c.from_node_id == donor_id);
                    if !already_have {
                        match serde_json::from_slice::<SerializableReshareContribution>(&data) {
                            Ok(c) => {
                                info!(
                                    from_node_id = c.from_node_id,
                                    "init-reshare: received contribution"
                                );
                                contributions.push(c);
                            }
                            Err(e) => {
                                warn!(donor_id, "init-reshare: invalid contribution JSON: {e}");
                            }
                        }
                    }
                }
            }
        }

        if contributions.len() >= min_contributions as usize {
            info!(
                count = contributions.len(),
                "init-reshare: received sufficient contributions"
            );
            break;
        }

        if attempt % 12 == 0 {
            info!(
                minutes = attempt / 12,
                received = contributions.len(),
                needed = min_contributions,
                "init-reshare: still waiting for contributions..."
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    if contributions.len() < min_contributions as usize {
        panic!(
            "init-reshare: timed out — received {} contributions, need {}",
            contributions.len(),
            min_contributions
        );
    }

    // Step 5: Decrypt and combine contributions
    let mut decoded_contributions: Vec<(u16, k256::Scalar, String)> = Vec::new();
    let mut participant_ids: Vec<u16> = Vec::new();

    for c in &contributions {
        participant_ids.push(c.from_node_id);

        if !c.encrypted {
            panic!(
                "init-reshare: contribution from node {} is not encrypted — all contributions must be ECIES-encrypted",
                c.from_node_id
            );
        }

        // ECIES-decrypt
        let sub_share = {
            use base64::Engine;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&c.sub_share_data)
                .expect("init-reshare: invalid base64 in encrypted contribution");
            let plaintext = toprf_seal::ecies::decrypt(&ephemeral_secret, &ciphertext)
                .expect("init-reshare: ECIES decryption failed");
            assert_eq!(
                plaintext.len(),
                32,
                "init-reshare: decrypted sub-share is not 32 bytes"
            );
            // Convert directly from bytes without hex intermediate to avoid
            // leaking key material in string form
            use k256::elliptic_curve::PrimeField;
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&plaintext);
            let field_bytes = k256::FieldBytes::from(scalar_bytes);
            Option::from(Scalar::from_repr(field_bytes))
                .expect("init-reshare: decrypted sub-share is not a valid scalar")
        };

        decoded_contributions.push((c.from_node_id, sub_share, c.verification_share.clone()));
    }

    // Combine into new node's key share
    let new_share = combine_recovery_contributions(
        new_node_id,
        &decoded_contributions,
        &participant_ids,
        group_public_key,
        new_threshold,
        new_total_shares,
    )
    .expect("init-reshare: failed to combine recovery contributions");

    info!(
        node_id = new_share.node_id,
        verification_share = %new_share.verification_share,
        "init-reshare: new key share computed"
    );

    // Step 6: Seal and upload
    let share_bytes = serde_json::to_vec(&new_share).expect("init-reshare: JSON serialization");

    let derived_key = toprf_seal::get_derived_key(toprf_seal::SAFE_FIELD_SELECT)
        .expect("init-reshare: failed to get hardware-derived key via MSG_KEY_REQ");

    let sealed_blob =
        toprf_seal::seal_derived(&share_bytes, &derived_key, toprf_seal::SAFE_FIELD_SELECT)
            .expect("init-reshare: sealing failed");

    // Verify round-trip
    let unsealed = toprf_seal::unseal_derived(&sealed_blob, &derived_key)
        .expect("init-reshare: unseal verification failed");
    assert_eq!(
        unsealed,
        &share_bytes[..],
        "init-reshare: unseal round-trip mismatch"
    );

    cloud_storage::upload_blob(upload_url, sealed_blob)
        .await
        .expect("init-reshare: failed to upload sealed blob");

    // Step 7: Clean up
    let _ = cloud_storage::delete_blob(&s3_attestation_url).await;
    let _ = cloud_storage::delete_blob(&s3_pubkey_url).await;
    let _ = cloud_storage::delete_blob(&s3_certs_url).await;
    for c in &contributions {
        let contrib_url = format!(
            "s3://{s3_bucket}/reshare/contribution-from-{}.json",
            c.from_node_id
        );
        let _ = cloud_storage::delete_blob(&contrib_url).await;
    }

    info!("init-reshare: complete — sealed blob uploaded");
    } // #[cfg(target_os = "linux")]
}

// -- Attestation report for website publication --

/// Extract the S3 bucket name from a storage URL like "s3://bucket/path/to/file".
#[cfg(target_os = "linux")]
fn s3_bucket_from_url(url: &str) -> Option<String> {
    let path = url.strip_prefix("s3://")?;
    let bucket = path.split('/').next()?;
    if bucket.is_empty() {
        return None;
    }
    Some(bucket.to_string())
}

/// Generate an attestation report bound to the loaded verification share
/// and upload it to S3 for website publication.
#[cfg(target_os = "linux")]
async fn upload_attestation_for_website(sealed_key_url: &str, key: &LoadedKey) {
    let bucket = match s3_bucket_from_url(sealed_key_url) {
        Some(b) => b,
        None => {
            warn!("attestation: cannot extract S3 bucket from SEALED_KEY_URL, skipping");
            return;
        }
    };

    let report_url = format!("s3://{bucket}/attestation/report.bin");
    let certs_url = format!("s3://{bucket}/attestation/certs.bin");
    let metadata_url = format!("s3://{bucket}/attestation/metadata.json");

    let vs_bytes = match hex::decode(&key.verification_share) {
        Ok(b) => b,
        Err(e) => {
            warn!("attestation: failed to decode verification share hex: {e}");
            return;
        }
    };

    let vs_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&vs_bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&vs_hash);

    info!("attestation: requesting SNP report bound to verification share");

    let (report, cert_table) =
        match toprf_seal::provider::get_ext_attestation_report(Some(&report_data)).await {
            Ok(r) => r,
            Err(e) => {
                warn!("attestation: failed to get attestation report: {e}");
                return;
            }
        };

    let mut attestation_bytes = Vec::with_capacity(toprf_seal::snp_report::REPORT_TOTAL_SIZE);
    attestation_bytes.extend_from_slice(&report.body_bytes);
    while attestation_bytes.len() < toprf_seal::snp_report::REPORT_BODY_SIZE {
        attestation_bytes.push(0);
    }
    attestation_bytes.extend_from_slice(&report.signature_r);
    attestation_bytes.extend_from_slice(&report.signature_s);
    while attestation_bytes.len() < toprf_seal::snp_report::REPORT_TOTAL_SIZE {
        attestation_bytes.push(0);
    }

    let metadata = serde_json::json!({
        "node_id": key.node_id,
        "verification_share": key.verification_share,
        "group_public_key": key.group_public_key,
        "threshold": key.threshold,
        "total_shares": key.total_shares,
        "report_data_binding": "SHA256(verification_share_bytes)",
        "report_data_hash": hex::encode(vs_hash),
        "measurement": hex::encode(report.measurement),
    });

    if let Err(e) = cloud_storage::upload_blob(&report_url, attestation_bytes).await {
        warn!("attestation: failed to upload report.bin: {e}");
        return;
    }
    if let Err(e) = cloud_storage::upload_blob(&certs_url, cert_table).await {
        warn!("attestation: failed to upload certs.bin: {e}");
        return;
    }
    let metadata_bytes = serde_json::to_vec_pretty(&metadata).expect("JSON serialization");
    if let Err(e) = cloud_storage::upload_blob(&metadata_url, metadata_bytes).await {
        warn!("attestation: failed to upload metadata.json: {e}");
        return;
    }

    info!(
        node_id = key.node_id,
        "attestation: report uploaded to s3://{}/attestation/", bucket,
    );
}

#[cfg(not(target_os = "linux"))]
async fn upload_attestation_for_website(_sealed_key_url: &str, _key: &LoadedKey) {
    info!("attestation: skipping upload (not on Linux/SEV-SNP hardware)");
}

// -- Main --

#[tokio::main]
async fn main() {
    // Install the default rustls crypto provider (ring via reqwest's rustls-tls)
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut port = env::var("PORT").unwrap_or_else(|_| "3001".into());
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut client_ca: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut init_seal = false;
    let mut init_reshare = false;
    let mut s3_bucket: Option<String> = None;
    let mut upload_url: Option<String> = None;
    let mut reshare_new_node_id: Option<u16> = None;
    let mut reshare_new_threshold: Option<u16> = None;
    let mut reshare_new_total_shares: Option<u16> = None;
    let mut reshare_group_public_key: Option<String> = None;
    let mut reshare_min_contributions: Option<u16> = None;
    let mut coordinator_config_path: Option<String> = env::var("COORDINATOR_CONFIG").ok();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --port");
                    std::process::exit(1);
                }
                port = args[i].clone();
            }
            "--tls-cert" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --tls-cert");
                    std::process::exit(1);
                }
                tls_cert = Some(args[i].clone());
            }
            "--tls-key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --tls-key");
                    std::process::exit(1);
                }
                tls_key = Some(args[i].clone());
            }
            "--client-ca" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --client-ca");
                    std::process::exit(1);
                }
                client_ca = Some(args[i].clone());
            }
            "--key-file" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --key-file");
                    std::process::exit(1);
                }
                key_file = Some(args[i].clone());
            }
            "--init-seal" => {
                init_seal = true;
            }
            "--init-reshare" => {
                init_reshare = true;
            }
            "--new-node-id" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --new-node-id");
                    std::process::exit(1);
                }
                reshare_new_node_id = Some(args[i].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --new-node-id: {e}");
                    std::process::exit(1);
                }));
            }
            "--new-threshold" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --new-threshold");
                    std::process::exit(1);
                }
                reshare_new_threshold = Some(args[i].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --new-threshold: {e}");
                    std::process::exit(1);
                }));
            }
            "--new-total-shares" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --new-total-shares");
                    std::process::exit(1);
                }
                reshare_new_total_shares = Some(args[i].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --new-total-shares: {e}");
                    std::process::exit(1);
                }));
            }
            "--group-public-key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --group-public-key");
                    std::process::exit(1);
                }
                reshare_group_public_key = Some(args[i].clone());
            }
            "--min-contributions" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --min-contributions");
                    std::process::exit(1);
                }
                reshare_min_contributions = Some(args[i].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --min-contributions: {e}");
                    std::process::exit(1);
                }));
            }
            "--s3-bucket" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --s3-bucket");
                    std::process::exit(1);
                }
                s3_bucket = Some(args[i].clone());
            }
            "--upload-url" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --upload-url");
                    std::process::exit(1);
                }
                upload_url = Some(args[i].clone());
            }
            "--coordinator-config" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --coordinator-config");
                    std::process::exit(1);
                }
                coordinator_config_path = Some(args[i].clone());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-node [OPTIONS]");
                eprintln!();
                eprintln!("Key loading (at boot only — no runtime key endpoints):");
                eprintln!("  1. Init-seal: --init-seal --s3-bucket <BUCKET> to run the");
                eprintln!("     S3-mediated ECIES init-seal flow. The node generates an");
                eprintln!("     ephemeral keypair, gets attestation, uploads both to S3,");
                eprintln!("     then polls for the operator's ECIES-encrypted share.");
                eprintln!("  2. Auto-unseal: set SEALED_KEY_URL to fetch and decrypt a sealed");
                eprintln!("     key blob at boot using AMD SEV-SNP attestation.");
                eprintln!("  3. Key file: --key-file <PATH> to load a NodeKeyShare JSON file");
                eprintln!("     from disk (for testing/dev).");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -p, --port <PORT>         Listen port (default: 3001)");
                eprintln!("      --init-seal           Run S3-mediated ECIES init-seal mode");
                eprintln!("      --s3-bucket <BUCKET>  S3 bucket for init-seal artifacts");
                eprintln!("      --upload-url <URL>    Storage URL for sealed blob (default: s3://<bucket>/sealed.bin)");
                eprintln!("      --key-file <PATH>     Load key share from JSON file at boot");
                eprintln!("      --coordinator-config <PATH>  Peer config JSON (enables /evaluate endpoint)");
                eprintln!("      --tls-cert <PATH>     TLS server certificate (PEM)");
                eprintln!("      --tls-key <PATH>      TLS server private key (PEM)");
                eprintln!("      --client-ca <PATH>    CA cert for client auth (enables mTLS)");
                eprintln!("  -h, --help                Show this help");
                eprintln!();
                eprintln!("Environment:");
                eprintln!("  PORT                        Listen port (default: 3001)");
                eprintln!("  SEALED_KEY_URL              URL to sealed key blob (gs://, s3://, https://, file://)");
                eprintln!("  EXPECTED_VERIFICATION_SHARE Hex-encoded k_i * G for key verification");
                eprintln!("  COORDINATOR_CONFIG          Path to coordinator config JSON (peer endpoints)");
                eprintln!("  (attestation uses /dev/sev-guest ioctl automatically)");
                eprintln!();
                eprintln!("When --tls-cert and --tls-key are provided, the node serves HTTPS.");
                eprintln!("When --client-ca is also provided, clients must present a certificate");
                eprintln!("signed by that CA (mutual TLS).");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // -- Validate mutually exclusive modes --
    if init_seal {
        if key_file.is_some() {
            eprintln!("Error: --init-seal cannot be used with --key-file");
            std::process::exit(1);
        }
        if env::var("SEALED_KEY_URL").is_ok() {
            eprintln!("Error: --init-seal cannot be used with SEALED_KEY_URL");
            std::process::exit(1);
        }
        let bucket = s3_bucket.unwrap_or_else(|| {
            eprintln!("Error: --init-seal requires --s3-bucket <BUCKET>");
            std::process::exit(1);
        });
        let seal_url = upload_url.unwrap_or_else(|| {
            // Default to s3://<bucket>/sealed.bin
            format!("s3://{bucket}/sealed.bin")
        });

        // Run init-seal mode and exit
        run_init_seal(&bucket, &seal_url).await;
        return;
    }

    if init_reshare {
        if key_file.is_some() {
            eprintln!("Error: --init-reshare cannot be used with --key-file");
            std::process::exit(1);
        }
        if env::var("SEALED_KEY_URL").is_ok() {
            eprintln!("Error: --init-reshare cannot be used with SEALED_KEY_URL");
            std::process::exit(1);
        }
        let bucket = s3_bucket.unwrap_or_else(|| {
            eprintln!("Error: --init-reshare requires --s3-bucket <BUCKET>");
            std::process::exit(1);
        });
        let seal_url = upload_url.unwrap_or_else(|| format!("s3://{bucket}/sealed.bin"));
        let new_node_id = reshare_new_node_id.unwrap_or_else(|| {
            eprintln!("Error: --init-reshare requires --new-node-id");
            std::process::exit(1);
        });
        let new_threshold = reshare_new_threshold.unwrap_or_else(|| {
            eprintln!("Error: --init-reshare requires --new-threshold");
            std::process::exit(1);
        });
        let new_total_shares = reshare_new_total_shares.unwrap_or_else(|| {
            eprintln!("Error: --init-reshare requires --new-total-shares");
            std::process::exit(1);
        });
        let group_public_key = reshare_group_public_key.unwrap_or_else(|| {
            eprintln!("Error: --init-reshare requires --group-public-key");
            std::process::exit(1);
        });
        let min_contributions = reshare_min_contributions.unwrap_or_else(|| {
            eprintln!("Error: --init-reshare requires --min-contributions");
            std::process::exit(1);
        });

        run_init_reshare(
            &bucket,
            &seal_url,
            new_node_id,
            new_threshold,
            new_total_shares,
            &group_public_key,
            min_contributions,
        )
        .await;
        return;
    }

    if upload_url.is_some() {
        eprintln!("Error: --upload-url can only be used with --init-seal or --init-reshare");
        std::process::exit(1);
    }
    if s3_bucket.is_some() {
        eprintln!("Error: --s3-bucket can only be used with --init-seal or --init-reshare");
        std::process::exit(1);
    }

    // Load coordinator config (if provided)
    let coordinator = coordinator_config_path.as_ref().map(|path| {
        let data = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read coordinator config {path}: {e}"));
        let config: CoordinatorConfig = serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("invalid coordinator config JSON in {path}: {e}"));
        info!(
            peers = config.peers.len(),
            "loaded coordinator config — /evaluate endpoint enabled"
        );
        for peer in &config.peers {
            info!(
                peer_node_id = peer.node_id,
                endpoint = %peer.endpoint,
                "registered peer"
            );
        }
        config
    });

    // Build HTTP client for peer calls (5s connect, 10s total timeout)
    let http_client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    let state = Arc::new(NodeState {
        loaded_key: OnceLock::new(),
        coordinator,
        http_client,
        reshare_seen: std::sync::Mutex::new(Vec::new()),
    });

    // -- Load key from file (testing/dev) --
    if let Some(ref path) = key_file {
        if env::var("SEALED_KEY_URL").is_ok() {
            eprintln!("Error: cannot use both --key-file and SEALED_KEY_URL");
            std::process::exit(1);
        }

        info!("loading key share from file: {path}");
        let share_bytes =
            std::fs::read(path).unwrap_or_else(|e| panic!("failed to read key file {path}: {e}"));
        let share: NodeKeyShare = serde_json::from_slice(&share_bytes)
            .unwrap_or_else(|e| panic!("invalid NodeKeyShare JSON in {path}: {e}"));

        if share.node_id == 0 {
            panic!("key file: node_id must be nonzero");
        }

        let key_share = hex_to_scalar(&share.secret_share)
            .unwrap_or_else(|e| panic!("key file: invalid secret_share: {e}"));

        // Verify k_i * G == verification_share
        let expected_point = hex_to_point(&share.verification_share)
            .unwrap_or_else(|e| panic!("key file: invalid verification_share: {e}"));
        let computed_point = {
            use k256::elliptic_curve::ops::MulByGenerator;
            use k256::ProjectivePoint;
            ProjectivePoint::mul_by_generator(&key_share)
        };
        if expected_point != computed_point {
            panic!("key file: key share does not match verification share");
        }

        let loaded = LoadedKey {
            node_id: share.node_id,
            key_share,
            verification_share: share.verification_share.clone(),
            group_public_key: share.group_public_key.clone(),
            threshold: share.threshold,
            total_shares: share.total_shares,
        };

        state
            .loaded_key
            .set(loaded)
            .expect("key file: OnceLock already set");
        info!(
            node_id = share.node_id,
            threshold = share.threshold,
            total_shares = share.total_shares,
            "key share loaded from file"
        );
    }

    // -- Auto-unseal from object storage (if configured) --
    if let Ok(sealed_url) = env::var("SEALED_KEY_URL") {
        info!(
            "auto-unseal: fetching sealed key from {}",
            cloud_storage::display_url(&sealed_url)
        );

        let expected_vs = env::var("EXPECTED_VERIFICATION_SHARE")
            .expect("EXPECTED_VERIFICATION_SHARE required when SEALED_KEY_URL is set");

        let sealed_blob = cloud_storage::download_blob(&sealed_url)
            .await
            .expect("failed to fetch sealed blob from object storage");

        // Unseal with hardware-derived key via MSG_KEY_REQ
        info!("auto-unseal: requesting hardware-derived key via MSG_KEY_REQ");

        let derived_key = toprf_seal::get_derived_key(toprf_seal::SAFE_FIELD_SELECT)
            .expect("auto-unseal: failed to get hardware-derived key via MSG_KEY_REQ");

        // Log header info
        if let Ok(field_select) = toprf_seal::parse_v2_header(&sealed_blob) {
            info!(
                field_select = format!("0x{field_select:X}"),
                "auto-unseal: sealed blob field_select"
            );
        }

        let share_json = Zeroizing::new(
            toprf_seal::unseal_derived(&sealed_blob, &derived_key)
                .expect("auto-unseal: decryption failed — derived key mismatch or corrupt blob"),
        );

        // Parse the unsealed key share
        let share: NodeKeyShare = serde_json::from_slice(&share_json)
            .expect("auto-unseal: unsealed data is not valid NodeKeyShare JSON");

        // Verify key: k_i * G == expected verification share
        let key_scalar =
            hex_to_scalar(&share.secret_share).expect("auto-unseal: invalid secret_share scalar");
        let computed_vs = {
            use k256::elliptic_curve::ops::MulByGenerator;
            use k256::ProjectivePoint;
            let point = ProjectivePoint::mul_by_generator(&key_scalar);
            toprf_core::point_to_hex(&point)
        };

        if computed_vs != expected_vs {
            panic!(
                "auto-unseal: key verification FAILED\n  computed: {computed_vs}\n  expected: {expected_vs}\n  The sealed key share does not match the expected verification share."
            );
        }

        info!(
            node_id = share.node_id,
            verification_share = %share.verification_share,
            "auto-unseal: key verified successfully"
        );

        // Load into OnceLock
        let loaded = LoadedKey {
            node_id: share.node_id,
            key_share: key_scalar,
            verification_share: share.verification_share.clone(),
            group_public_key: share.group_public_key.clone(),
            threshold: share.threshold,
            total_shares: share.total_shares,
        };

        state
            .loaded_key
            .set(loaded)
            .expect("auto-unseal: OnceLock already set (should be impossible)");
        info!("auto-unseal: node is ready to serve requests");

        // Generate and upload attestation report bound to verification share
        upload_attestation_for_website(&sealed_url, state.loaded_key.get().unwrap()).await;
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/info", get(node_info))
        .route("/evaluate", post(coordinator::evaluate_handler))
        .route("/partial-evaluate", post(eval))
        .route("/reshare", post(reshare_handler::reshare_handler))
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64KB for reshare requests with attestation
        .with_state(state);

    let bind_addr = format!("0.0.0.0:{port}");

    // Determine whether to serve plain HTTP or HTTPS (with optional mTLS)
    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            // -- TLS mode --
            use axum_server::tls_rustls::RustlsConfig;
            use rustls::server::WebPkiClientVerifier;
            use rustls::RootCertStore;

            let mut rustls_config = if let Some(ca_path) = &client_ca {
                // mTLS: require client certificates signed by this CA
                let ca_pem = std::fs::read(ca_path)
                    .unwrap_or_else(|e| panic!("failed to read client CA {ca_path}: {e}"));
                let mut ca_reader = BufReader::new(ca_pem.as_slice());
                let ca_certs = rustls_pemfile::certs(&mut ca_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse client CA PEM");

                let mut root_store = RootCertStore::empty();
                for cert in ca_certs {
                    root_store
                        .add(cert)
                        .expect("failed to add CA cert to root store");
                }

                let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .expect("failed to build client certificate verifier");

                // Load server cert chain and key
                let cert_pem = std::fs::read(&cert_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS cert {cert_path}: {e}"));
                let key_pem = std::fs::read(&key_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS key {key_path}: {e}"));

                let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse server certificate PEM");
                let private_key =
                    rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
                        .expect("failed to parse server private key PEM")
                        .expect("no private key found in PEM file");

                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(certs, private_key)
                    .expect("failed to build rustls ServerConfig")
            } else {
                // TLS without client auth
                let cert_pem = std::fs::read(&cert_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS cert {cert_path}: {e}"));
                let key_pem = std::fs::read(&key_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS key {key_path}: {e}"));

                let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse server certificate PEM");
                let private_key =
                    rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
                        .expect("failed to parse server private key PEM")
                        .expect("no private key found in PEM file");

                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, private_key)
                    .expect("failed to build rustls ServerConfig")
            };

            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let tls_config = RustlsConfig::from_config(Arc::new(rustls_config));
            let addr: SocketAddr = bind_addr
                .parse()
                .unwrap_or_else(|e| panic!("invalid bind address {bind_addr}: {e}"));

            if client_ca.is_some() {
                info!(addr = %bind_addr, "starting toprf-node with mTLS (waiting for key)");
            } else {
                info!(addr = %bind_addr, "starting toprf-node with TLS (waiting for key)");
            }

            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
                .unwrap_or_else(|e| error!("server error: {e}"));
        }
        (None, None) => {
            // -- Plain HTTP mode (local dev) --
            warn!(addr = %bind_addr, "starting WITHOUT TLS on 0.0.0.0:{port} — not recommended for production");

            let listener = TcpListener::bind(&bind_addr)
                .await
                .unwrap_or_else(|e| panic!("failed to bind to {bind_addr}: {e}"));

            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| error!("server error: {e}"));
        }
        _ => {
            eprintln!("Error: --tls-cert and --tls-key must both be provided (or neither)");
            std::process::exit(1);
        }
    }
}
