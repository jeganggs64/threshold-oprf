//! TOPRF node server — stateless TEE that evaluates OPRF requests.
//!
//! Key loading modes (at boot, never at runtime):
//!
//! 1. **Init-seal** (initial deployment) — `--init-seal --upload-url <URL>`
//!    boots an ephemeral HTTPS server with a self-signed cert. The operator
//!    verifies the attestation report (which binds the TLS pubkey), then
//!    POSTs the key share. The node seals it with MSG_KEY_REQ and uploads
//!    the sealed blob to object storage, then exits.
//!
//! 2. **Auto-unseal** (production) — When `SEALED_KEY_URL` is set, the node
//!    fetches a sealed key blob from object storage at boot, derives the
//!    sealing key from its AMD SEV-SNP attestation measurement, and decrypts
//!    the share automatically. Supports both v2 (MSG_KEY_REQ) and v1 (HKDF)
//!    sealed blobs. No admin interaction required after deployment.
//!
//! 3. **Key file** (testing/dev) — `--key-file <PATH>` loads a NodeKeyShare
//!    JSON file from disk at boot. No network endpoint is exposed for key
//!    loading.
//!
//! In all modes, the key exists only in memory after loading. If the TEE
//! restarts, auto-unseal re-derives the key from the sealed blob.
//!
//! Endpoints (normal mode):
//!   GET  /health           — liveness + key status ("waiting_for_key" or "ready")
//!   GET  /info             — public info (only when key is loaded)
//!   POST /partial-evaluate — OPRF partial evaluation (only when key is loaded)
//!
//! Endpoints (init-seal mode):
//!   GET  /attest           — raw attestation report (binary)
//!   POST /init-key         — accept key share JSON, seal, upload, exit
//!
//! Usage:
//!   toprf-node --port 3001 --key-file /path/to/share.json
//!   toprf-node --init-seal --upload-url gs://bucket/sealed.bin
//!
//! Supported storage URLs (--upload-url and SEALED_KEY_URL):
//!   gs://bucket/object             — GCP Cloud Storage (VM service account)
//!   s3://bucket/key                — AWS S3 (instance profile IAM role)
//!   https://<acct>.blob.../c/b     — Azure Blob Storage (managed identity)
//!   https://...                    — plain HTTPS (presigned URL, etc.)
//!   file:///path                   — local file (dev/testing only)
//!
//! Environment variables:
//!   PORT                       — HTTP listen port (default: 3001)
//!   SEALED_KEY_URL             — URL to a sealed key blob (see schemes above)
//!   EXPECTED_VERIFICATION_SHARE — hex-encoded k_i * G for key verification
//!   SNP_PROVIDER               — attestation provider: "gcp" or "raw" (default: "raw")

mod cloud_storage;

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

// -- Application state --

struct NodeState {
    /// The loaded key material. Set exactly once at boot.
    loaded_key: OnceLock<LoadedKey>,
}

struct LoadedKey {
    node_id: u16,
    key_share: Scalar,
    verification_share: String,
    group_public_key: String,
    threshold: u16,
    total_shares: u16,
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
    match state.loaded_key.get() {
        Some(key) => Json(HealthResponse {
            status: "ready".into(),
            node_id: Some(key.node_id),
        }),
        None => Json(HealthResponse {
            status: "waiting_for_key".into(),
            node_id: None,
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

// -- Init-seal mode --

/// State for the init-seal ephemeral server.
struct InitSealState {
    /// Upload URL for the sealed blob.
    upload_url: String,
    /// Raw attestation report bytes (for /attest endpoint).
    attestation_report_bytes: Vec<u8>,
    /// Shutdown signal sender — triggers server exit after /init-key completes.
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

/// GET /attest — returns the raw attestation report (binary).
async fn attest_handler(State(state): State<Arc<InitSealState>>) -> impl IntoResponse {
    info!("init-seal: /attest endpoint called, returning attestation report");
    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        state.attestation_report_bytes.clone(),
    )
}

/// POST /init-key — accepts key share JSON, seals it, uploads, then signals shutdown.
async fn init_key_handler(
    State(state): State<Arc<InitSealState>>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    info!("init-seal: /init-key endpoint called, processing key share");

    // Validate the body is valid JSON and a valid NodeKeyShare
    let mut share_bytes = Zeroizing::new(body.to_vec());
    let _share: NodeKeyShare = serde_json::from_slice(&share_bytes).map_err(|e| {
        error!("init-seal: invalid NodeKeyShare JSON: {e}");
        (
            StatusCode::BAD_REQUEST,
            format!("invalid NodeKeyShare JSON: {e}"),
        )
    })?;
    info!("init-seal: key share JSON parsed successfully");

    // Step 1: Get hardware-derived key via MSG_KEY_REQ
    info!("init-seal: requesting hardware-derived key via MSG_KEY_REQ (SAFE_FIELD_SELECT)");
    let derived_key = toprf_seal::get_derived_key(toprf_seal::SAFE_FIELD_SELECT).map_err(|e| {
        error!("init-seal: failed to get derived key: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to get derived key: {e}"),
        )
    })?;
    info!("init-seal: hardware-derived key obtained successfully");

    // Step 2: Seal the key share
    info!("init-seal: sealing key share with derived key");
    let sealed_blob =
        toprf_seal::seal_derived(&share_bytes, &derived_key, toprf_seal::SAFE_FIELD_SELECT)
            .map_err(|e| {
                error!("init-seal: sealing failed: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("sealing failed: {e}"),
                )
            })?;
    info!(
        sealed_blob_size = sealed_blob.len(),
        "init-seal: key share sealed successfully"
    );

    // Zeroize the plaintext key share bytes
    share_bytes.zeroize();
    drop(share_bytes);
    info!("init-seal: plaintext key share zeroized from memory");

    // Step 3: Upload the sealed blob
    let upload_url = &state.upload_url;
    info!(url = %cloud_storage::display_url(upload_url), "init-seal: uploading sealed blob");

    cloud_storage::upload_blob(upload_url, sealed_blob)
        .await
        .map_err(|e| {
            error!("init-seal: upload failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("upload failed: {e}"),
            )
        })?;

    info!("init-seal: sealed blob uploaded successfully");
    info!("init-seal: initialization complete — shutting down");

    // Signal the server to shut down
    let _ = state.shutdown_tx.send(true);

    Ok((
        StatusCode::OK,
        "sealed blob uploaded successfully, node shutting down".into(),
    ))
}

/// Run the init-seal mode: generate ephemeral TLS cert, get attestation,
/// serve /attest and /init-key, then exit after key is sealed and uploaded.
async fn run_init_seal(port: &str, upload_url: String) {
    use axum_server::tls_rustls::RustlsConfig;

    info!("init-seal: starting initial deployment mode");

    // Validate upload URL scheme
    if !cloud_storage::is_valid_storage_url(&upload_url) {
        eprintln!("Error: --upload-url must use https://, gs://, s3://, or file://");
        std::process::exit(1);
    }
    info!(
        url = %cloud_storage::display_url(&upload_url),
        "init-seal: upload URL validated"
    );

    // Step 1: Generate ephemeral TLS keypair with self-signed certificate
    info!("init-seal: generating ephemeral TLS keypair and self-signed certificate");
    let key_pair = rcgen::KeyPair::generate().expect("failed to generate keypair");
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("failed to create cert params");
    let cert = cert_params
        .self_signed(&key_pair)
        .expect("failed to generate self-signed certificate");

    let cert_der = cert.der().clone();
    let key_der = key_pair.serialize_der();

    // Step 2: Compute SHA-256 of the TLS certificate's public key
    let tls_pubkey_bytes = key_pair.public_key_der();
    let tls_pubkey_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&tls_pubkey_bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };
    info!(
        pubkey_hash = %hex::encode(tls_pubkey_hash),
        "init-seal: TLS public key SHA-256 hash computed"
    );

    // Step 3: Get attestation report with TLS pubkey hash as REPORT_DATA
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&tls_pubkey_hash);
    // Remaining 32 bytes are zeros

    let provider = match env::var("SNP_PROVIDER").as_deref() {
        Ok("gcp") => toprf_seal::provider::SnpProvider::GcpMetadata,
        _ => toprf_seal::provider::SnpProvider::DevSevGuest,
    };

    info!("init-seal: requesting attestation report with TLS pubkey hash as REPORT_DATA");
    let report = toprf_seal::provider::get_attestation_report(provider, Some(&report_data))
        .await
        .expect("init-seal: failed to get attestation report");

    // Serialize the raw report body + signature for the /attest endpoint
    let mut attestation_bytes = Vec::with_capacity(report.body_bytes.len() + 96);
    attestation_bytes.extend_from_slice(&report.body_bytes);
    // Pad to REPORT_BODY_SIZE if needed (should already be exact)
    while attestation_bytes.len() < toprf_seal::snp_report::REPORT_BODY_SIZE {
        attestation_bytes.push(0);
    }
    attestation_bytes.extend_from_slice(&report.signature_r);
    attestation_bytes.extend_from_slice(&report.signature_s);
    // Pad to full report size
    while attestation_bytes.len() < toprf_seal::snp_report::REPORT_TOTAL_SIZE {
        attestation_bytes.push(0);
    }

    info!(
        measurement = %hex::encode(report.measurement),
        "init-seal: attestation report obtained"
    );

    // Step 4: Set up the ephemeral HTTPS server
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let init_state = Arc::new(InitSealState {
        upload_url,
        attestation_report_bytes: attestation_bytes,
        shutdown_tx,
    });

    let app = Router::new()
        .route("/attest", get(attest_handler))
        .route("/init-key", post(init_key_handler))
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64KB max for key share JSON
        .with_state(init_state);

    let bind_addr = format!("0.0.0.0:{port}");
    let addr: SocketAddr = bind_addr
        .parse()
        .unwrap_or_else(|e| panic!("invalid bind address {bind_addr}: {e}"));

    // Build rustls config from the ephemeral cert
    let rustls_config = {
        let cert_chain = vec![cert_der];
        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain.into_iter().collect(), private_key.into())
            .expect("failed to build rustls ServerConfig for init-seal");

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    };

    let tls_config = RustlsConfig::from_config(Arc::new(rustls_config));

    info!(
        addr = %bind_addr,
        "init-seal: ephemeral HTTPS server starting — waiting for operator"
    );
    info!("init-seal: endpoints available:");
    info!("  GET  /attest   — fetch raw attestation report");
    info!("  POST /init-key — submit key share JSON");

    // Serve until shutdown signal
    let server = axum_server::bind_rustls(addr, tls_config).serve(app.into_make_service());

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("init-seal: server error: {e}");
            }
        }
        _ = shutdown_rx.wait_for(|&v| v) => {
            info!("init-seal: shutdown signal received, exiting");
        }
    }
}

// -- Main --

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut port = env::var("PORT").unwrap_or_else(|_| "3001".into());
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut client_ca: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut init_seal = false;
    let mut upload_url: Option<String> = None;

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
            "--upload-url" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --upload-url");
                    std::process::exit(1);
                }
                upload_url = Some(args[i].clone());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-node [OPTIONS]");
                eprintln!();
                eprintln!("Key loading (at boot only — no runtime key endpoints):");
                eprintln!("  1. Init-seal: --init-seal --upload-url <URL> to run the initial");
                eprintln!("     deployment flow. The node generates an ephemeral TLS cert,");
                eprintln!("     serves /attest and /init-key, seals the key share with");
                eprintln!("     MSG_KEY_REQ, uploads to object storage, then exits.");
                eprintln!("  2. Auto-unseal: set SEALED_KEY_URL to fetch and decrypt a sealed");
                eprintln!("     key blob at boot using AMD SEV-SNP attestation.");
                eprintln!("  3. Key file: --key-file <PATH> to load a NodeKeyShare JSON file");
                eprintln!("     from disk (for testing/dev).");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -p, --port <PORT>         Listen port (default: 3001)");
                eprintln!(
                    "      --init-seal           Run initial deployment (seal + upload) mode"
                );
                eprintln!("      --upload-url <URL>    Storage URL for sealed blob (gs://, s3://, https://, file://)");
                eprintln!("      --key-file <PATH>     Load key share from JSON file at boot");
                eprintln!("      --tls-cert <PATH>     TLS server certificate (PEM)");
                eprintln!("      --tls-key <PATH>      TLS server private key (PEM)");
                eprintln!("      --client-ca <PATH>    CA cert for client auth (enables mTLS)");
                eprintln!("  -h, --help                Show this help");
                eprintln!();
                eprintln!("Environment:");
                eprintln!("  PORT                        Listen port (default: 3001)");
                eprintln!("  SEALED_KEY_URL              URL to sealed key blob (gs://, s3://, https://, file://)");
                eprintln!("  EXPECTED_VERIFICATION_SHARE Hex-encoded k_i * G for key verification");
                eprintln!("  SNP_PROVIDER                Attestation provider: \"gcp\" or \"raw\" (default: \"raw\")");
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
        if upload_url.is_none() {
            eprintln!("Error: --init-seal requires --upload-url <URL>");
            std::process::exit(1);
        }

        // Run init-seal mode and exit
        run_init_seal(&port, upload_url.unwrap()).await;
        return;
    }

    if upload_url.is_some() {
        eprintln!("Error: --upload-url can only be used with --init-seal");
        std::process::exit(1);
    }

    let state = Arc::new(NodeState {
        loaded_key: OnceLock::new(),
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

        // Detect blob version to choose the right unseal path
        let blob_version = toprf_seal::detect_sealed_version(&sealed_blob)
            .expect("auto-unseal: failed to detect sealed blob version");

        info!(
            blob_version = blob_version,
            "auto-unseal: detected sealed blob version"
        );

        let share_json = match blob_version {
            2 => {
                // v2: Hardware-derived key via MSG_KEY_REQ
                info!("auto-unseal: v2 blob detected, requesting hardware-derived key via MSG_KEY_REQ");

                let derived_key = toprf_seal::get_derived_key(toprf_seal::SAFE_FIELD_SELECT)
                    .expect("auto-unseal: failed to get hardware-derived key via MSG_KEY_REQ");

                // Log v2 header info
                if let Ok(field_select) = toprf_seal::parse_v2_header(&sealed_blob) {
                    info!(
                        field_select = format!("0x{field_select:X}"),
                        "auto-unseal: v2 blob field_select"
                    );
                }

                Zeroizing::new(
                    toprf_seal::unseal_derived(&sealed_blob, &derived_key).expect(
                        "auto-unseal: v2 decryption failed — derived key mismatch or corrupt blob",
                    ),
                )
            }
            1 => {
                // v1: HKDF-from-measurement (backwards compatibility)
                info!("auto-unseal: v1 blob detected, using HKDF-based unseal (legacy)");

                // Get attestation measurement for v1 unseal
                let provider = match env::var("SNP_PROVIDER").as_deref() {
                    Ok("gcp") => toprf_seal::provider::SnpProvider::GcpMetadata,
                    _ => toprf_seal::provider::SnpProvider::DevSevGuest,
                };
                let report = toprf_seal::provider::get_attestation_report(provider, None)
                    .await
                    .expect("failed to get attestation report");

                // Verify report authenticity
                toprf_seal::attestation::AttestationVerifier::verify_report(&report)
                    .await
                    .expect("attestation report verification failed");

                let measurement = report.measurement;
                let policy = report.policy;

                // Parse sealed blob header for logging
                if let Ok((sealed_measurement, sealed_policy)) =
                    toprf_seal::sealing::parse_sealed_header(&sealed_blob)
                {
                    info!(
                        sealed_for = %hex::encode(sealed_measurement),
                        our_measurement = %hex::encode(measurement),
                        sealed_policy = sealed_policy,
                        report_policy = policy,
                        "auto-unseal: v1 measurement comparison"
                    );
                }

                Zeroizing::new(
                    toprf_seal::sealing::unseal(&sealed_blob, &measurement, policy).expect(
                        "auto-unseal: v1 decryption failed — measurement mismatch or corrupt blob",
                    ),
                )
            }
            other => {
                panic!("auto-unseal: unsupported sealed blob version: {other}");
            }
        };

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
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/info", get(node_info))
        .route("/partial-evaluate", post(eval))
        .layer(DefaultBodyLimit::max(8192))
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
