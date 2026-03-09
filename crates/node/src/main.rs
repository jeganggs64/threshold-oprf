//! TOPRF node server — stateless TEE that evaluates OPRF requests.
//!
//! Key loading modes (at boot, never at runtime):
//!
//! 1. **Auto-unseal** (production) — When `SEALED_KEY_URL` is set, the node
//!    fetches a sealed key blob from object storage at boot, derives the
//!    sealing key from its AMD SEV-SNP attestation measurement, and decrypts
//!    the share automatically. No admin interaction required after deployment.
//!
//! 2. **Key file** (testing/dev) — `--key-file <PATH>` loads a NodeKeyShare
//!    JSON file from disk at boot. No network endpoint is exposed for key
//!    loading.
//!
//! In both modes, the key exists only in memory after loading. If the TEE
//! restarts, auto-unseal re-derives the key from the sealed blob.
//!
//! Endpoints:
//!   GET  /health           — liveness + key status ("waiting_for_key" or "ready")
//!   GET  /info             — public info (only when key is loaded)
//!   POST /partial-evaluate — OPRF partial evaluation (only when key is loaded)
//!
//! Usage:
//!   toprf-node --port 3001 --key-file /path/to/share.json
//!
//! Environment variables:
//!   PORT                       — HTTP listen port (default: 3001)
//!   SEALED_KEY_URL             — HTTPS or file:// URL to a sealed key blob
//!   EXPECTED_VERIFICATION_SHARE — hex-encoded k_i * G for key verification
//!   SNP_PROVIDER               — attestation provider: "gcp" or "raw" (default: "raw")

use std::env;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::extract::DefaultBodyLimit;
use axum::{Json, Router};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

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
    let key = state.loaded_key.get().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "no key loaded".into(),
    ))?;

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
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no key loaded".to_string(),
        )
            .into_response()
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
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "evaluation failed".to_string()).into_response());
        }
    };

    info!(
        node_id = key.node_id,
        partial_point = %partial.partial_point,
        "partial evaluation complete"
    );

    Ok(Json(partial))
}

// -- Auto-unseal helpers --

/// Returns `true` if the IP is loopback, private, link-local, or otherwise
/// not a globally routable address. Used to block SSRF via DNS rebinding.
fn is_non_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()          // 127.0.0.0/8
            || v4.is_private()        // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local()     // 169.254/16
            || v4.is_broadcast()      // 255.255.255.255
            || v4.is_unspecified()    // 0.0.0.0
            || v4.is_documentation()  // 192.0.2/24, 198.51.100/24, 203.0.113/24
            // Shared address space (RFC 6598) — used by carrier-grade NAT
            || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()          // ::1
            || v6.is_unspecified()    // ::
            // IPv4-mapped (::ffff:0:0/96) — check the embedded v4
            || match v6.to_ipv4_mapped() {
                Some(v4) => is_non_global_ip(&IpAddr::V4(v4)),
                None => false,
            }
            // Unique local (fc00::/7) and link-local (fe80::/10)
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

async fn fetch_sealed_blob(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if url.starts_with("file://") {
        tracing::warn!("using file:// URL for sealed blob — not recommended for production");
        let path = &url[7..];
        let bytes = tokio::fs::read(path).await?;
        if bytes.len() > 1024 * 1024 {
            return Err("sealed blob too large (>1MB)".into());
        }
        return Ok(bytes);
    }

    if !url.starts_with("https://") {
        return Err("SEALED_KEY_URL must use https:// (or file:// for local testing)".into());
    }

    // Block private/loopback/link-local addresses to prevent SSRF.
    // We resolve the hostname to IPs and reject any non-global address.
    // This defeats DNS rebinding attacks where a hostname initially resolves
    // to a public IP but later re-resolves to an internal one.
    let authority = url.strip_prefix("https://").unwrap_or(url);
    let authority = authority.split('/').next().unwrap_or("");
    let host_for_resolve = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:443")
    };
    let addrs: Vec<SocketAddr> = host_for_resolve
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve SEALED_KEY_URL host: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("SEALED_KEY_URL host resolved to no addresses".into());
    }
    for addr in &addrs {
        if is_non_global_ip(&addr.ip()) {
            return Err(format!(
                "SEALED_KEY_URL resolved to non-public address {} — SSRF blocked",
                addr.ip()
            )
            .into());
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(format!("failed to fetch sealed blob: HTTP {}", resp.status()).into());
    }
    // Check Content-Length before downloading the full body to avoid
    // reading an unexpectedly large response into memory.
    if let Some(len) = resp.content_length() {
        if len > 1024 * 1024 {
            return Err("sealed blob too large (Content-Length > 1MB)".into());
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > 1024 * 1024 {
        return Err("sealed blob too large (>1MB)".into());
    }
    Ok(bytes.to_vec())
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
            "--help" | "-h" => {
                eprintln!("Usage: toprf-node [OPTIONS]");
                eprintln!();
                eprintln!("Key loading (at boot only — no runtime key endpoints):");
                eprintln!("  1. Auto-unseal: set SEALED_KEY_URL to fetch and decrypt a sealed");
                eprintln!("     key blob at boot using AMD SEV-SNP attestation.");
                eprintln!("  2. Key file: --key-file <PATH> to load a NodeKeyShare JSON file");
                eprintln!("     from disk (for testing/dev).");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -p, --port <PORT>        Listen port (default: 3001)");
                eprintln!("      --key-file <PATH>    Load key share from JSON file at boot");
                eprintln!("      --tls-cert <PATH>    TLS server certificate (PEM)");
                eprintln!("      --tls-key <PATH>     TLS server private key (PEM)");
                eprintln!("      --client-ca <PATH>   CA cert for client auth (enables mTLS)");
                eprintln!("  -h, --help               Show this help");
                eprintln!();
                eprintln!("Environment:");
                eprintln!("  PORT                        Listen port (default: 3001)");
                eprintln!("  SEALED_KEY_URL              HTTPS or file:// URL to sealed key blob");
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
        let share_bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read key file {path}: {e}"));
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

        state.loaded_key.set(loaded).expect("key file: OnceLock already set");
        info!(
            node_id = share.node_id,
            threshold = share.threshold,
            total_shares = share.total_shares,
            "key share loaded from file"
        );
    }

    // -- Auto-unseal from object storage (if configured) --
    if let Ok(sealed_url) = env::var("SEALED_KEY_URL") {
        let display_url = sealed_url.split('?').next().unwrap_or(&sealed_url);
        info!("auto-unseal: fetching sealed key from {display_url}");

        let expected_vs = env::var("EXPECTED_VERIFICATION_SHARE")
            .expect("EXPECTED_VERIFICATION_SHARE required when SEALED_KEY_URL is set");

        let sealed_blob = fetch_sealed_blob(&sealed_url)
            .await
            .expect("failed to fetch sealed blob from object storage");

        // Get attestation measurement — only real attestation is supported
        let provider = match env::var("SNP_PROVIDER").as_deref() {
            Ok("gcp") => toprf_seal::provider::SnpProvider::GcpMetadata,
            _ => toprf_seal::provider::SnpProvider::DevSevGuest,
        };
        let report =
            toprf_seal::provider::get_attestation_report(provider, None)
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
                "auto-unseal: measurement comparison"
            );
        }

        // Derive sealing key from OUR attestation measurement and policy,
        // then unseal. Using the report's policy (not the blob header's)
        // ensures we trust the hardware attestation, not stored metadata.
        let share_json = Zeroizing::new(
            toprf_seal::sealing::unseal(&sealed_blob, &measurement, policy)
                .expect("auto-unseal: decryption failed — measurement mismatch or corrupt blob"),
        );

        // Parse the unsealed key share
        let share: NodeKeyShare = serde_json::from_slice(&share_json)
            .expect("auto-unseal: unsealed data is not valid NodeKeyShare JSON");

        // Verify key: k_i * G == expected verification share
        let key_scalar = hex_to_scalar(&share.secret_share)
            .expect("auto-unseal: invalid secret_share scalar");
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
                    root_store.add(cert).expect("failed to add CA cert to root store");
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
                let private_key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
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
                let private_key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
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
