//! TOPRF proxy — the single entry point for mobile app OPRF requests.
//!
//! Responsibilities:
//!   1. Issue challenge nonces for attestation
//!   2. Register devices via Apple App Attest (one-time)
//!   3. Validate attestation tokens (Apple / Google) per request
//!   4. Rate limit per device (per hour / per day)
//!   5. Validate that the blinded point is a valid secp256k1 curve point
//!   6. Fan out to nodes over TLS, collect ≥ threshold partial evaluations
//!   7. Verify each DLEQ proof against known verification shares
//!   8. Return verified partials to the app (app does Lagrange + unblinding)
//!
//! The proxy never sees the unblinded point or the final ruonID.

mod attestation;
mod device_keys;
mod nonce;
mod rate_limit;

use std::env;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::extract::DefaultBodyLimit;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use toprf_core::partial_eval::verify_partial;
use toprf_core::{hex_to_point, PartialEvaluation};

use crate::device_keys::DeviceKeyStore;
use crate::nonce::NonceStore;

// -- Configuration --

#[derive(Deserialize, Clone)]
struct ProxyConfig {
    group_public_key: String,
    threshold: u16,
    nodes: Vec<NodeConfig>,
    #[serde(default)]
    rate_limit: RateLimitConfig,
    require_attestation: bool,
    /// Apple App ID (e.g., "TEAMID.com.example.app") for attestation verification.
    #[serde(default)]
    apple_app_id: String,
    /// Android package name for Play Integrity verification.
    #[serde(default)]
    android_package_name: String,
    /// CA certificate path for verifying node TLS certs (pins proxy→node connections).
    #[serde(default)]
    node_ca_cert: Option<String>,
    /// Client certificate path (PEM) for mTLS with nodes.
    #[serde(default)]
    proxy_client_cert: Option<String>,
    /// Client private key path (PEM) for mTLS with nodes.
    #[serde(default)]
    proxy_client_key: Option<String>,
    /// Path to persist device keys (JSON). Omit for in-memory only.
    #[serde(default)]
    device_keys_path: Option<String>,
    /// Path to persist rate limit state (JSON). Omit for in-memory only.
    #[serde(default)]
    rate_limit_path: Option<String>,
}

#[derive(Deserialize, Clone)]
struct NodeConfig {
    node_id: u16,
    endpoint: String,
    verification_share: String,
}

#[derive(Deserialize, Clone)]
struct RateLimitConfig {
    #[serde(default = "default_per_hour")]
    per_hour: u32,
    #[serde(default = "default_per_day")]
    per_day: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_hour: default_per_hour(),
            per_day: default_per_day(),
        }
    }
}

fn default_per_hour() -> u32 { 10 }
fn default_per_day() -> u32 { 30 }

// -- Application state --

struct ProxyState {
    config: ProxyConfig,
    http_client: reqwest::Client,
    rate_limiter: RwLock<rate_limit::RateLimiter>,
    nonce_store: RwLock<NonceStore>,
    device_keys: RwLock<DeviceKeyStore>,
    /// Monotonic counter of successful evaluations.
    total_evaluations: AtomicU64,
    /// Instant the server was started (for uptime calculation).
    started_at: Instant,
}

// -- Request/response types --

#[derive(Deserialize)]
struct EvalRequest {
    blinded_point: String,
    /// Attestation token (base64 JSON). Required when require_attestation is true.
    #[serde(default)]
    attestation_token: Option<String>,
    /// Challenge nonce. Required when require_attestation is true.
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct AttestRequest {
    /// Base64-encoded CBOR attestation object from Apple.
    attestation_object: String,
    /// The key ID from the Secure Enclave.
    key_id: String,
    /// The challenge nonce.
    nonce: String,
}

#[derive(Serialize)]
struct VerifiedPartial {
    node_id: u16,
    partial_point: String,
}

#[derive(Serialize)]
struct EvalResponse {
    partials: Vec<VerifiedPartial>,
    threshold: u16,
}

#[derive(Serialize)]
struct ChallengeResponse {
    nonce: String,
}

#[derive(Serialize)]
struct AttestResponse {
    device_id: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    threshold: u16,
    total_nodes: usize,
    nodes_up: usize,
    nodes_status: Vec<NodeHealthStatus>,
}

#[derive(Serialize)]
struct NodeHealthStatus {
    node_id: u16,
    status: String,
}

#[derive(Serialize)]
struct MetricsResponse {
    uptime_seconds: u64,
    total_evaluations: u64,
    active_devices: usize,
    nodes_configured: usize,
    threshold: u16,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    group_public_key: String,
}

#[derive(Serialize)]
struct NodeEvalRequest {
    blinded_point: String,
}

// -- Handlers --

async fn health(State(state): State<Arc<ProxyState>>) -> Json<HealthResponse> {
    // Fan out HEAD /health requests to all nodes concurrently with a 2s timeout.
    let health_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| state.http_client.clone());

    let mut handles = tokio::task::JoinSet::new();
    for node in &state.config.nodes {
        let client = health_client.clone();
        let endpoint = node.endpoint.clone();
        let node_id = node.node_id;

        handles.spawn(async move {
            let url = format!("{endpoint}/health");
            let ok = client.head(&url).send().await.is_ok();
            (node_id, ok)
        });
    }

    let mut nodes_status: Vec<NodeHealthStatus> = Vec::with_capacity(state.config.nodes.len());
    let mut nodes_up: usize = 0;

    while let Some(result) = handles.join_next().await {
        match result {
            Ok((node_id, reachable)) => {
                let status = if reachable { "up" } else { "down" };
                if reachable {
                    nodes_up += 1;
                }
                nodes_status.push(NodeHealthStatus {
                    node_id,
                    status: status.into(),
                });
            }
            Err(_) => {
                // JoinError — task panicked; treat as down. We don't know the
                // node_id here so we skip adding a status entry.
            }
        }
    }

    // Sort by node_id for deterministic output.
    nodes_status.sort_by_key(|n| n.node_id);

    let overall = if nodes_up >= state.config.threshold as usize {
        "ok"
    } else {
        "degraded"
    };

    Json(HealthResponse {
        status: overall.into(),
        threshold: state.config.threshold,
        total_nodes: state.config.nodes.len(),
        nodes_up,
        nodes_status,
    })
}

/// Operational metrics snapshot.
async fn metrics(State(state): State<Arc<ProxyState>>) -> Json<MetricsResponse> {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let total_evaluations = state.total_evaluations.load(Ordering::Relaxed);
    let active_devices = state.rate_limiter.read().await.device_count();

    Json(MetricsResponse {
        uptime_seconds,
        total_evaluations,
        active_devices,
        nodes_configured: state.config.nodes.len(),
        threshold: state.config.threshold,
    })
}

async fn public_key(State(state): State<Arc<ProxyState>>) -> Json<PublicKeyResponse> {
    Json(PublicKeyResponse {
        group_public_key: state.config.group_public_key.clone(),
    })
}

/// Issue a challenge nonce for attestation.
async fn challenge(State(state): State<Arc<ProxyState>>) -> Json<ChallengeResponse> {
    let nonce = state.nonce_store.write().await.issue();
    Json(ChallengeResponse { nonce })
}

/// One-time Apple App Attest device registration.
async fn attest(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, (StatusCode, String)> {
    // Validate nonce
    {
        let mut nonce_store = state.nonce_store.write().await;
        if !nonce_store.consume(&req.nonce) {
            return Err((StatusCode::FORBIDDEN, "invalid or expired nonce".into()));
        }
    }

    let mut key_store = state.device_keys.write().await;
    let device_id = attestation::verify_apple_attestation(
        &req.attestation_object,
        &req.key_id,
        &req.nonce,
        &state.config.apple_app_id,
        &mut key_store,
    )
    .map_err(|e| {
        warn!(error = %e, "attestation failed during device registration");
        (StatusCode::FORBIDDEN, "attestation failed".to_string())
    })?;

    Ok(Json(AttestResponse { device_id }))
}

/// Main OPRF evaluation endpoint.
async fn evaluate(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<EvalRequest>,
) -> Result<Json<EvalResponse>, (StatusCode, String)> {
    // -- 1. Attestation + nonce validation --
    let device_id = if state.config.require_attestation {
        let attestation_token = req
            .attestation_token
            .as_deref()
            .ok_or((StatusCode::BAD_REQUEST, "missing attestation_token".into()))?;
        let nonce = req
            .nonce
            .as_deref()
            .ok_or((StatusCode::BAD_REQUEST, "missing nonce".into()))?;

        // Consume nonce (single-use)
        {
            let mut nonce_store = state.nonce_store.write().await;
            if !nonce_store.consume(nonce) {
                return Err((StatusCode::FORBIDDEN, "invalid or expired nonce".into()));
            }
        }

        // Verify attestation
        let mut key_store = state.device_keys.write().await;
        attestation::verify_attestation(
            attestation_token,
            nonce,
            &state.config.apple_app_id,
            &state.config.android_package_name,
            &mut key_store,
            &state.http_client,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "attestation failed during evaluation");
            (StatusCode::FORBIDDEN, "attestation failed".to_string())
        })?
    } else {
        "anonymous".to_string()
    };

    // -- 2. Rate limiting --
    {
        let mut limiter = state.rate_limiter.write().await;
        limiter
            .check_and_record(
                &device_id,
                state.config.rate_limit.per_hour,
                state.config.rate_limit.per_day,
            )
            .map_err(|msg| {
                warn!(device_id = %device_id, msg, "rate limited");
                (StatusCode::TOO_MANY_REQUESTS, msg.to_string())
            })?;
    }

    // -- 3. Validate blinded point --
    let blinded_point = hex_to_point(&req.blinded_point)
        .map_err(|e| {
            warn!(error = %e, "invalid blinded_point from client");
            (StatusCode::BAD_REQUEST, "invalid blinded_point".to_string())
        })?;

    let threshold = state.config.threshold as usize;

    // -- 4. Fan out to all nodes --
    let mut handles = tokio::task::JoinSet::new();

    for node in &state.config.nodes {
        let client = state.http_client.clone();
        let endpoint = node.endpoint.clone();
        let node_id = node.node_id;
        let blinded_hex = req.blinded_point.clone();

        handles.spawn(async move {
            let url = format!("{endpoint}/partial-evaluate");
            let resp = client
                .post(&url)
                .json(&NodeEvalRequest {
                    blinded_point: blinded_hex,
                })
                .send()
                .await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    match r.json::<PartialEvaluation>().await {
                        Ok(partial) => Ok((node_id, partial)),
                        Err(e) => {
                            eprintln!("node {node_id}: bad response: {e}");
                            Err((node_id, "bad response from node".to_string()))
                        }
                    }
                }
                Ok(r) => {
                    let status = r.status();
                    let body = r.bytes().await.unwrap_or_default();
                    let body = String::from_utf8_lossy(&body[..body.len().min(1024)]).to_string();
                    eprintln!("node {node_id}: HTTP {status}: {body}");
                    Err((node_id, format!("node returned HTTP {status}")))
                }
                Err(e) => {
                    eprintln!("node {node_id}: request failed: {e}");
                    Err((node_id, "request to node failed".to_string()))
                }
            }
        });
    }

    // -- 5. Collect ≥ threshold responses --
    let mut partials: Vec<PartialEvaluation> = Vec::with_capacity(threshold);
    let mut errors: Vec<(u16, String)> = Vec::new();

    let mut seen_node_ids = std::collections::HashSet::new();

    while let Some(result) = handles.join_next().await {
        match result {
            Ok(Ok((expected_node_id, partial))) => {
                if partial.node_id != expected_node_id {
                    warn!(expected = expected_node_id, got = partial.node_id, "node returned wrong node_id");
                    errors.push((expected_node_id, "node_id mismatch in response".into()));
                } else if !seen_node_ids.insert(partial.node_id) {
                    warn!(node_id = partial.node_id, "duplicate node_id in partials, skipping");
                } else {
                    info!(node_id = partial.node_id, "received partial evaluation");
                    partials.push(partial);
                    if partials.len() >= threshold {
                        handles.abort_all();
                        break;
                    }
                }
            }
            Ok(Err((node_id, err))) => {
                warn!(node_id, error = %err, "node failed");
                errors.push((node_id, err));
            }
            Err(e) => {
                warn!(error = %e, "task error");
            }
        }
    }

    if partials.len() < threshold {
        // Log full details server-side for debugging
        for (id, e) in &errors {
            tracing::warn!(node_id = id, error = %e, "node error during evaluation");
        }
        // Return generic message to client (no internal details)
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "insufficient nodes available: need {threshold}, got {}",
                partials.len()
            ),
        ));
    }

    // -- 6. Verify DLEQ proofs, strip proofs, return partials --
    let mut verified: Vec<VerifiedPartial> = Vec::with_capacity(partials.len());

    for partial in &partials {
        let vs = state
            .config
            .nodes
            .iter()
            .find(|n| n.node_id == partial.node_id)
            .ok_or_else(|| {
                error!(node_id = partial.node_id, "received partial from unknown node");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal configuration error".to_string(),
                )
            })?;

        verify_partial(partial, &blinded_point, &vs.verification_share).map_err(|e| {
            error!(node_id = partial.node_id, error = %e, "DLEQ verification failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DLEQ proof verification failed".to_string(),
            )
        })?;

        verified.push(VerifiedPartial {
            node_id: partial.node_id,
            partial_point: partial.partial_point.clone(),
        });
    }

    state.total_evaluations.fetch_add(1, Ordering::Relaxed);

    info!(
        device_id = %device_id,
        partials_returned = verified.len(),
        "evaluation complete"
    );

    Ok(Json(EvalResponse {
        partials: verified,
        threshold: state.config.threshold,
    }))
}

// -- Main --

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut config_file = env::var("CONFIG_FILE").unwrap_or_default();
    let mut port = env::var("PORT").unwrap_or_else(|_| "3000".into());
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_file = args[i].clone();
            }
            "--port" | "-p" => {
                i += 1;
                port = args[i].clone();
            }
            "--tls-cert" => {
                i += 1;
                tls_cert = Some(args[i].clone());
            }
            "--tls-key" => {
                i += 1;
                tls_key = Some(args[i].clone());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-proxy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -c, --config <PATH>    Path to proxy config JSON");
                eprintln!("  -p, --port <PORT>      Listen port (default: 3000)");
                eprintln!("      --tls-cert <PATH>  TLS server certificate (PEM)");
                eprintln!("      --tls-key <PATH>   TLS server private key (PEM)");
                eprintln!("  -h, --help             Show this help");
                eprintln!();
                eprintln!("When --tls-cert and --tls-key are provided, the proxy serves HTTPS.");
                eprintln!("Otherwise it serves plain HTTP.");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if config_file.is_empty() {
        eprintln!("Error: --config or CONFIG_FILE is required");
        std::process::exit(1);
    }

    let config_json = std::fs::read_to_string(&config_file)
        .unwrap_or_else(|e| panic!("failed to read config {config_file}: {e}"));
    let config: ProxyConfig = serde_json::from_str(&config_json)
        .unwrap_or_else(|e| panic!("failed to parse config: {e}"));

    // Validate configuration invariants
    if config.threshold < 1 {
        panic!("threshold must be at least 1");
    }
    if config.nodes.len() < config.threshold as usize {
        panic!(
            "not enough nodes ({}) for threshold ({})",
            config.nodes.len(),
            config.threshold
        );
    }
    {
        let mut config_node_ids = std::collections::HashSet::new();
        for node in &config.nodes {
            if node.node_id == 0 {
                panic!("node_id must be nonzero in config");
            }
            if !config_node_ids.insert(node.node_id) {
                panic!("duplicate node_id {} in config", node.node_id);
            }
        }
    }

    info!(
        threshold = config.threshold,
        nodes = config.nodes.len(),
        group_public_key = %config.group_public_key,
        rate_limit_hour = config.rate_limit.per_hour,
        rate_limit_day = config.rate_limit.per_day,
        require_attestation = config.require_attestation,
        "loaded proxy config"
    );

    for node in &config.nodes {
        info!(
            node_id = node.node_id,
            endpoint = %node.endpoint,
            "registered node"
        );
    }

    // Build HTTP client for node communication — with optional mTLS
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10));

    if let Some(ca_cert_path) = &config.node_ca_cert {
        let ca_pem = std::fs::read(ca_cert_path)
            .unwrap_or_else(|e| panic!("failed to read CA cert {ca_cert_path}: {e}"));
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
            .expect("invalid CA certificate PEM");
        client_builder = client_builder
            .add_root_certificate(ca_cert)
            .tls_built_in_root_certs(false); // Only trust our CA for node connections
        info!("TLS: using custom CA for node connections");
    }

    // mTLS: attach client certificate when connecting to nodes
    match (&config.proxy_client_cert, &config.proxy_client_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read_to_string(cert_path)
                .unwrap_or_else(|e| panic!("failed to read client cert {cert_path}: {e}"));
            let key_pem = std::fs::read_to_string(key_path)
                .unwrap_or_else(|e| panic!("failed to read client key {key_path}: {e}"));

            let combined_pem = format!("{}\n{}", cert_pem, key_pem);
            let identity = reqwest::Identity::from_pem(combined_pem.as_bytes())
                .expect("failed to parse client identity PEM");
            client_builder = client_builder.identity(identity);
            info!("mTLS: using client certificate for node connections");
        }
        (None, None) => {
            // No client certificate — plain TLS (or plain HTTP)
        }
        _ => {
            panic!("proxy_client_cert and proxy_client_key must both be set (or neither)");
        }
    }

    let http_client = client_builder.build().expect("failed to build HTTP client");

    // Initialize stores — persistent if paths are configured, in-memory otherwise
    let rate_limiter = match &config.rate_limit_path {
        Some(path) => rate_limit::RateLimiter::new_persistent(path),
        None => rate_limit::RateLimiter::new(),
    };

    let device_keys = match &config.device_keys_path {
        Some(path) => DeviceKeyStore::new_persistent(path),
        None => DeviceKeyStore::new(),
    };

    let state = Arc::new(ProxyState {
        config,
        http_client,
        rate_limiter: RwLock::new(rate_limiter),
        nonce_store: RwLock::new(NonceStore::new(Duration::from_secs(300))), // 5 min TTL
        device_keys: RwLock::new(device_keys),
        total_evaluations: AtomicU64::new(0),
        started_at: Instant::now(),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/oprf/public-key", get(public_key))
        .route("/oprf/challenge", get(challenge))
        .route("/oprf/attest", post(attest))
        .route("/oprf/evaluate", post(evaluate))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(state);

    let bind_addr = format!("0.0.0.0:{port}");

    // Determine whether to serve plain HTTP or HTTPS
    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            // -- TLS mode --
            use axum_server::tls_rustls::RustlsConfig;

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

            let mut rustls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .expect("failed to build rustls ServerConfig");

            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let tls_config = RustlsConfig::from_config(Arc::new(rustls_config));
            let addr: SocketAddr = bind_addr
                .parse()
                .unwrap_or_else(|e| panic!("invalid bind address {bind_addr}: {e}"));

            info!(addr = %bind_addr, "starting toprf-proxy with TLS");

            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            });

            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .unwrap_or_else(|e| error!("server error: {e}"));
        }
        (None, None) => {
            // -- Plain HTTP mode --
            info!(addr = %bind_addr, "starting toprf-proxy (plain HTTP)");

            let listener = TcpListener::bind(&bind_addr)
                .await
                .unwrap_or_else(|e| panic!("failed to bind to {bind_addr}: {e}"));

            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .unwrap_or_else(|e| error!("server error: {e}"));
        }
        _ => {
            eprintln!("Error: --tls-cert and --tls-key must both be provided (or neither)");
            std::process::exit(1);
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    tracing::info!("received shutdown signal");
}
