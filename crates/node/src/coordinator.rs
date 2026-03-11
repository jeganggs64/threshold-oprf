//! Coordinator logic for node-as-coordinator mode.
//!
//! When a node receives a request on `POST /evaluate`, it acts as coordinator:
//! 1. Computes its own partial evaluation (E_self = k_i * B)
//! 2. Forwards the blinded point to a peer node via PrivateLink
//! 3. Verifies the peer's DLEQ proof
//! 4. Combines both partials via Lagrange interpolation
//! 5. Returns the final evaluation E = k * B
//!
//! Peers are tried in order; if the first peer fails, the next is attempted.
//! Only one peer is needed (threshold=2 means self + 1 peer).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use toprf_core::combine::combine_partials;
use toprf_core::partial_eval::partial_evaluate;
use toprf_core::{hex_to_point, point_to_hex, PartialEvaluation};

use crate::NodeState;

/// Configuration for peer nodes reachable via PrivateLink.
#[derive(Debug, Clone, Deserialize)]
pub struct CoordinatorConfig {
    pub peers: Vec<PeerNode>,
}

/// A peer node's connection details and verification share.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerNode {
    pub node_id: u16,
    /// PrivateLink endpoint, e.g. "http://vpce-xxx:3001"
    pub endpoint: String,
    /// Hex-encoded verification share (k_j * G) for DLEQ proof verification.
    pub verification_share: String,
}

#[derive(Serialize)]
pub struct EvaluateResponse {
    /// Combined OPRF evaluation point: E = k * B (compressed hex).
    pub evaluation: String,
    /// Partial evaluations used, with DLEQ proofs for optional client verification.
    pub partials: Vec<PartialEvaluation>,
}

/// POST /evaluate — coordinator endpoint.
pub async fn evaluate_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<crate::EvalRequest>,
) -> Result<Json<EvaluateResponse>, axum::response::Response> {
    let key = state.loaded_key.get().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "no key loaded".to_string()).into_response()
    })?;

    let coordinator = state.coordinator.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "coordinator not configured".to_string(),
        )
            .into_response()
    })?;

    // 1. Validate blinded point
    let blinded_point = hex_to_point(&req.blinded_point).map_err(|e| {
        warn!("invalid blinded_point: {e}");
        (StatusCode::BAD_REQUEST, "invalid blinded_point".to_string()).into_response()
    })?;

    // 2. Compute own partial evaluation
    let own_partial =
        partial_evaluate(key.node_id, &key.key_share, &blinded_point).map_err(|e| {
            error!("own partial evaluation failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "evaluation failed".to_string(),
            )
                .into_response()
        })?;

    info!(node_id = key.node_id, "computed own partial");

    // 3. Call peers — try each in order until one succeeds
    let mut peer_partial: Option<PartialEvaluation> = None;
    let mut peer_vs: Option<String> = None;

    for peer in &coordinator.peers {
        match call_peer(&state.http_client, peer, &req.blinded_point).await {
            Ok(partial) => {
                info!(peer_node_id = peer.node_id, "received peer partial");
                peer_vs = Some(peer.verification_share.clone());
                peer_partial = Some(partial);
                break;
            }
            Err(e) => {
                warn!(peer_node_id = peer.node_id, error = %e, "peer call failed, trying next");
            }
        }
    }

    let peer_partial = peer_partial.ok_or_else(|| {
        error!("all peers unreachable");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no peer available".to_string(),
        )
            .into_response()
    })?;

    // 4. Combine partials via Lagrange interpolation (verifies DLEQ proofs internally)
    let partials = vec![own_partial, peer_partial];
    let verification_shares = vec![
        (key.node_id, key.verification_share.clone()),
        (partials[1].node_id, peer_vs.unwrap()),
    ];

    let combined = combine_partials(
        &partials,
        &blinded_point,
        &verification_shares,
        key.threshold as usize,
    )
    .map_err(|e| {
        error!("combine_partials failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "combination failed".to_string(),
        )
            .into_response()
    })?;

    info!(
        coordinator = key.node_id,
        peer = partials[1].node_id,
        "evaluation complete"
    );

    Ok(Json(EvaluateResponse {
        evaluation: point_to_hex(&combined),
        partials,
    }))
}

/// Call a peer node's /partial-evaluate endpoint via PrivateLink.
async fn call_peer(
    client: &reqwest::Client,
    peer: &PeerNode,
    blinded_point: &str,
) -> Result<PartialEvaluation, String> {
    let url = format!(
        "{}/partial-evaluate",
        peer.endpoint.trim_end_matches('/')
    );

    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "blinded_point": blinded_point }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("peer returned {status}: {body}"));
    }

    let partial: PartialEvaluation = resp
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if partial.node_id != peer.node_id {
        return Err(format!(
            "node_id mismatch: expected {}, got {}",
            peer.node_id, partial.node_id
        ));
    }

    Ok(partial)
}
