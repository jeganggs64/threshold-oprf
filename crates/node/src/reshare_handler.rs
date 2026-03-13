//! Share recovery endpoint for donor nodes.
//!
//! `POST /reshare` — accepts a new node's attestation report, cert chain,
//! and X25519 public key. Independently verifies attestation, generates a
//! recovery contribution (Lagrange-weighted share), ECIES-encrypts it to
//! the verified pubkey, and returns the encrypted sub-share.
//!
//! This implements single-node share recovery: one node is replaced at a time
//! while all other nodes keep their existing shares. The new share lies on the
//! SAME polynomial as the existing shares.
//!
//! Security: the donor node is the trust anchor. It verifies the target's
//! attestation independently — Lambda/orchestrator is just a courier.
//! Even a fully compromised orchestrator cannot extract sub-shares for an
//! unattested or wrongly-measured target.
//!
//! Dev mode: when `RESHARE_SKIP_ATTESTATION=true` is set, attestation
//! verification is skipped and the sub-share is returned as plaintext hex.
//! This is for local integration testing only.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use toprf_core::reshare::{generate_recovery_contribution, SerializableReshareContribution};
use toprf_core::scalar_to_hex;

use crate::NodeState;

/// Request body for POST /reshare.
#[derive(Deserialize)]
pub struct ReshareRequest {
    /// The new node's X25519 public key (hex-encoded, 64 chars / 32 bytes).
    pub target_pubkey: String,
    /// SNP attestation report (base64-encoded binary).
    pub attestation_report: String,
    /// Certificate chain from extended report (base64-encoded binary).
    pub cert_chain: String,
    /// The target new node's ID (1-indexed).
    pub new_node_id: u16,
    /// IDs of all participating donor nodes (must include this node).
    pub participant_ids: Vec<u16>,
    /// Expected measurement of the target node (hex, 96 chars / 48 bytes).
    /// Ignored in dev mode.
    pub expected_measurement: String,
    /// Group public key — donor verifies this matches its own.
    pub group_public_key: String,
}

/// Response body from POST /reshare.
#[derive(Serialize)]
pub struct ReshareResponse {
    /// The serializable contribution (encrypted or plaintext sub-share).
    #[serde(flatten)]
    pub contribution: SerializableReshareContribution,
}

/// POST /reshare — donor node endpoint.
pub async fn reshare_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<ReshareRequest>,
) -> Result<Json<ReshareResponse>, axum::response::Response> {
    // 1. Check key is loaded
    let key = state.loaded_key.get().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "no key loaded".to_string()).into_response()
    })?;

    // 2. Verify group_public_key matches this node's
    if req.group_public_key != key.group_public_key {
        warn!(
            expected = %key.group_public_key,
            got = %req.group_public_key,
            "reshare: group_public_key mismatch"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "group_public_key does not match this node's key".to_string(),
        )
            .into_response());
    }

    // 3. Verify this node is in the participant list
    if !req.participant_ids.contains(&key.node_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("this node ({}) is not in participant_ids", key.node_id),
        )
            .into_response());
    }

    // 4. Verify new_node_id is not in participant_ids
    if req.participant_ids.contains(&req.new_node_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            "new_node_id must not be in participant_ids".to_string(),
        )
            .into_response());
    }

    // 5. Decode the target X25519 public key
    let pubkey_bytes = hex::decode(&req.target_pubkey).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid target_pubkey hex: {e}"),
        )
            .into_response()
    })?;
    if pubkey_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("target_pubkey must be 32 bytes, got {}", pubkey_bytes.len()),
        )
            .into_response());
    }
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // 6. Attestation verification (skipped in dev mode)
    let skip_attestation = std::env::var("RESHARE_SKIP_ATTESTATION")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if skip_attestation {
        warn!("reshare: RESHARE_SKIP_ATTESTATION is set — skipping attestation verification. DO NOT USE IN PRODUCTION.");
    } else {
        // Decode attestation report and cert chain
        use base64::Engine;
        let report_bytes = base64::engine::general_purpose::STANDARD
            .decode(&req.attestation_report)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid attestation_report base64: {e}"),
                )
                    .into_response()
            })?;

        let cert_bytes = base64::engine::general_purpose::STANDARD
            .decode(&req.cert_chain)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid cert_chain base64: {e}"),
                )
                    .into_response()
            })?;

        // Parse the SNP report
        let report = toprf_seal::snp_report::SnpReport::from_bytes(&report_bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid attestation report: {e}"),
            )
                .into_response()
        })?;

        // Parse the certificate chain
        let certs = toprf_seal::attestation::parse_cert_table(&cert_bytes).map_err(|e| {
            (StatusCode::BAD_REQUEST, format!("invalid cert chain: {e}")).into_response()
        })?;

        // Verify AMD signature chain
        toprf_seal::attestation::AttestationVerifier::verify_report_with_certs(&report, &certs)
            .map_err(|e| {
                warn!("reshare: attestation verification failed: {e}");
                (
                    StatusCode::FORBIDDEN,
                    format!("attestation verification failed: {e}"),
                )
                    .into_response()
            })?;

        // Verify measurement matches expected
        let report_measurement_hex = hex::encode(report.measurement);
        if report_measurement_hex != req.expected_measurement {
            warn!(
                expected = %req.expected_measurement,
                got = %report_measurement_hex,
                "reshare: measurement mismatch"
            );
            return Err((
                StatusCode::FORBIDDEN,
                "measurement does not match expected value".to_string(),
            )
                .into_response());
        }

        // Verify REPORT_DATA binds to target_pubkey: REPORT_DATA[0..32] == SHA256(pubkey)
        let expected_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&pubkey_bytes);
            hasher.finalize()
        };
        if report.report_data[..32] != expected_hash[..] {
            warn!("reshare: REPORT_DATA does not match SHA256(target_pubkey)");
            return Err((
                StatusCode::FORBIDDEN,
                "REPORT_DATA does not bind to provided target_pubkey".to_string(),
            )
                .into_response());
        }

        info!(
            measurement = %report_measurement_hex,
            "reshare: attestation verified successfully"
        );
    }

    // 7. Generate recovery contribution: L_i(new_node_id) * k_i
    let sub_scalar = generate_recovery_contribution(
        key.node_id,
        &key.key_share,
        &req.participant_ids,
        req.new_node_id,
    )
    .map_err(|e| {
        warn!("reshare: contribution generation failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("reshare contribution failed: {e}"),
        )
            .into_response()
    })?;

    // 8. Encrypt or return plaintext based on mode
    let (sub_share_data, encrypted) = if skip_attestation {
        // Dev mode: return plaintext hex
        (scalar_to_hex(&sub_scalar), false)
    } else {
        // Production: ECIES-encrypt to the verified target pubkey
        let recipient = PublicKey::from(pubkey_arr);
        let sub_share_bytes = sub_scalar.to_bytes();
        let ciphertext = toprf_seal::ecies::encrypt(&recipient, &sub_share_bytes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ECIES encryption failed: {e}"),
            )
                .into_response()
        })?;
        use base64::Engine;
        (
            base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            true,
        )
    };

    // Donor's verification share for the new node to verify the contribution
    let donor_vs = key.verification_share.clone();

    info!(
        from_node_id = key.node_id,
        target_node_id = req.new_node_id,
        encrypted = encrypted,
        "reshare: recovery contribution generated"
    );

    Ok(Json(ReshareResponse {
        contribution: SerializableReshareContribution {
            from_node_id: key.node_id,
            new_node_id: req.new_node_id,
            sub_share_data,
            encrypted,
            verification_share: donor_vs,
        },
    }))
}
