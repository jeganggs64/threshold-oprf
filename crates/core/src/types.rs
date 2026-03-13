use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum TOPRFError {
    #[error("hash-to-curve failed after 256 attempts")]
    HashToCurveFailed,

    #[error("invalid point encoding: {0}")]
    InvalidPoint(String),

    #[error("invalid scalar encoding: {0}")]
    InvalidScalar(String),

    #[error("FROST error: {0}")]
    Frost(String),

    #[error("not enough partial evaluations: need {need}, got {got}")]
    InsufficientPartials { need: usize, got: usize },

    #[error("DLEQ proof verification failed for node {0}")]
    DLEQVerificationFailed(u16),

    #[error("reshare error: {0}")]
    ReshareError(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// A node's identifier (1-indexed).
pub type NodeId = u16;

/// A partial OPRF evaluation from a single node.
#[derive(Clone, Serialize, Deserialize)]
pub struct PartialEvaluation {
    pub node_id: NodeId,
    /// Compressed SEC1 encoding of the partial evaluation point (33 bytes hex).
    pub partial_point: String,
    /// DLEQ proof: (challenge, response) proving the node used its correct key share.
    pub dleq_proof: DLEQProof,
}

impl std::fmt::Debug for PartialEvaluation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialEvaluation")
            .field("node_id", &self.node_id)
            .field("partial_point", &"<redacted>")
            .field("dleq_proof", &"<redacted>")
            .finish()
    }
}

/// DLEQ proof: proves that log_G(V) == log_B(E) where V is the verification
/// share and E is the partial evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct DLEQProof {
    pub challenge: String,
    pub response: String,
}

impl std::fmt::Debug for DLEQProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DLEQProof")
            .field("challenge", &self.challenge)
            .field("response", &"<redacted>")
            .finish()
    }
}

/// Serialized key share for a single node.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct NodeKeyShare {
    pub node_id: NodeId,
    /// The secret scalar share (32 bytes hex).
    pub secret_share: String,
    /// The verification share (compressed point, 33 bytes hex).
    pub verification_share: String,
    /// The group public key (compressed point, 33 bytes hex).
    pub group_public_key: String,
    /// Threshold (min_signers).
    pub threshold: u16,
    /// Total number of shares (max_signers).
    pub total_shares: u16,
}

impl std::fmt::Debug for NodeKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKeyShare")
            .field("node_id", &self.node_id)
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("secret_share", &"<redacted>")
            .field("verification_share", &self.verification_share)
            .field("group_public_key", &self.group_public_key)
            .finish()
    }
}

/// Result of the key generation ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenResult {
    /// The group public key (compressed point, 33 bytes hex).
    pub group_public_key: String,
    /// Individual node key shares.
    pub shares: Vec<NodeKeyShare>,
    /// Threshold.
    pub threshold: u16,
    /// Total shares.
    pub total_shares: u16,
}

// -- Point encoding helpers --

/// Encode a ProjectivePoint as compressed hex (33 bytes → 66 hex chars).
pub fn point_to_hex(point: &ProjectivePoint) -> String {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    hex::encode(encoded.as_bytes())
}

/// Decode a compressed hex point (66 hex chars) to ProjectivePoint.
pub fn hex_to_point(h: &str) -> Result<ProjectivePoint, TOPRFError> {
    let bytes = hex::decode(h).map_err(|e| TOPRFError::InvalidPoint(e.to_string()))?;
    let encoded =
        EncodedPoint::from_bytes(&bytes).map_err(|e| TOPRFError::InvalidPoint(e.to_string()))?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    if affine.is_some().into() {
        let point = ProjectivePoint::from(affine.unwrap());
        if bool::from(point.is_identity()) {
            return Err(TOPRFError::InvalidInput(
                "identity point not allowed".into(),
            ));
        }
        Ok(point)
    } else {
        Err(TOPRFError::InvalidPoint("not on curve".into()))
    }
}

/// Encode a Scalar as hex (32 bytes → 64 hex chars).
pub fn scalar_to_hex(s: &Scalar) -> String {
    use zeroize::Zeroizing;
    let bytes = Zeroizing::new(s.to_bytes());
    hex::encode(&bytes[..])
}

/// Decode a hex string (64 hex chars) to Scalar.
pub fn hex_to_scalar(h: &str) -> Result<Scalar, TOPRFError> {
    let bytes = hex::decode(h).map_err(|e| TOPRFError::InvalidScalar(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(TOPRFError::InvalidScalar(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes.try_into().unwrap();
    let field_bytes = k256::FieldBytes::from(arr);
    let scalar: Scalar = Option::from(Scalar::from_repr(field_bytes))
        .ok_or_else(|| TOPRFError::InvalidScalar("scalar out of range".into()))?;
    if bool::from(scalar.is_zero()) {
        return Err(TOPRFError::InvalidInput("zero scalar not allowed".into()));
    }
    Ok(scalar)
}

/// Like `hex_to_scalar` but allows zero — used for DLEQ proof components
/// where zero is theoretically valid (with negligible probability).
pub fn hex_to_scalar_unrestricted(hex_str: &str) -> Result<Scalar, TOPRFError> {
    let bytes = hex::decode(hex_str).map_err(|e| TOPRFError::InvalidScalar(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(TOPRFError::InvalidScalar("expected 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let fb = k256::FieldBytes::from(arr);
    Option::from(Scalar::from_repr(fb))
        .ok_or_else(|| TOPRFError::InvalidScalar("not a valid scalar".into()))
}
