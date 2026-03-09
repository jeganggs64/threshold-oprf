//! Hash-to-curve implementation matching the JavaScript RuonID protocol.
//!
//! Uses try-and-increment with domain separator "RuonOPRF-v1":
//!   for ctr in 0..256:
//!     x = SHA-256("RuonOPRF-v1" || len(nationality) as u32 BE || nationality || personalNumber || ctr)
//!     try to decompress (02 || x) as a secp256k1 point
//!
//! The 4-byte nationality length prefix prevents ambiguity between
//! (nationality, personalNumber) pairs that would otherwise concatenate identically.
//!
//! NOTE: try-and-increment has a timing side-channel (the counter at which a valid
//! point is found leaks through execution time). This is acceptable because the server
//! never calls hash_to_curve on raw inputs — the client blinds the point before sending.
//!
//! This MUST produce identical outputs to the JS implementation in
//! `app/lib/oprf.ts` and `server/src/oprf/utils.ts`.

use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint};
use sha2::{Digest, Sha256};

use crate::TOPRFError;

/// Hash an identity input (nationality + personalNumber) to a secp256k1 curve point.
///
/// Matches the JS `hashToCurve(nationality, personalNumber)` function exactly.
pub fn hash_to_curve(nationality: &str, personal_number: &str) -> Result<ProjectivePoint, TOPRFError> {
    for ctr in 0u8..=255 {
        let mut hasher = Sha256::new();
        hasher.update(b"RuonOPRF-v1");
        let nat_len = u32::try_from(nationality.len())
            .map_err(|_| TOPRFError::InvalidInput("nationality too long".into()))?;
        hasher.update(&nat_len.to_be_bytes());
        hasher.update(nationality.as_bytes());
        hasher.update(personal_number.as_bytes());
        hasher.update([ctr]);
        let hash = hasher.finalize();

        // Build compressed point: 02 || hash (even y parity)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&hash);

        let encoded = match EncodedPoint::from_bytes(&compressed) {
            Ok(ep) => ep,
            Err(_) => continue,
        };

        let affine = AffinePoint::from_encoded_point(&encoded);
        if affine.is_some().into() {
            return Ok(ProjectivePoint::from(affine.unwrap()));
        }
    }

    Err(TOPRFError::HashToCurveFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::point_to_hex;

    #[test]
    fn test_hash_to_curve_deterministic() {
        let p1 = hash_to_curve("SGP", "S1234567A").unwrap();
        let p2 = hash_to_curve("SGP", "S1234567A").unwrap();
        assert_eq!(point_to_hex(&p1), point_to_hex(&p2));
    }

    #[test]
    fn test_hash_to_curve_different_inputs() {
        let p1 = hash_to_curve("SGP", "S1234567A").unwrap();
        let p2 = hash_to_curve("USA", "123456789").unwrap();
        assert_ne!(point_to_hex(&p1), point_to_hex(&p2));
    }

    #[test]
    fn test_hash_to_curve_produces_valid_point() {
        let point = hash_to_curve("GBR", "AB123456").unwrap();
        let hex = point_to_hex(&point);
        // Compressed secp256k1 point: 02/03 prefix + 32 bytes = 66 hex chars
        assert_eq!(hex.len(), 66);
        assert!(hex.starts_with("02") || hex.starts_with("03"));
    }
}
