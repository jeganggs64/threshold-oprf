//! Shamir secret sharing via FROST for secp256k1 scalars.
//!
//! Uses `frost-secp256k1::keys::split` to split an existing OPRF secret key
//! into threshold shares, and provides conversion to/from raw k256 types.

use frost::keys::IdentifierList;
use frost_secp256k1 as frost;
use k256::Scalar;
use rand::rngs::OsRng;

use crate::types::{KeyGenResult, NodeKeyShare, TOPRFError};

/// Split an existing OPRF secret scalar into `total_shares` Shamir shares
/// with a threshold of `threshold`.
///
/// This is the one-time ceremony operation. After this, the original scalar
/// should be destroyed.
pub fn split_key(
    secret_scalar: &Scalar,
    threshold: u16,
    total_shares: u16,
) -> Result<KeyGenResult, TOPRFError> {
    if threshold < 2 {
        return Err(TOPRFError::InvalidInput("threshold must be >= 2".into()));
    }
    if total_shares < threshold {
        return Err(TOPRFError::InvalidInput(
            "total_shares must be >= threshold".into(),
        ));
    }

    // Convert k256::Scalar to FROST's SigningKey
    let scalar_bytes: k256::FieldBytes = secret_scalar.into();
    let signing_key = frost::SigningKey::deserialize(&scalar_bytes[..])
        .map_err(|e| TOPRFError::Frost(format!("failed to create SigningKey: {e}")))?;

    // Split using FROST's trusted dealer
    let (secret_shares, public_key_package) = frost::keys::split(
        &signing_key,
        total_shares,
        threshold,
        IdentifierList::Default,
        &mut OsRng,
    )
    .map_err(|e| TOPRFError::Frost(format!("split failed: {e}")))?;

    // Extract group public key
    let group_verifying_key = public_key_package.verifying_key();
    let group_pk_bytes = group_verifying_key
        .serialize()
        .map_err(|e| TOPRFError::Frost(format!("serialize group key: {e}")))?;
    let group_pk_hex = hex::encode(&group_pk_bytes);

    // Convert each share to our serializable format
    let mut shares = Vec::with_capacity(total_shares as usize);

    for (identifier, secret_share) in &secret_shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share.clone())
            .map_err(|e| TOPRFError::Frost(format!("KeyPackage conversion failed: {e}")))?;

        let signing_share = key_package.signing_share();
        let verifying_share = key_package.verifying_share();

        let share_bytes = signing_share.serialize();
        let verify_bytes = verifying_share
            .serialize()
            .map_err(|e| TOPRFError::Frost(format!("serialize verifying share: {e}")))?;

        // Extract node_id from FROST Identifier (1-indexed)
        let id_bytes = identifier.serialize();
        // The identifier is serialized as a scalar; for default list it's 1, 2, 3, ...
        // Extract the last byte for the node ID (works for small IDs)
        let node_id = if id_bytes.len() >= 2 {
            u16::from_be_bytes([id_bytes[id_bytes.len() - 2], id_bytes[id_bytes.len() - 1]])
        } else {
            id_bytes[id_bytes.len() - 1] as u16
        };

        shares.push(NodeKeyShare {
            node_id,
            secret_share: hex::encode(&share_bytes),
            verification_share: hex::encode(&verify_bytes),
            group_public_key: group_pk_hex.clone(),
            threshold,
            total_shares,
        });
    }

    // Sort by node_id for deterministic output
    shares.sort_by_key(|s| s.node_id);

    Ok(KeyGenResult {
        group_public_key: group_pk_hex,
        shares,
        threshold,
        total_shares,
    })
}

/// Reconstruct the original secret from t-of-n shares (TESTING ONLY).
///
/// This should NEVER be used in production — the whole point of threshold
/// OPRF is that the key is never reconstructed.
#[cfg(test)]
pub fn reconstruct_secret(shares: &[NodeKeyShare]) -> Result<Scalar, TOPRFError> {
    use crate::hex_to_scalar;

    // reconstruct() expects &[KeyPackage] — convert our shares
    // We re-split the original and use FROST's reconstruct for verification.
    // For a simpler approach, just do Lagrange interpolation directly on our scalars.
    let node_ids: Vec<u16> = shares.iter().map(|s| s.node_id).collect();
    let mut secret = Scalar::ZERO;
    for share in shares {
        let scalar = hex_to_scalar(&share.secret_share)?;
        let lambda = crate::combine::lagrange_coefficient(share.node_id, &node_ids)?;
        secret += lambda * scalar;
    }
    Ok(secret)
}

/// Extract a k256::Scalar from a NodeKeyShare's secret_share hex.
pub fn share_to_scalar(share: &NodeKeyShare) -> Result<Scalar, TOPRFError> {
    crate::hex_to_scalar(&share.secret_share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;
    use rand::rngs::OsRng;

    #[test]
    fn test_split_2_of_3() {
        let secret = Scalar::random(&mut OsRng);
        let result = split_key(&secret, 2, 3).unwrap();

        assert_eq!(result.shares.len(), 3);
        assert_eq!(result.threshold, 2);
        assert_eq!(result.total_shares, 3);

        // All shares should have different secret values
        let s1 = &result.shares[0].secret_share;
        let s2 = &result.shares[1].secret_share;
        let s3 = &result.shares[2].secret_share;
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_ne!(s1, s3);

        // All shares should reference the same group public key
        assert_eq!(
            result.shares[0].group_public_key,
            result.shares[1].group_public_key
        );
        assert_eq!(
            result.shares[1].group_public_key,
            result.shares[2].group_public_key
        );
    }

    #[test]
    fn test_split_3_of_5() {
        let secret = Scalar::random(&mut OsRng);
        let result = split_key(&secret, 3, 5).unwrap();
        assert_eq!(result.shares.len(), 5);
        assert_eq!(result.threshold, 3);
    }
}
