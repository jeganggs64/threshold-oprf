//! Single-node share recovery protocol.
//!
//! Replaces one node at a time while all other nodes keep their existing
//! shares. The new share lies on the SAME polynomial as the existing shares.
//!
//! Protocol:
//!
//! 1. A quorum of donor nodes (≥ threshold) each compute a recovery
//!    contribution: `s_i = L_i(new_node_id) * k_i`, where L_i is the
//!    Lagrange basis polynomial evaluated at the new node's ID.
//!
//! 2. The new node sums the contributions:
//!    `k_new = Σ s_i = Σ L_i(new_node_id) * k_i = p(new_node_id)`
//!
//! 3. Verification: each sub-share is verified against the donor's
//!    verification share: `g^{s_i} == V_i^{L_i(new_node_id)}`.
//!    The combined result is verified against the group public key:
//!    `GPK == ∏ V_i^{L_i(0)}`.

use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::subtle::ConstantTimeEq;
use k256::{ProjectivePoint, Scalar, U256};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::combine::lagrange_coefficient;
use crate::types::{NodeId, NodeKeyShare, TOPRFError};
use crate::{hex_to_point, hex_to_scalar, point_to_hex, scalar_to_hex};

/// Serializable recovery contribution sent from donor to new node.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableReshareContribution {
    /// The donor node's ID.
    pub from_node_id: NodeId,
    /// The target new node's ID.
    pub new_node_id: NodeId,
    /// The sub-share data — either plaintext hex (64 chars) or base64 ECIES
    /// ciphertext, depending on `encrypted`.
    pub sub_share_data: String,
    /// Whether `sub_share_data` is ECIES-encrypted.
    pub encrypted: bool,
    /// The donor's verification share (compressed point hex).
    pub verification_share: String,
}

impl std::fmt::Debug for SerializableReshareContribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerializableReshareContribution")
            .field("from_node_id", &self.from_node_id)
            .field("new_node_id", &self.new_node_id)
            .field("encrypted", &self.encrypted)
            .field("sub_share_data", &"<redacted>")
            .finish()
    }
}

/// Compute the Lagrange coefficient for `node_id` in the set
/// `participant_ids`, evaluated at an arbitrary point `eval_point`.
///
/// L_i(x) = ∏_{j∈S, j≠i} (x - x_j) / (x_i - x_j)
fn lagrange_coefficient_at(
    node_id: NodeId,
    participant_ids: &[NodeId],
    eval_point: NodeId,
) -> Result<Scalar, TOPRFError> {
    if node_id == 0 || participant_ids.contains(&0) {
        return Err(TOPRFError::InvalidInput("node_id must be nonzero".into()));
    }
    let xi = scalar_from_u16(node_id);
    let x = scalar_from_u16(eval_point);
    let mut coeff = Scalar::ONE;

    for &other_id in participant_ids {
        if other_id == node_id {
            continue;
        }
        let xj = scalar_from_u16(other_id);

        // numerator: x - xj
        let num = x - xj;
        // denominator: xi - xj
        let den = xi - xj;
        let den_inv = den.invert();
        if bool::from(den_inv.is_none()) {
            return Err(TOPRFError::InvalidInput(
                "duplicate node IDs cause zero denominator".into(),
            ));
        }
        coeff = coeff * num * den_inv.unwrap();
    }

    Ok(coeff)
}

/// Generate a recovery contribution for a new node.
///
/// Called by each donor node. Returns `L_i(new_node_id) * k_i` where
/// L_i is the Lagrange basis polynomial for this node evaluated at
/// the new node's ID.
pub fn generate_recovery_contribution(
    node_id: NodeId,
    key_share: &Scalar,
    participant_ids: &[NodeId],
    new_node_id: NodeId,
) -> Result<Scalar, TOPRFError> {
    if new_node_id == 0 {
        return Err(TOPRFError::InvalidInput(
            "new_node_id must be nonzero".into(),
        ));
    }
    if !participant_ids.contains(&node_id) {
        return Err(TOPRFError::InvalidInput(
            "node_id must be in participant_ids".into(),
        ));
    }
    if participant_ids.contains(&new_node_id) {
        return Err(TOPRFError::InvalidInput(
            "new_node_id must not be in participant_ids".into(),
        ));
    }

    let lambda = lagrange_coefficient_at(node_id, participant_ids, new_node_id)?;
    let mut sub_share = lambda * key_share;

    // Return a copy and zeroize the local
    let result = sub_share;
    sub_share.zeroize();
    Ok(result)
}

/// Decode a plaintext (dev-mode) sub-share from a serializable contribution.
pub fn decode_plaintext_sub_share(
    contribution: &SerializableReshareContribution,
) -> Result<Scalar, TOPRFError> {
    if contribution.encrypted {
        return Err(TOPRFError::InvalidInput(
            "contribution is encrypted — cannot decode as plaintext".into(),
        ));
    }
    hex_to_scalar(&contribution.sub_share_data)
}

/// Combine decoded recovery contributions into a new key share.
///
/// `decoded_contributions` is a list of `(from_node_id, sub_share_scalar,
/// verification_share_hex)` tuples. Each sub-share has already been
/// decrypted (or decoded from plaintext).
///
/// Verification steps:
/// 1. Each sub-share is verified: `g^{s_i} == V_i^{L_i(new_node_id)}`
/// 2. The group public key is verified: `GPK == ∏ V_i^{L_i(0)}`
pub fn combine_recovery_contributions(
    new_node_id: NodeId,
    decoded_contributions: &[(NodeId, Scalar, String)],
    participant_ids: &[NodeId],
    group_public_key: &str,
    new_threshold: u16,
    new_total_shares: u16,
) -> Result<NodeKeyShare, TOPRFError> {
    if new_node_id == 0 {
        return Err(TOPRFError::InvalidInput(
            "new_node_id must be nonzero".into(),
        ));
    }
    if decoded_contributions.is_empty() {
        return Err(TOPRFError::ReshareError("no contributions provided".into()));
    }

    // Check for duplicate donors
    let mut seen = std::collections::HashSet::new();
    for &(from_id, _, _) in decoded_contributions {
        if !seen.insert(from_id) {
            return Err(TOPRFError::InvalidInput(format!(
                "duplicate contribution from node {}",
                from_id
            )));
        }
    }

    // Verify each sub-share against donor's verification share
    for &(from_id, ref sub_share, ref vs_hex) in decoded_contributions {
        let lambda = lagrange_coefficient_at(from_id, participant_ids, new_node_id)?;
        let vs_point = hex_to_point(vs_hex)?;

        // Expected: V_i^{L_i(new_node_id)}
        let expected = vs_point * lambda;
        // Actual: g^{s_i}
        let actual = ProjectivePoint::mul_by_generator(sub_share);

        if !bool::from(expected.ct_eq(&actual)) {
            return Err(TOPRFError::ReshareError(format!(
                "sub-share verification failed for contribution from node {}",
                from_id
            )));
        }
    }

    // Verify group public key: GPK == ∏ V_i^{L_i(0)}
    let expected_gpk = hex_to_point(group_public_key)?;
    let mut reconstructed_gpk = ProjectivePoint::IDENTITY;
    for &(from_id, _, ref vs_hex) in decoded_contributions {
        let lambda_0 = lagrange_coefficient(from_id, participant_ids)?;
        let vs_point = hex_to_point(vs_hex)?;
        reconstructed_gpk += vs_point * lambda_0;
    }
    if !bool::from(expected_gpk.ct_eq(&reconstructed_gpk)) {
        return Err(TOPRFError::ReshareError(
            "reconstructed GPK does not match provided group_public_key".into(),
        ));
    }

    // Sum sub-shares to get the new key share
    let mut new_share = Scalar::ZERO;
    for (_, sub_share, _) in decoded_contributions {
        new_share += sub_share;
    }

    if bool::from(new_share.is_zero()) {
        return Err(TOPRFError::InvalidInput("resulting share is zero".into()));
    }

    // Compute verification share: V_new = g^{k_new}
    let verification_share = ProjectivePoint::mul_by_generator(&new_share);

    Ok(NodeKeyShare {
        node_id: new_node_id,
        secret_share: scalar_to_hex(&new_share),
        verification_share: point_to_hex(&verification_share),
        group_public_key: group_public_key.to_string(),
        threshold: new_threshold,
        total_shares: new_total_shares,
    })
}

fn scalar_from_u16(id: u16) -> Scalar {
    let uint = U256::from_u32(id as u32);
    Scalar::reduce(uint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combine::combine_partials;
    use crate::partial_eval::partial_evaluate;
    use crate::shamir::split_key;
    use k256::elliptic_curve::ops::MulByGenerator;
    use k256::elliptic_curve::Field;
    use rand::rngs::OsRng;

    #[test]
    fn test_single_node_recovery_2_of_3() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let expected = blinded_point * secret;

        // Original split
        let keygen = split_key(&secret, 2, 3).unwrap();

        // Replace node 2: donors are nodes 1 and 3, new node gets ID 2
        let replaced_node_id: NodeId = keygen.shares[1].node_id;
        let participant_ids: Vec<NodeId> = vec![keygen.shares[0].node_id, keygen.shares[2].node_id];

        // Each donor generates its recovery contribution
        let mut decoded: Vec<(NodeId, Scalar, String)> = Vec::new();
        for &donor_id in &participant_ids {
            let share = keygen
                .shares
                .iter()
                .find(|s| s.node_id == donor_id)
                .unwrap();
            let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
            let sub_share = generate_recovery_contribution(
                donor_id,
                &scalar,
                &participant_ids,
                replaced_node_id,
            )
            .unwrap();
            decoded.push((donor_id, sub_share, share.verification_share.clone()));
        }

        // New node combines contributions
        let new_share = combine_recovery_contributions(
            replaced_node_id,
            &decoded,
            &participant_ids,
            &keygen.group_public_key,
            2,
            3,
        )
        .unwrap();

        // The new share should be the same as the original share for that node_id
        // (because it's on the same polynomial)
        assert_eq!(
            new_share.secret_share, keygen.shares[1].secret_share,
            "recovered share should match original"
        );

        // Verify OPRF still works: use the recovered share + another original share
        let vs: Vec<(NodeId, String)> = vec![
            (
                keygen.shares[0].node_id,
                keygen.shares[0].verification_share.clone(),
            ),
            (new_share.node_id, new_share.verification_share.clone()),
        ];

        let partials: Vec<_> = vec![
            {
                let s = crate::hex_to_scalar(&keygen.shares[0].secret_share).unwrap();
                partial_evaluate(keygen.shares[0].node_id, &s, &blinded_point).unwrap()
            },
            {
                let s = crate::hex_to_scalar(&new_share.secret_share).unwrap();
                partial_evaluate(new_share.node_id, &s, &blinded_point).unwrap()
            },
        ];

        let combined = combine_partials(&partials, &blinded_point, &vs, 2).unwrap();
        assert_eq!(
            crate::point_to_hex(&combined),
            crate::point_to_hex(&expected),
            "OPRF with recovered share should match"
        );
    }

    #[test]
    fn test_recovery_new_node_id() {
        // Replace node with a brand new ID (not reusing old ID)
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let expected = blinded_point * secret;

        let keygen = split_key(&secret, 2, 3).unwrap();

        // Donors: nodes 1 and 2, new node gets ID 4
        let participant_ids: Vec<NodeId> = vec![keygen.shares[0].node_id, keygen.shares[1].node_id];
        let new_id: NodeId = 4;

        let mut decoded: Vec<(NodeId, Scalar, String)> = Vec::new();
        for &donor_id in &participant_ids {
            let share = keygen
                .shares
                .iter()
                .find(|s| s.node_id == donor_id)
                .unwrap();
            let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
            let sub_share =
                generate_recovery_contribution(donor_id, &scalar, &participant_ids, new_id)
                    .unwrap();
            decoded.push((donor_id, sub_share, share.verification_share.clone()));
        }

        let new_share = combine_recovery_contributions(
            new_id,
            &decoded,
            &participant_ids,
            &keygen.group_public_key,
            2,
            3,
        )
        .unwrap();

        // Verify OPRF works with new share + one donor
        let vs: Vec<(NodeId, String)> = vec![
            (
                keygen.shares[0].node_id,
                keygen.shares[0].verification_share.clone(),
            ),
            (new_share.node_id, new_share.verification_share.clone()),
        ];

        let partials: Vec<_> = vec![
            {
                let s = crate::hex_to_scalar(&keygen.shares[0].secret_share).unwrap();
                partial_evaluate(keygen.shares[0].node_id, &s, &blinded_point).unwrap()
            },
            {
                let s = crate::hex_to_scalar(&new_share.secret_share).unwrap();
                partial_evaluate(new_share.node_id, &s, &blinded_point).unwrap()
            },
        ];

        let combined = combine_partials(&partials, &blinded_point, &vs, 2).unwrap();
        assert_eq!(
            crate::point_to_hex(&combined),
            crate::point_to_hex(&expected),
        );
    }

    #[test]
    fn test_recovery_rejects_tampered_contribution() {
        let secret = Scalar::random(&mut OsRng);
        let keygen = split_key(&secret, 2, 3).unwrap();

        let participant_ids: Vec<NodeId> = vec![keygen.shares[0].node_id, keygen.shares[1].node_id];
        let new_id: NodeId = 4;

        let mut decoded: Vec<(NodeId, Scalar, String)> = Vec::new();
        for &donor_id in &participant_ids {
            let share = keygen
                .shares
                .iter()
                .find(|s| s.node_id == donor_id)
                .unwrap();
            let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
            let sub_share =
                generate_recovery_contribution(donor_id, &scalar, &participant_ids, new_id)
                    .unwrap();
            decoded.push((donor_id, sub_share, share.verification_share.clone()));
        }

        // Tamper with first contribution
        decoded[0].1 = Scalar::random(&mut OsRng);

        let result = combine_recovery_contributions(
            new_id,
            &decoded,
            &participant_ids,
            &keygen.group_public_key,
            2,
            3,
        );
        assert!(result.is_err(), "should reject tampered contribution");
    }

    #[test]
    fn test_decode_plaintext_sub_share() {
        let scalar = Scalar::random(&mut OsRng);
        let contribution = SerializableReshareContribution {
            from_node_id: 1,
            new_node_id: 4,
            sub_share_data: scalar_to_hex(&scalar),
            encrypted: false,
            verification_share: String::new(),
        };

        let decoded = decode_plaintext_sub_share(&contribution).unwrap();
        assert_eq!(scalar_to_hex(&decoded), scalar_to_hex(&scalar));

        // Should fail for encrypted contributions
        let encrypted = SerializableReshareContribution {
            encrypted: true,
            ..contribution
        };
        assert!(decode_plaintext_sub_share(&encrypted).is_err());
    }

    #[test]
    fn test_recovery_3_of_5() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let expected = blinded_point * secret;

        let keygen = split_key(&secret, 3, 5).unwrap();

        // Replace node 3 using donors {1, 2, 4}
        let participant_ids: Vec<NodeId> = vec![
            keygen.shares[0].node_id,
            keygen.shares[1].node_id,
            keygen.shares[3].node_id,
        ];
        let replaced_id = keygen.shares[2].node_id;

        let mut decoded: Vec<(NodeId, Scalar, String)> = Vec::new();
        for &donor_id in &participant_ids {
            let share = keygen
                .shares
                .iter()
                .find(|s| s.node_id == donor_id)
                .unwrap();
            let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
            let sub_share =
                generate_recovery_contribution(donor_id, &scalar, &participant_ids, replaced_id)
                    .unwrap();
            decoded.push((donor_id, sub_share, share.verification_share.clone()));
        }

        let new_share = combine_recovery_contributions(
            replaced_id,
            &decoded,
            &participant_ids,
            &keygen.group_public_key,
            3,
            5,
        )
        .unwrap();

        // Recovered share should match original
        assert_eq!(new_share.secret_share, keygen.shares[2].secret_share);

        // Verify OPRF with recovered share + two original shares
        let vs: Vec<(NodeId, String)> = vec![
            (
                keygen.shares[0].node_id,
                keygen.shares[0].verification_share.clone(),
            ),
            (
                keygen.shares[1].node_id,
                keygen.shares[1].verification_share.clone(),
            ),
            (new_share.node_id, new_share.verification_share.clone()),
        ];

        let partials: Vec<_> = vec![
            {
                let s = crate::hex_to_scalar(&keygen.shares[0].secret_share).unwrap();
                partial_evaluate(keygen.shares[0].node_id, &s, &blinded_point).unwrap()
            },
            {
                let s = crate::hex_to_scalar(&keygen.shares[1].secret_share).unwrap();
                partial_evaluate(keygen.shares[1].node_id, &s, &blinded_point).unwrap()
            },
            {
                let s = crate::hex_to_scalar(&new_share.secret_share).unwrap();
                partial_evaluate(new_share.node_id, &s, &blinded_point).unwrap()
            },
        ];

        let combined = combine_partials(&partials, &blinded_point, &vs, 3).unwrap();
        assert_eq!(
            crate::point_to_hex(&combined),
            crate::point_to_hex(&expected),
        );
    }
}
