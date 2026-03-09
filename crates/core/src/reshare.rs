//! Resharing protocol for migrating key shares to new nodes without
//! reconstructing the secret.
//!
//! Any quorum of existing nodes (≥ threshold) can jointly produce new
//! shares for a new set of nodes. The original secret is never reconstructed.
//!
//! Protocol (for 2-of-3 → new 2-of-3):
//!
//! 1. Each participating node i computes λ_i for the participating subset.
//! 2. Each node i generates a random degree-(t'-1) polynomial f_i(x)
//!    where f_i(0) = λ_i * k_i (their weighted share).
//! 3. Each node i sends f_i(j') to each new node j'.
//! 4. New node j' sums: k'_j' = Σ f_i(j')
//! 5. The new shares are valid t'-of-n' Shamir shares of the same secret.

use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::subtle::ConstantTimeEq;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar, U256};
use rand::rngs::OsRng;

use zeroize::Zeroize;

use crate::combine::lagrange_coefficient;
use crate::types::{NodeId, NodeKeyShare, TOPRFError};
use crate::{hex_to_point, point_to_hex, scalar_to_hex};

/// A node's contribution to the resharing protocol.
///
/// Contains the sub-shares (polynomial evaluations) this node sends to
/// each new node.
#[derive(Clone)]
pub struct ReshareContribution {
    /// The contributing node's ID.
    pub from_node_id: NodeId,
    /// Sub-shares for each new node: (new_node_id, sub_share_scalar).
    pub sub_shares: Vec<(NodeId, Scalar)>,
    /// Commitments to the polynomial coefficients (for verification).
    pub commitments: Vec<ProjectivePoint>,
}

impl std::fmt::Debug for ReshareContribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReshareContribution")
            .field("commitments", &self.commitments)
            .field("sub_shares", &format!("<{} shares redacted>", self.sub_shares.len()))
            .finish()
    }
}

impl Drop for ReshareContribution {
    fn drop(&mut self) {
        for (_, scalar) in &mut self.sub_shares {
            scalar.zeroize();
        }
    }
}

/// Generate this node's contribution to the resharing protocol.
///
/// Called by each participating node. The node needs:
/// - Its key share scalar
/// - The set of participating node IDs (to compute Lagrange coefficients)
/// - The IDs of the new nodes that will receive shares
/// - The new threshold
pub fn generate_reshare_contribution(
    node_id: NodeId,
    key_share: &Scalar,
    participant_ids: &[NodeId],
    new_node_ids: &[NodeId],
    new_threshold: u16,
) -> Result<ReshareContribution, TOPRFError> {
    if new_threshold < 2 {
        return Err(TOPRFError::ReshareError(
            "new threshold must be at least 2".into(),
        ));
    }
    if new_threshold as usize > new_node_ids.len() {
        return Err(TOPRFError::InvalidInput(
            "new_threshold must be <= number of new nodes".into(),
        ));
    }

    // Validate no zero IDs in participant_ids or new_node_ids
    if node_id == 0 || participant_ids.iter().any(|&id| id == 0) {
        return Err(TOPRFError::InvalidInput("node_id must be nonzero".into()));
    }
    if new_node_ids.iter().any(|&id| id == 0) {
        return Err(TOPRFError::InvalidInput("new_node_ids must all be nonzero".into()));
    }
    if !participant_ids.contains(&node_id) {
        return Err(TOPRFError::InvalidInput("node_id must be in participant_ids".into()));
    }
    // Check for duplicate participant_ids
    let mut seen_participants = std::collections::HashSet::new();
    for &id in participant_ids {
        if !seen_participants.insert(id) {
            return Err(TOPRFError::InvalidInput(format!("duplicate participant_id: {}", id)));
        }
    }
    // Check for duplicate new_node_ids
    let mut seen = std::collections::HashSet::new();
    for &id in new_node_ids {
        if !seen.insert(id) {
            return Err(TOPRFError::InvalidInput(format!("duplicate new_node_id: {}", id)));
        }
    }

    // Compute this node's Lagrange coefficient for the participating subset
    let lambda = lagrange_coefficient(node_id, participant_ids)?;

    // The weighted share: λ_i * k_i
    let weighted_share = lambda * key_share;

    // Generate a random polynomial of degree (new_threshold - 1)
    // where f(0) = weighted_share
    let degree = (new_threshold - 1) as usize;
    let mut coefficients = Vec::with_capacity(degree + 1);
    coefficients.push(weighted_share); // a_0 = λ_i * k_i

    for _ in 0..degree {
        coefficients.push(Scalar::random(&mut OsRng));
    }

    // Compute commitments: C_j = a_j * G (Feldman VSS)
    let commitments: Vec<ProjectivePoint> = coefficients
        .iter()
        .map(|c| ProjectivePoint::mul_by_generator(c))
        .collect();

    // Evaluate the polynomial at each new node's ID
    let sub_shares: Vec<(NodeId, Scalar)> = new_node_ids
        .iter()
        .map(|&new_id| {
            let x = scalar_from_u16(new_id);
            let value = evaluate_polynomial(&coefficients, &x);
            (new_id, value)
        })
        .collect();

    // Zeroize secret coefficients before returning
    for coeff in &mut coefficients {
        coeff.zeroize();
    }

    Ok(ReshareContribution {
        from_node_id: node_id,
        sub_shares,
        commitments,
    })
}

/// Combine reshare contributions to produce a new key share for this node.
///
/// Called by each new node after receiving contributions from the
/// participating quorum.
/// `min_contributions` is the old threshold — the minimum number of old nodes
/// that must participate in resharing.
pub fn combine_reshare_contributions(
    new_node_id: NodeId,
    contributions: &[ReshareContribution],
    min_contributions: u16,
    new_threshold: u16,
    new_total_shares: u16,
    group_public_key: &str,
) -> Result<NodeKeyShare, TOPRFError> {
    if new_node_id == 0 {
        return Err(TOPRFError::InvalidInput("new_node_id must be nonzero".into()));
    }
    // Check for duplicate contributions from the same old node
    let mut seen_from = std::collections::HashSet::new();
    for contrib in contributions {
        if !seen_from.insert(contrib.from_node_id) {
            return Err(TOPRFError::InvalidInput(format!(
                "duplicate contribution from node {}", contrib.from_node_id
            )));
        }
    }

    if contributions.len() < min_contributions as usize {
        return Err(TOPRFError::ReshareError(format!(
            "need at least {} contributions, got {}",
            min_contributions,
            contributions.len()
        )));
    }

    // Verify each contribution's commitments (Feldman VSS verification)
    let x = scalar_from_u16(new_node_id);
    for contribution in contributions {
        let sub_share = contribution
            .sub_shares
            .iter()
            .find(|(id, _)| *id == new_node_id)
            .ok_or_else(|| {
                TOPRFError::ReshareError(format!(
                    "contribution from node {} missing sub-share for node {}",
                    contribution.from_node_id, new_node_id
                ))
            })?;

        // Verify: sub_share * G == Σ (x^j * C_j) for j = 0..degree
        let expected = ProjectivePoint::mul_by_generator(&sub_share.1);
        let mut computed = ProjectivePoint::IDENTITY;
        let mut x_pow = Scalar::ONE;
        for commitment in &contribution.commitments {
            computed = computed + (commitment * &x_pow);
            x_pow = x_pow * x;
        }

        if !bool::from(expected.ct_eq(&computed)) {
            return Err(TOPRFError::ReshareError(format!(
                "Feldman VSS verification failed for contribution from node {}",
                contribution.from_node_id
            )));
        }
    }

    // Verify sum of commitment constants matches group public key
    let expected_gpk = hex_to_point(group_public_key)?;
    let actual_gpk: ProjectivePoint = contributions
        .iter()
        .map(|c| c.commitments[0])
        .fold(ProjectivePoint::IDENTITY, |acc, c| acc + c);
    if !bool::from(expected_gpk.ct_eq(&actual_gpk)) {
        return Err(TOPRFError::ReshareError(
            "sum of commitment constants does not match group public key".into(),
        ));
    }

    // Sum all sub-shares for this node
    let mut new_share = Scalar::ZERO;
    for contribution in contributions {
        let sub_share = contribution
            .sub_shares
            .iter()
            .find(|(id, _)| *id == new_node_id)
            .unwrap();
        new_share = new_share + sub_share.1;
    }

    if bool::from(new_share.is_zero()) {
        return Err(TOPRFError::InvalidInput("resulting share is zero".into()));
    }

    // Compute verification share: V' = k' * G
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

/// Evaluate a polynomial at x: f(x) = Σ a_i * x^i
fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;

    for coeff in coefficients {
        result = result + coeff * &x_pow;
        x_pow = x_pow * x;
    }

    result
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
    fn test_reshare_2_of_3_to_2_of_3() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let expected = blinded_point * &secret;

        // Original split
        let keygen = split_key(&secret, 2, 3).unwrap();

        // Reshare using nodes 1 and 2 → new nodes 4, 5, 6
        let participant_ids: Vec<NodeId> = vec![
            keygen.shares[0].node_id,
            keygen.shares[1].node_id,
        ];
        let new_node_ids: Vec<NodeId> = vec![4, 5, 6];
        let new_threshold = 2u16;

        // Each participating node generates its contribution
        let contributions: Vec<ReshareContribution> = participant_ids
            .iter()
            .map(|&node_id| {
                let share = keygen.shares.iter().find(|s| s.node_id == node_id).unwrap();
                let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                generate_reshare_contribution(
                    node_id,
                    &scalar,
                    &participant_ids,
                    &new_node_ids,
                    new_threshold,
                )
                .unwrap()
            })
            .collect();

        // Each new node combines the contributions to get their share
        let new_shares: Vec<NodeKeyShare> = new_node_ids
            .iter()
            .map(|&new_id| {
                combine_reshare_contributions(
                    new_id,
                    &contributions,
                    2, // old threshold (min contributors)
                    new_threshold,
                    3,
                    &keygen.group_public_key,
                )
                .unwrap()
            })
            .collect();

        // Verify: any 2 of the new 3 shares should produce the same OPRF output
        let new_vs: Vec<(NodeId, String)> = new_shares
            .iter()
            .map(|s| (s.node_id, s.verification_share.clone()))
            .collect();

        let subsets: Vec<Vec<usize>> = vec![vec![0, 1], vec![0, 2], vec![1, 2]];
        for subset in subsets {
            let partials: Vec<_> = subset
                .iter()
                .map(|&i| {
                    let share = &new_shares[i];
                    let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                    partial_evaluate(share.node_id, &scalar, &blinded_point).unwrap()
                })
                .collect();

            let combined = combine_partials(&partials, &blinded_point, &new_vs, 2).unwrap();
            assert_eq!(
                crate::point_to_hex(&combined),
                crate::point_to_hex(&expected),
                "reshared subset {:?} produced different result",
                subset,
            );
        }
    }

    #[test]
    fn test_reshare_2_of_3_to_3_of_5() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let expected = blinded_point * &secret;

        let keygen = split_key(&secret, 2, 3).unwrap();

        let participant_ids: Vec<NodeId> = vec![
            keygen.shares[0].node_id,
            keygen.shares[2].node_id,
        ];
        let new_node_ids: Vec<NodeId> = vec![10, 11, 12, 13, 14];
        let new_threshold = 3u16;

        let contributions: Vec<ReshareContribution> = participant_ids
            .iter()
            .map(|&node_id| {
                let share = keygen.shares.iter().find(|s| s.node_id == node_id).unwrap();
                let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                generate_reshare_contribution(
                    node_id,
                    &scalar,
                    &participant_ids,
                    &new_node_ids,
                    new_threshold,
                )
                .unwrap()
            })
            .collect();

        let new_shares: Vec<NodeKeyShare> = new_node_ids
            .iter()
            .map(|&new_id| {
                combine_reshare_contributions(
                    new_id,
                    &contributions,
                    2, // old threshold
                    new_threshold,
                    5,
                    &keygen.group_public_key,
                )
                .unwrap()
            })
            .collect();

        // Verify: any 3 of the new 5 shares should produce the same output
        let new_vs: Vec<(NodeId, String)> = new_shares
            .iter()
            .map(|s| (s.node_id, s.verification_share.clone()))
            .collect();

        // Test subset {10, 12, 14}
        let subset = vec![0usize, 2, 4];
        let partials: Vec<_> = subset
            .iter()
            .map(|&i| {
                let share = &new_shares[i];
                let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                partial_evaluate(share.node_id, &scalar, &blinded_point).unwrap()
            })
            .collect();

        let combined = combine_partials(&partials, &blinded_point, &new_vs, 3).unwrap();
        assert_eq!(
            crate::point_to_hex(&combined),
            crate::point_to_hex(&expected),
        );
    }

    #[test]
    fn test_feldman_vss_rejects_tampered_contribution() {
        let secret = Scalar::random(&mut OsRng);
        let keygen = split_key(&secret, 2, 3).unwrap();

        let participant_ids: Vec<NodeId> = vec![
            keygen.shares[0].node_id,
            keygen.shares[1].node_id,
        ];
        let new_node_ids: Vec<NodeId> = vec![4, 5, 6];

        let mut contributions: Vec<ReshareContribution> = participant_ids
            .iter()
            .map(|&node_id| {
                let share = keygen.shares.iter().find(|s| s.node_id == node_id).unwrap();
                let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                generate_reshare_contribution(node_id, &scalar, &participant_ids, &new_node_ids, 2)
                    .unwrap()
            })
            .collect();

        // Tamper with the first contribution's sub-share
        contributions[0].sub_shares[0].1 = Scalar::random(&mut OsRng);

        let result = combine_reshare_contributions(4, &contributions, 2, 2, 3, &keygen.group_public_key);
        assert!(result.is_err(), "should reject tampered contribution");
    }
}
