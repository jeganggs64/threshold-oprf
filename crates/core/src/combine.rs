//! Lagrange interpolation for combining partial OPRF evaluations.
//!
//! Given partial evaluations E_i = k_i * B from a threshold quorum,
//! combines them into E = k * B using Lagrange coefficients:
//!
//!   E = Σ λ_i * E_i
//!
//! where λ_i = ∏_{j∈S, j≠i} j / (j - i)  evaluated at x=0.

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar, U256};

use crate::types::{NodeId, PartialEvaluation, TOPRFError};
use crate::hex_to_point;

/// Compute the Lagrange coefficient for node `node_id` given the set of
/// participating node IDs, evaluated at x=0.
///
/// λ_i = ∏_{j∈S, j≠i} (0 - j) / (i - j) = ∏_{j∈S, j≠i} j / (j - i)
///
/// Note: uses the "negated numerator" form, where we compute:
///   λ_i = ∏_{j∈S,j≠i} (-j) / (i-j) = ∏ j/(j-i)
///
/// All arithmetic is modulo the secp256k1 curve order.
pub fn lagrange_coefficient(node_id: NodeId, participant_ids: &[NodeId]) -> Result<Scalar, TOPRFError> {
    if node_id == 0 || participant_ids.iter().any(|&id| id == 0) {
        return Err(TOPRFError::InvalidInput("node_id must be nonzero".into()));
    }
    let xi = scalar_from_u16(node_id);
    let mut coeff = Scalar::ONE;

    for &other_id in participant_ids {
        if other_id == node_id {
            continue;
        }
        let xj = scalar_from_u16(other_id);

        // numerator: 0 - xj = -xj
        let num = -xj;
        // denominator: xi - xj
        let den = xi - xj;
        // den_inv = den^{-1} mod order
        let den_inv = den.invert();
        if bool::from(den_inv.is_none()) {
            return Err(TOPRFError::InvalidInput("duplicate node IDs cause zero denominator".into()));
        }

        coeff = coeff * num * den_inv.unwrap();
    }

    Ok(coeff)
}

/// Combine partial evaluations from a quorum of nodes into the final
/// OPRF evaluation point.
///
/// Verifies DLEQ proofs for each partial evaluation before combining.
pub fn combine_partials(
    partials: &[PartialEvaluation],
    blinded_point: &ProjectivePoint,
    verification_shares: &[(NodeId, String)], // (node_id, verification_share_hex)
    threshold: usize,
) -> Result<ProjectivePoint, TOPRFError> {
    // Validate no duplicate node IDs
    let mut seen_ids = std::collections::HashSet::new();
    for p in partials {
        if p.node_id == 0 {
            return Err(TOPRFError::InvalidInput("node_id must be nonzero".into()));
        }
        if !seen_ids.insert(p.node_id) {
            return Err(TOPRFError::InvalidInput(format!("duplicate node_id: {}", p.node_id)));
        }
    }

    if partials.len() < threshold {
        return Err(TOPRFError::InsufficientPartials {
            need: threshold,
            got: partials.len(),
        });
    }

    // Verify each partial evaluation's DLEQ proof
    for partial in partials {
        let vs = verification_shares
            .iter()
            .find(|(id, _)| *id == partial.node_id)
            .ok_or_else(|| {
                TOPRFError::DLEQVerificationFailed(partial.node_id)
            })?;

        crate::partial_eval::verify_partial(partial, blinded_point, &vs.1)?;
    }

    // Collect participant IDs
    let participant_ids: Vec<NodeId> = partials.iter().map(|p| p.node_id).collect();

    // Combine: E = Σ λ_i * E_i
    let mut result = ProjectivePoint::IDENTITY;

    for partial in partials {
        let lambda = lagrange_coefficient(partial.node_id, &participant_ids)?;
        let partial_point = hex_to_point(&partial.partial_point)?;
        result = result + (partial_point * lambda);
    }

    if bool::from(result.is_identity()) {
        return Err(TOPRFError::InvalidInput("combined result is identity point".into()));
    }

    Ok(result)
}

/// Convert a u16 node ID to a Scalar.
fn scalar_from_u16(id: u16) -> Scalar {
    let uint = U256::from_u32(id as u32);
    Scalar::reduce(uint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partial_eval::partial_evaluate;
    use crate::point_to_hex;
    use crate::shamir::split_key;
    use k256::elliptic_curve::ops::MulByGenerator;
    use k256::elliptic_curve::Field;
    use rand::rngs::OsRng;

    /// Helper: evaluate OPRF with a single (non-threshold) key for comparison.
    fn single_evaluate(secret: &Scalar, blinded_point: &ProjectivePoint) -> ProjectivePoint {
        blinded_point * secret
    }

    #[test]
    fn test_lagrange_coefficients_2_of_3() {
        // For nodes {1, 2}, the Lagrange coefficients at x=0 should be:
        // λ_1 = (0-2)/(1-2) = -2/-1 = 2
        // λ_2 = (0-1)/(2-1) = -1/1 = -1
        let ids = vec![1u16, 2u16];
        let l1 = lagrange_coefficient(1, &ids).unwrap();
        let l2 = lagrange_coefficient(2, &ids).unwrap();

        let two = Scalar::from(2u64);
        let neg_one = -Scalar::ONE;

        assert_eq!(l1, two);
        assert_eq!(l2, neg_one);
    }

    #[test]
    fn test_combine_2_of_3_matches_single_eval() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));

        // Expected result from single-server OPRF
        let expected = single_evaluate(&secret, &blinded_point);

        // Split into 2-of-3
        let keygen = split_key(&secret, 2, 3).unwrap();

        // Build verification shares list
        let vs: Vec<(NodeId, String)> = keygen
            .shares
            .iter()
            .map(|s| (s.node_id, s.verification_share.clone()))
            .collect();

        // Test all 3 possible 2-of-3 subsets
        let subsets: Vec<Vec<usize>> = vec![vec![0, 1], vec![0, 2], vec![1, 2]];

        for subset in subsets {
            let partials: Vec<PartialEvaluation> = subset
                .iter()
                .map(|&i| {
                    let share = &keygen.shares[i];
                    let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                    partial_evaluate(share.node_id, &scalar, &blinded_point).unwrap()
                })
                .collect();

            let combined = combine_partials(&partials, &blinded_point, &vs, 2).unwrap();

            assert_eq!(
                point_to_hex(&combined),
                point_to_hex(&expected),
                "subset {:?} produced different result",
                subset,
            );
        }
    }

    #[test]
    fn test_1_of_3_fails() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));

        let keygen = split_key(&secret, 2, 3).unwrap();
        let vs: Vec<(NodeId, String)> = keygen
            .shares
            .iter()
            .map(|s| (s.node_id, s.verification_share.clone()))
            .collect();

        let scalar = crate::hex_to_scalar(&keygen.shares[0].secret_share).unwrap();
        let partial = partial_evaluate(keygen.shares[0].node_id, &scalar, &blinded_point).unwrap();

        let result = combine_partials(&[partial], &blinded_point, &vs, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_3_of_5() {
        let secret = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let expected = single_evaluate(&secret, &blinded_point);

        let keygen = split_key(&secret, 3, 5).unwrap();
        let vs: Vec<(NodeId, String)> = keygen
            .shares
            .iter()
            .map(|s| (s.node_id, s.verification_share.clone()))
            .collect();

        // Use shares 0, 2, 4 (nodes 1, 3, 5)
        let subset = vec![0usize, 2, 4];
        let partials: Vec<PartialEvaluation> = subset
            .iter()
            .map(|&i| {
                let share = &keygen.shares[i];
                let scalar = crate::hex_to_scalar(&share.secret_share).unwrap();
                partial_evaluate(share.node_id, &scalar, &blinded_point).unwrap()
            })
            .collect();

        let combined = combine_partials(&partials, &blinded_point, &vs, 3).unwrap();
        assert_eq!(point_to_hex(&combined), point_to_hex(&expected));
    }

    /// Output deterministic test vectors for cross-language verification.
    /// Run with: cargo test -p toprf-core test_cross_lang_vectors -- --nocapture
    #[test]
    fn test_cross_lang_vectors() {
        use crate::hash_to_curve::hash_to_curve;

        // Use a deterministic input so we can verify in TypeScript
        let h = hash_to_curve("SG", "S1234567A").unwrap();
        let blinded_scalar = Scalar::from(42u64);
        let blinded_point = h * blinded_scalar;

        // Use a known secret
        let secret = Scalar::from(12345u64);
        let expected = &blinded_point * &secret;

        // Split into 2-of-3
        // Use a deterministic polynomial: f(x) = secret + coeff*x
        // coeff = 7
        let coeff = Scalar::from(7u64);
        // share_1 = secret + 7*1 = 12352
        // share_2 = secret + 7*2 = 12359
        // share_3 = secret + 7*3 = 12366
        let share1 = secret + coeff * Scalar::from(1u64);
        let share2 = secret + coeff * Scalar::from(2u64);
        let share3 = secret + coeff * Scalar::from(3u64);

        // Partial evaluations: E_i = share_i * B
        let e1 = &blinded_point * &share1;
        let e2 = &blinded_point * &share2;
        let e3 = &blinded_point * &share3;

        // Combine nodes {1, 2}
        let ids_12: Vec<u16> = vec![1, 2];
        let l1_12 = lagrange_coefficient(1, &ids_12).unwrap();
        let l2_12 = lagrange_coefficient(2, &ids_12).unwrap();
        let combined_12 = e1 * l1_12 + e2 * l2_12;
        assert_eq!(point_to_hex(&combined_12), point_to_hex(&expected), "nodes 1,2 mismatch");

        // Combine nodes {1, 3}
        let ids_13: Vec<u16> = vec![1, 3];
        let l1_13 = lagrange_coefficient(1, &ids_13).unwrap();
        let l3_13 = lagrange_coefficient(3, &ids_13).unwrap();
        let combined_13 = e1 * l1_13 + e3 * l3_13;
        assert_eq!(point_to_hex(&combined_13), point_to_hex(&expected), "nodes 1,3 mismatch");

        // Combine nodes {2, 3}
        let ids_23: Vec<u16> = vec![2, 3];
        let l2_23 = lagrange_coefficient(2, &ids_23).unwrap();
        let l3_23 = lagrange_coefficient(3, &ids_23).unwrap();
        let combined_23 = e2 * l2_23 + e3 * l3_23;
        assert_eq!(point_to_hex(&combined_23), point_to_hex(&expected), "nodes 2,3 mismatch");

        // Print test vectors for TypeScript verification
        println!("\n=== CROSS-LANGUAGE TEST VECTORS ===");
        println!("hash_to_curve(\"SG\", \"S1234567A\") = {}", point_to_hex(&h));
        println!("blinded_point (42 * H) = {}", point_to_hex(&blinded_point));
        println!("expected (secret * B) = {}", point_to_hex(&expected));
        println!("partial_1 (node 1) = {}", point_to_hex(&e1));
        println!("partial_2 (node 2) = {}", point_to_hex(&e2));
        println!("partial_3 (node 3) = {}", point_to_hex(&e3));
        println!("=== END VECTORS ===\n");
    }
}
