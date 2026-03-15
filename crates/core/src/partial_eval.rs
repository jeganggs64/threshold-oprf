//! Partial OPRF evaluation performed by each node.
//!
//! Each node computes: E_i = k_i * B
//! where k_i is their key share and B is the blinded point from the client.
//!
//! Includes a DLEQ proof so the coordinator can verify the node used the
//! correct key share without learning the share itself.

use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

use crate::types::{DLEQProof, NodeId, PartialEvaluation, TOPRFError};
use crate::{hex_to_point, hex_to_scalar_unrestricted, point_to_hex, scalar_to_hex};

/// Compute a partial OPRF evaluation.
///
/// Given a node's key share `k_i` and a blinded point `B`, computes:
///   E_i = k_i * B
///
/// Also produces a DLEQ proof that log_G(V_i) == log_B(E_i),
/// where V_i = k_i * G is the node's verification share.
pub fn partial_evaluate(
    node_id: NodeId,
    key_share: &Scalar,
    blinded_point: &ProjectivePoint,
) -> Result<PartialEvaluation, TOPRFError> {
    if node_id == 0 {
        return Err(TOPRFError::InvalidInput("node_id must be nonzero".into()));
    }

    use k256::elliptic_curve::Group;
    if bool::from(blinded_point.is_identity()) {
        return Err(TOPRFError::InvalidInput(
            "blinded point is the identity element".into(),
        ));
    }

    // E_i = k_i * B
    let partial = blinded_point * key_share;

    // Verification share: V_i = k_i * G
    let verification_share = ProjectivePoint::mul_by_generator(key_share);

    // DLEQ proof: prove log_G(V_i) == log_B(E_i)
    let proof = dleq_prove(key_share, blinded_point, &partial, &verification_share);

    Ok(PartialEvaluation {
        node_id,
        partial_point: point_to_hex(&partial),
        dleq_proof: proof,
    })
}

/// Verify a partial evaluation's DLEQ proof.
///
/// Checks that the node used the correct key share (whose public commitment
/// is `verification_share`) to evaluate the blinded point.
pub fn verify_partial(
    partial: &PartialEvaluation,
    blinded_point: &ProjectivePoint,
    verification_share_hex: &str,
) -> Result<(), TOPRFError> {
    use k256::elliptic_curve::Group;
    if bool::from(blinded_point.is_identity()) {
        return Err(TOPRFError::InvalidInput(
            "blinded point is the identity element".into(),
        ));
    }

    let partial_point = hex_to_point(&partial.partial_point)?;
    let verification_share = hex_to_point(verification_share_hex)?;

    let challenge = hex_to_scalar_unrestricted(&partial.dleq_proof.challenge)?;
    let response = hex_to_scalar_unrestricted(&partial.dleq_proof.response)?;

    dleq_verify(
        blinded_point,
        &partial_point,
        &verification_share,
        &challenge,
        &response,
    )
    .map_err(|_| TOPRFError::DLEQVerificationFailed(partial.node_id))
}

// -- DLEQ proof internals --

/// Non-interactive DLEQ proof (Chaum-Pedersen protocol via Fiat-Shamir).
///
/// Proves: log_G(V) == log_B(E)  (i.e., V = k*G and E = k*B for the same k)
///
/// 1. Pick random t
/// 2. Compute A1 = t*G, A2 = t*B
/// 3. Challenge c = H(G, B, V, E, A1, A2)
/// 4. Response s = t - c*k
fn dleq_prove(
    secret: &Scalar,
    base_point: &ProjectivePoint,   // B
    evaluation: &ProjectivePoint,   // E = k*B
    public_share: &ProjectivePoint, // V = k*G
) -> DLEQProof {
    use zeroize::Zeroizing;
    let t = Zeroizing::new(Scalar::random(&mut OsRng));

    // A1 = t * G
    let a1 = ProjectivePoint::mul_by_generator(&*t);
    // A2 = t * B
    let a2 = base_point * &*t;

    let generator = ProjectivePoint::GENERATOR;

    let challenge = dleq_challenge(&generator, base_point, public_share, evaluation, &a1, &a2);

    // s = t - c * k (mod order)
    let response = *t - challenge * secret;

    DLEQProof {
        challenge: scalar_to_hex(&challenge),
        response: scalar_to_hex(&response),
    }
}

/// Verify a DLEQ proof.
///
/// 1. Recompute A1 = s*G + c*V, A2 = s*B + c*E
/// 2. Recompute challenge c' = H(G, B, V, E, A1, A2)
/// 3. Check c == c'
fn dleq_verify(
    base_point: &ProjectivePoint,   // B
    evaluation: &ProjectivePoint,   // E
    public_share: &ProjectivePoint, // V
    challenge: &Scalar,
    response: &Scalar,
) -> Result<(), ()> {
    let generator = ProjectivePoint::GENERATOR;

    // A1 = s*G + c*V
    let a1 = ProjectivePoint::mul_by_generator(response) + public_share * challenge;
    // A2 = s*B + c*E
    let a2 = base_point * response + evaluation * challenge;

    let expected_challenge =
        dleq_challenge(&generator, base_point, public_share, evaluation, &a1, &a2);

    use k256::elliptic_curve::subtle::ConstantTimeEq;
    if bool::from(challenge.ct_eq(&expected_challenge)) {
        Ok(())
    } else {
        Err(())
    }
}

/// Compute the DLEQ challenge scalar: c = H(G, B, V, E, A1, A2).
///
/// Uses SHA-512 (64 bytes) reduced mod the curve order to make bias
/// negligible (~2^{-256} for secp256k1's ~256-bit order).
fn dleq_challenge(
    generator: &ProjectivePoint,
    base_point: &ProjectivePoint,
    public_share: &ProjectivePoint,
    evaluation: &ProjectivePoint,
    a1: &ProjectivePoint,
    a2: &ProjectivePoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"TOPRF-DLEQ-secp256k1-v1");
    hasher.update(generator.to_bytes());
    hasher.update(base_point.to_bytes());
    hasher.update(public_share.to_bytes());
    hasher.update(evaluation.to_bytes());
    hasher.update(a1.to_bytes());
    hasher.update(a2.to_bytes());
    let hash = hasher.finalize();

    // Wide reduction: 512 bits → ~256-bit scalar, bias is ~2^{-256}
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    scalar_from_wide_bytes(&bytes)
}

/// Convert 64 bytes to a Scalar by wide reduction modulo the curve order.
///
/// Using a 512-bit intermediate for a ~256-bit modulus makes the
/// statistical bias negligible (~2^{-256}).
fn scalar_from_wide_bytes(bytes: &[u8; 64]) -> Scalar {
    use k256::elliptic_curve::ops::Reduce;
    let uint = crypto_bigint::U512::from_be_slice(bytes);
    Scalar::reduce(uint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;

    #[test]
    fn test_partial_evaluation() {
        let key_share = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));

        let partial = partial_evaluate(1, &key_share, &blinded_point).unwrap();
        let expected = blinded_point * key_share;
        let partial_point = hex_to_point(&partial.partial_point).unwrap();

        assert_eq!(point_to_hex(&partial_point), point_to_hex(&expected));
    }

    #[test]
    fn test_dleq_proof_valid() {
        let key_share = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let verification_share = ProjectivePoint::mul_by_generator(&key_share);

        let partial = partial_evaluate(1, &key_share, &blinded_point).unwrap();
        let result = verify_partial(&partial, &blinded_point, &point_to_hex(&verification_share));
        assert!(result.is_ok());
    }

    #[test]
    fn test_dleq_proof_wrong_share_fails() {
        let key_share = Scalar::random(&mut OsRng);
        let wrong_share = Scalar::random(&mut OsRng);
        let blinded_point = ProjectivePoint::mul_by_generator(&Scalar::random(&mut OsRng));
        let wrong_verification = ProjectivePoint::mul_by_generator(&wrong_share);

        let partial = partial_evaluate(1, &key_share, &blinded_point).unwrap();
        let result = verify_partial(&partial, &blinded_point, &point_to_hex(&wrong_verification));
        assert!(result.is_err());
    }
}
