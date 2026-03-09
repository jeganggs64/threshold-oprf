//! HKDF key derivation + AES-256-GCM sealing/unsealing.
//!
//! Sealed blob binary format:
//! ```text
//! magic:       "SNPSEAL\0" (8 bytes)
//! version:     u32 LE      (4 bytes) = 1
//! measurement: [u8; 48]
//! policy:      u64 LE      (8 bytes)
//! salt:        [u8; 32]    (random HKDF salt)
//! nonce:       [u8; 12]    (random AES-GCM nonce)
//! ciphertext:  [u8; ...]   (encrypted data + 16-byte GCM auth tag)
//! ```
//! Total header: 112 bytes.
//! AAD covers the first 100 bytes (magic + version + measurement + policy + salt).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::SealError;

const MAGIC: &[u8; 8] = b"SNPSEAL\0";
const SEAL_VERSION: u32 = 1;
/// Total header size: magic(8) + version(4) + measurement(48) + policy(8) + salt(32) + nonce(12)
const HEADER_SIZE: usize = 112;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 32;
/// AAD covers everything before the nonce: magic(8) + version(4) + measurement(48) + policy(8) + salt(32) = 100
const AAD_SIZE: usize = 100;

/// Derive the 32-byte AES-256 sealing key from measurement, policy, and salt.
///
/// ```text
/// sealing_key = HKDF-SHA256(
///   ikm  = measurement (48 bytes) || policy (8 bytes LE),
///   salt = random 32-byte salt,
///   info = "ki"
/// )
/// ```
pub fn derive_sealing_key(measurement: &[u8; 48], policy: u64, salt: &[u8; SALT_SIZE]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Vec::with_capacity(56);
    ikm.extend_from_slice(measurement);
    ikm.extend_from_slice(&policy.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"ki", &mut key)
        .expect("HKDF expand should not fail for 32-byte output");
    Zeroizing::new(key)
}

/// Seal (encrypt) plaintext data bound to a specific measurement and policy.
///
/// Returns the full sealed blob: header (112 bytes) + ciphertext (includes
/// the 16-byte GCM authentication tag).
pub fn seal(
    plaintext: &[u8],
    measurement: &[u8; 48],
    policy: u64,
) -> Result<Vec<u8>, SealError> {
    // Generate a random 32-byte salt for HKDF
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let key_bytes = derive_sealing_key(measurement, policy, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&*key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Build the AAD header (everything except nonce and ciphertext)
    let mut header = Vec::with_capacity(AAD_SIZE);
    header.extend_from_slice(MAGIC);                        // 8 bytes
    header.extend_from_slice(&SEAL_VERSION.to_le_bytes());  // 4 bytes
    header.extend_from_slice(measurement);                  // 48 bytes
    header.extend_from_slice(&policy.to_le_bytes());        // 8 bytes
    header.extend_from_slice(&salt);                        // 32 bytes
    debug_assert_eq!(header.len(), AAD_SIZE);

    // Encrypt with AAD binding the header to the ciphertext
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|e| SealError::SealingFailed(format!("AES-GCM encryption failed: {e}")))?;

    // Assemble the sealed blob: header + nonce + ciphertext
    let mut blob = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    blob.extend_from_slice(&header);       // 100 bytes (AAD)
    blob.extend_from_slice(&nonce_bytes);  // 12 bytes
    blob.extend_from_slice(&ciphertext);   // variable

    debug_assert_eq!(blob.len(), HEADER_SIZE + ciphertext.len());
    Ok(blob)
}

/// Unseal (decrypt) a sealed blob using the provided measurement and policy.
///
/// The measurement and policy come from the attestation report, NOT from the
/// blob header. If the measurement doesn't match what was used to seal, the
/// derived key will differ and AES-GCM decryption will fail with an
/// authentication error.
pub fn unseal(
    sealed_blob: &[u8],
    measurement: &[u8; 48],
    policy: u64,
) -> Result<Vec<u8>, SealError> {
    if sealed_blob.len() < HEADER_SIZE {
        return Err(SealError::UnsealingFailed(format!(
            "sealed blob too short: {} bytes (minimum {})",
            sealed_blob.len(),
            HEADER_SIZE
        )));
    }

    // Validate magic
    if &sealed_blob[..8] != MAGIC {
        return Err(SealError::UnsealingFailed(
            "invalid sealed blob: bad magic bytes".into(),
        ));
    }

    // Validate version
    let version = u32::from_le_bytes(sealed_blob[8..12].try_into().unwrap());
    if version != SEAL_VERSION {
        return Err(SealError::UnsealingFailed(format!(
            "unsupported sealed blob version: {version} (expected {SEAL_VERSION})"
        )));
    }

    // Extract salt (at offset 68, length 32)
    let salt: [u8; SALT_SIZE] = sealed_blob[68..68 + SALT_SIZE].try_into().unwrap();

    // Extract AAD (first 100 bytes: magic + version + measurement + policy + salt)
    let aad = &sealed_blob[..AAD_SIZE];

    // Extract nonce (at offset 100, length 12)
    let nonce_bytes: [u8; NONCE_SIZE] = sealed_blob[AAD_SIZE..AAD_SIZE + NONCE_SIZE].try_into().unwrap();

    // Ciphertext is everything after the header
    let ciphertext = &sealed_blob[HEADER_SIZE..];
    if ciphertext.is_empty() {
        return Err(SealError::UnsealingFailed(
            "sealed blob has no ciphertext".into(),
        ));
    }

    // Derive the key from the attestation measurement/policy and stored salt
    let key_bytes = derive_sealing_key(measurement, policy, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&*key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SealError::UnsealingFailed(
            "AES-GCM decryption failed — measurement or policy mismatch, or data corrupted".into(),
        ))?;

    Ok(plaintext)
}

/// Parse a sealed blob header to extract the measurement, policy, and salt
/// it was sealed for.
///
/// This is for display/logging only — the actual unseal uses the attestation
/// measurement, not the one stored in the header.
pub fn parse_sealed_header(blob: &[u8]) -> Result<([u8; 48], u64), SealError> {
    if blob.len() < HEADER_SIZE {
        return Err(SealError::UnsealingFailed(format!(
            "sealed blob too short to parse header: {} bytes (minimum {})",
            blob.len(),
            HEADER_SIZE
        )));
    }

    if &blob[..8] != MAGIC {
        return Err(SealError::UnsealingFailed(
            "invalid sealed blob: bad magic bytes".into(),
        ));
    }

    let measurement: [u8; 48] = blob[12..60].try_into().unwrap();
    let policy = u64::from_le_bytes(blob[60..68].try_into().unwrap());

    Ok((measurement, policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_measurement() -> [u8; 48] {
        let mut m = [0u8; 48];
        for (i, byte) in m.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7);
        }
        m
    }

    fn different_measurement() -> [u8; 48] {
        let mut m = [0u8; 48];
        for (i, byte) in m.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(13);
        }
        m
    }

    #[test]
    fn test_seal_unseal_round_trip() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let plaintext = b"this is the secret key share data";

        let sealed = seal(plaintext, &measurement, policy).unwrap();
        assert!(sealed.len() > HEADER_SIZE);
        assert_eq!(&sealed[..8], MAGIC);

        let recovered = unseal(&sealed, &measurement, policy).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_wrong_measurement_fails() {
        let measurement = test_measurement();
        let wrong_measurement = different_measurement();
        let policy = 0x30000u64;
        let plaintext = b"secret data";

        let sealed = seal(plaintext, &measurement, policy).unwrap();
        let result = unseal(&sealed, &wrong_measurement, policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_wrong_policy_fails() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let wrong_policy = 0x40000u64;
        let plaintext = b"secret data";

        let sealed = seal(plaintext, &measurement, policy).unwrap();
        let result = unseal(&sealed, &measurement, wrong_policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_corrupt_ciphertext_fails() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let plaintext = b"secret data";

        let mut sealed = seal(plaintext, &measurement, policy).unwrap();
        // Corrupt a byte in the ciphertext area
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;

        let result = unseal(&sealed, &measurement, policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_corrupt_header_fails() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let plaintext = b"secret data";

        let mut sealed = seal(plaintext, &measurement, policy).unwrap();
        // Corrupt a byte in the AAD header area (e.g., the measurement)
        sealed[20] ^= 0xFF;

        // Decryption should fail because the AAD doesn't match
        let result = unseal(&sealed, &measurement, policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_invalid_magic_fails() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let plaintext = b"secret data";

        let mut sealed = seal(plaintext, &measurement, policy).unwrap();
        // Corrupt the magic bytes
        sealed[0] = b'X';

        let result = unseal(&sealed, &measurement, policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_derive_key_deterministic_with_same_salt() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let salt = [0xAB; 32];

        let key1 = derive_sealing_key(&measurement, policy, &salt);
        let key2 = derive_sealing_key(&measurement, policy, &salt);
        assert_eq!(*key1, *key2);

        // Different measurement should produce a different key
        let key3 = derive_sealing_key(&different_measurement(), policy, &salt);
        assert_ne!(*key1, *key3);
    }

    #[test]
    fn test_different_salt_produces_different_key() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let salt1 = [0xAA; 32];
        let salt2 = [0xBB; 32];

        let key1 = derive_sealing_key(&measurement, policy, &salt1);
        let key2 = derive_sealing_key(&measurement, policy, &salt2);
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_parse_sealed_header() {
        let measurement = test_measurement();
        let policy = 0x30000u64;
        let plaintext = b"data";

        let sealed = seal(plaintext, &measurement, policy).unwrap();
        let (parsed_measurement, parsed_policy) = parse_sealed_header(&sealed).unwrap();
        assert_eq!(parsed_measurement, measurement);
        assert_eq!(parsed_policy, policy);
    }

    #[test]
    fn test_blob_too_short() {
        let result = unseal(&[0u8; 10], &test_measurement(), 0);
        assert!(result.is_err());
    }
}
