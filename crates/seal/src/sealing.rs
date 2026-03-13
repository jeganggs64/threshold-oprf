//! AES-256-GCM sealing/unsealing using hardware-derived keys (MSG_KEY_REQ).
//!
//! ## Sealed blob format
//! ```text
//! magic:        "SNPSEAL\0"  (8 bytes)
//! version:      u32 LE       (4 bytes) = 2
//! field_select: u64 LE       (8 bytes) — which fields were mixed into key derivation
//! nonce:        [u8; 12]     (12 bytes — random AES-GCM nonce)
//! ciphertext:   [u8; ...]    (encrypted data + 16-byte GCM auth tag)
//! ```
//! Total header: 32 bytes. AAD: first 20 bytes (magic + version + field_select).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::SealError;

const MAGIC: &[u8; 8] = b"SNPSEAL\0";
const NONCE_SIZE: usize = 12;

const V2_SEAL_VERSION: u32 = 2;
/// Total header size: magic(8) + version(4) + field_select(8) + nonce(12) = 32
const V2_HEADER_SIZE: usize = 32;
/// AAD covers: magic(8) + version(4) + field_select(8) = 20
const V2_AAD_SIZE: usize = 20;

/// Seal plaintext using a hardware-derived key from MSG_KEY_REQ.
///
/// The key is derived by the AMD Secure Processor from:
/// - The chip's unique root key (VCEK)
/// - The guest's MEASUREMENT (launch digest)
/// - The guest's TCB_VERSION (firmware/microcode versions)
///
/// The sealed blob can ONLY be decrypted on the SAME physical chip
/// running the SAME software stack.
pub fn seal_derived(
    plaintext: &[u8],
    derived_key: &[u8; 32],
    field_select: u64,
) -> Result<Vec<u8>, SealError> {
    let key = Key::<Aes256Gcm>::from_slice(derived_key);
    let cipher = Aes256Gcm::new(key);

    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Build the AAD header: magic + version + field_select
    let mut aad = Vec::with_capacity(V2_AAD_SIZE);
    aad.extend_from_slice(MAGIC); // 8 bytes
    aad.extend_from_slice(&V2_SEAL_VERSION.to_le_bytes()); // 4 bytes
    aad.extend_from_slice(&field_select.to_le_bytes()); // 8 bytes
    debug_assert_eq!(aad.len(), V2_AAD_SIZE);

    // Encrypt with AAD binding the header to the ciphertext
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| SealError::SealingFailed(format!("AES-GCM encryption failed: {e}")))?;

    // Assemble the sealed blob: aad(20) + nonce(12) + ciphertext
    let mut blob = Vec::with_capacity(V2_HEADER_SIZE + ciphertext.len());
    blob.extend_from_slice(&aad); // 20 bytes (AAD)
    blob.extend_from_slice(&nonce_bytes); // 12 bytes
    blob.extend_from_slice(&ciphertext); // variable

    debug_assert_eq!(blob.len(), V2_HEADER_SIZE + ciphertext.len());
    Ok(blob)
}

/// Unseal a sealed blob using a hardware-derived key.
///
/// The caller must provide the key from MSG_KEY_REQ. If the chip or
/// measurement differs from when the blob was sealed, the key will
/// differ and decryption will fail.
pub fn unseal_derived(sealed_blob: &[u8], derived_key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    if sealed_blob.len() < V2_HEADER_SIZE {
        return Err(SealError::UnsealingFailed(format!(
            "sealed blob too short: {} bytes (minimum {})",
            sealed_blob.len(),
            V2_HEADER_SIZE
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
    if version != V2_SEAL_VERSION {
        return Err(SealError::UnsealingFailed(format!(
            "unsupported sealed blob version {version} (expected {V2_SEAL_VERSION})"
        )));
    }

    // Extract AAD (first 20 bytes: magic + version + field_select)
    let aad = &sealed_blob[..V2_AAD_SIZE];

    // Extract nonce (bytes 20..32)
    let nonce_bytes: [u8; NONCE_SIZE] = sealed_blob[V2_AAD_SIZE..V2_AAD_SIZE + NONCE_SIZE]
        .try_into()
        .unwrap();

    // Ciphertext is everything after the header
    let ciphertext = &sealed_blob[V2_HEADER_SIZE..];
    if ciphertext.is_empty() {
        return Err(SealError::UnsealingFailed(
            "sealed blob has no ciphertext".into(),
        ));
    }

    let key = Key::<Aes256Gcm>::from_slice(derived_key);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            SealError::UnsealingFailed(
                "AES-GCM decryption failed — derived key mismatch or data corrupted".into(),
            )
        })?;

    Ok(plaintext)
}

/// Parse a sealed blob header to extract the field_select value.
///
/// This is for display/logging only — it tells you which guest fields
/// were mixed into the key derivation when the blob was sealed.
pub fn parse_v2_header(blob: &[u8]) -> Result<u64, SealError> {
    if blob.len() < V2_HEADER_SIZE {
        return Err(SealError::UnsealingFailed(format!(
            "sealed blob too short to parse header: {} bytes (minimum {})",
            blob.len(),
            V2_HEADER_SIZE
        )));
    }

    if &blob[..8] != MAGIC {
        return Err(SealError::UnsealingFailed(
            "invalid sealed blob: bad magic bytes".into(),
        ));
    }

    let version = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    if version != V2_SEAL_VERSION {
        return Err(SealError::UnsealingFailed(format!(
            "expected v2 header, got version {version}"
        )));
    }

    let field_select = u64::from_le_bytes(blob[12..20].try_into().unwrap());
    Ok(field_select)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_derived_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(11).wrapping_add(0x42);
        }
        k
    }

    fn different_derived_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(0xAA);
        }
        k
    }

    #[test]
    fn test_seal_unseal_derived_round_trip() {
        let key = test_derived_key();
        let field_select = 0x28u64; // MEASUREMENT | TCB_VERSION
        let plaintext = b"this is the secret key share data sealed with hardware key";

        let sealed = seal_derived(plaintext, &key, field_select).unwrap();
        assert!(sealed.len() > V2_HEADER_SIZE);
        assert_eq!(&sealed[..8], MAGIC);

        let recovered = unseal_derived(&sealed, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_derived_wrong_key_fails() {
        let key = test_derived_key();
        let wrong_key = different_derived_key();
        let field_select = 0x28u64;
        let plaintext = b"secret data";

        let sealed = seal_derived(plaintext, &key, field_select).unwrap();
        let result = unseal_derived(&sealed, &wrong_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_derived_corrupt_ciphertext_fails() {
        let key = test_derived_key();
        let field_select = 0x28u64;
        let plaintext = b"secret data";

        let mut sealed = seal_derived(plaintext, &key, field_select).unwrap();
        // Corrupt a byte in the ciphertext area
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;

        let result = unseal_derived(&sealed, &key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_derived_header_parsing() {
        let key = test_derived_key();
        let field_select = 0x28u64; // MEASUREMENT | TCB_VERSION
        let plaintext = b"data";

        let sealed = seal_derived(plaintext, &key, field_select).unwrap();

        // Check the version field
        let version = u32::from_le_bytes(sealed[8..12].try_into().unwrap());
        assert_eq!(version, 2);

        // Check field_select via parse_v2_header
        let parsed_field_select = parse_v2_header(&sealed).unwrap();
        assert_eq!(parsed_field_select, field_select);
    }

    #[test]
    fn test_non_v2_blob_rejected() {
        // A blob with version != 2 should be rejected by unseal_derived
        let derived_key = test_derived_key();

        // Construct a fake v1 blob (valid magic, version=1, then garbage)
        let mut fake_v1 = Vec::new();
        fake_v1.extend_from_slice(MAGIC);
        fake_v1.extend_from_slice(&1u32.to_le_bytes());
        fake_v1.extend_from_slice(&[0u8; 128]); // padding to make it large enough

        let result = unseal_derived(&fake_v1, &derived_key);
        assert!(result.is_err());
        match result.unwrap_err() {
            SealError::UnsealingFailed(msg) => {
                assert!(
                    msg.contains("unsupported sealed blob version"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected UnsealingFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_derived_corrupt_aad_fails() {
        let key = test_derived_key();
        let field_select = 0x28u64;
        let plaintext = b"secret data";

        let mut sealed = seal_derived(plaintext, &key, field_select).unwrap();
        // Corrupt a byte in the AAD area (field_select)
        sealed[15] ^= 0xFF;

        // Decryption should fail because the AAD doesn't match
        let result = unseal_derived(&sealed, &key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }

    #[test]
    fn test_blob_too_short() {
        let result = unseal_derived(&[0u8; 10], &test_derived_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_magic_fails() {
        let key = test_derived_key();
        let field_select = 0x28u64;
        let plaintext = b"data";

        let mut sealed = seal_derived(plaintext, &key, field_select).unwrap();
        // Corrupt the magic bytes
        sealed[0] = b'X';

        let result = unseal_derived(&sealed, &key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SealError::UnsealingFailed(_)));
    }
}
