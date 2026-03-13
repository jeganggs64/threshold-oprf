//! ECIES encryption/decryption using X25519.
//!
//! Scheme: X25519 ECDH → HKDF-SHA256 → AES-256-GCM.
//!
//! Wire format:
//!   `ephemeral_pubkey[32] || nonce[12] || ciphertext_with_tag[...]`
//!
//! Used during init-seal: the operator encrypts a key share to the node's
//! attested X25519 public key, and the node decrypts inside the enclave.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::SealError;

/// HKDF info string for key derivation.
const HKDF_INFO: &[u8] = b"toprf-ecies-aes256gcm";

/// Size of an X25519 public key.
const PUBKEY_LEN: usize = 32;

/// Size of an AES-256-GCM nonce.
const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` to the given X25519 `recipient_pubkey`.
///
/// Returns the wire-format ciphertext:
///   `ephemeral_pubkey[32] || nonce[12] || ciphertext_with_tag[...]`
pub fn encrypt(recipient_pubkey: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    // Generate ephemeral X25519 keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = PublicKey::from(&ephemeral_secret);

    // X25519 ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_pubkey);
    if !shared_secret.was_contributory() {
        return Err(SealError::SealingFailed(
            "X25519: non-contributory DH result (low-order point)".into(),
        ));
    }

    // Derive AES-256 key via HKDF-SHA256 (binding both public keys)
    let aes_key = derive_aes_key(
        shared_secret.as_bytes(),
        ephemeral_pubkey.as_bytes(),
        recipient_pubkey.as_bytes(),
    )?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
        .map_err(|e| SealError::SealingFailed(format!("AES-256-GCM init failed: {e}")))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SealError::SealingFailed(format!("AES-256-GCM encrypt failed: {e}")))?;

    // Build wire format: ephemeral_pubkey[32] || nonce[12] || ciphertext_with_tag
    let mut output = Vec::with_capacity(PUBKEY_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(ephemeral_pubkey.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt ECIES ciphertext using the recipient's X25519 static secret.
///
/// Input must be wire format: `ephemeral_pubkey[32] || nonce[12] || ciphertext_with_tag[...]`
pub fn decrypt(
    recipient_secret: &StaticSecret,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let min_len = PUBKEY_LEN + NONCE_LEN + 16; // 16 = AES-GCM tag
    if data.len() < min_len {
        return Err(SealError::UnsealingFailed(format!(
            "ECIES ciphertext too short: {} bytes (minimum {})",
            data.len(),
            min_len
        )));
    }

    // Parse wire format
    let ephemeral_pubkey = {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[..PUBKEY_LEN]);
        PublicKey::from(bytes)
    };

    let nonce_bytes = &data[PUBKEY_LEN..PUBKEY_LEN + NONCE_LEN];
    let ciphertext = &data[PUBKEY_LEN + NONCE_LEN..];

    // Derive recipient public key from secret for HKDF binding
    let recipient_pubkey = PublicKey::from(recipient_secret);

    // X25519 ECDH
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_pubkey);
    if !shared_secret.was_contributory() {
        return Err(SealError::UnsealingFailed(
            "X25519: non-contributory DH result (low-order point)".into(),
        ));
    }

    // Derive AES-256 key via HKDF-SHA256 (binding both public keys)
    let aes_key = derive_aes_key(
        shared_secret.as_bytes(),
        ephemeral_pubkey.as_bytes(),
        recipient_pubkey.as_bytes(),
    )?;

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
        .map_err(|e| SealError::UnsealingFailed(format!("AES-256-GCM init failed: {e}")))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SealError::UnsealingFailed(format!("AES-256-GCM decrypt failed: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}

/// Generate a new X25519 keypair for use during init-seal.
///
/// Returns (static_secret, public_key_bytes). The secret is a `StaticSecret`
/// so it can be held across the S3 polling loop and used for decryption later.
pub fn generate_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let pubkey = PublicKey::from(&secret);
    (secret, *pubkey.as_bytes())
}

/// Derive an AES-256 key from an ECDH shared secret using HKDF-SHA256.
///
/// Both public keys are included in the HKDF info string to bind the
/// derived key to this specific session (prevents key-compromise
/// impersonation if the same shared secret were somehow reused).
fn derive_aes_key(
    shared_secret: &[u8],
    ephemeral_pubkey: &[u8; 32],
    recipient_pubkey: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 64);
    info.extend_from_slice(HKDF_INFO);
    info.extend_from_slice(ephemeral_pubkey);
    info.extend_from_slice(recipient_pubkey);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .map_err(|e| SealError::SealingFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret, pubkey_bytes) = generate_keypair();
        let pubkey = PublicKey::from(pubkey_bytes);

        let plaintext = b"test key share data that should be encrypted";
        let ciphertext = encrypt(&pubkey, plaintext).unwrap();

        // Verify wire format structure
        assert!(ciphertext.len() > PUBKEY_LEN + NONCE_LEN + 16);
        assert_eq!(
            ciphertext.len(),
            PUBKEY_LEN + NONCE_LEN + plaintext.len() + 16
        );

        let decrypted = decrypt(&secret, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_different_ciphertexts_each_time() {
        let (_, pubkey_bytes) = generate_keypair();
        let pubkey = PublicKey::from(pubkey_bytes);

        let plaintext = b"same plaintext";
        let ct1 = encrypt(&pubkey, plaintext).unwrap();
        let ct2 = encrypt(&pubkey, plaintext).unwrap();

        // Ephemeral key and nonce differ each time
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (_, pubkey_bytes) = generate_keypair();
        let pubkey = PublicKey::from(pubkey_bytes);

        let plaintext = b"secret data";
        let ciphertext = encrypt(&pubkey, plaintext).unwrap();

        // Try to decrypt with a different key
        let (wrong_secret, _) = generate_keypair();
        let result = decrypt(&wrong_secret, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (secret, pubkey_bytes) = generate_keypair();
        let pubkey = PublicKey::from(pubkey_bytes);

        let plaintext = b"secret data";
        let mut ciphertext = encrypt(&pubkey, plaintext).unwrap();

        // Tamper with the encrypted payload
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = decrypt(&secret, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data_fails() {
        let (secret, _) = generate_keypair();

        // Too short to even contain pubkey + nonce + tag
        let short = vec![0u8; 10];
        assert!(decrypt(&secret, &short).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let (secret, pubkey_bytes) = generate_keypair();
        let pubkey = PublicKey::from(pubkey_bytes);

        let ciphertext = encrypt(&pubkey, b"").unwrap();
        let decrypted = decrypt(&secret, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let (secret, pubkey_bytes) = generate_keypair();
        let pubkey = PublicKey::from(pubkey_bytes);

        let plaintext = vec![0xAB; 4096];
        let ciphertext = encrypt(&pubkey, &plaintext).unwrap();
        let decrypted = decrypt(&secret, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }
}
