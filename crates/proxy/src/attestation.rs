//! Device attestation verification.
//!
//! Supports two platforms:
//! - Apple App Attest (two-phase: one-time registration + per-request assertion)
//! - Google Play Integrity (stateless token verification via Google API)
//!
//! Ported from the TypeScript implementation in ruonid/server/src/providers/attestation.ts.

use base64::Engine;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::device_keys::DeviceKeyStore;

// ---------------------------------------------------------------------------
// Apple App Attest Root CA (production)
// ---------------------------------------------------------------------------

const APPLE_APP_ATTEST_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yw9TRCHg/GnBXvzYR1N9r1CdUrj1mQ02NByAo0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhd6jnedy+sMIPAjEAp5U/xI7NMNqCmMUqHeId3NcUWiSlycLpe/IC
HyQhVBSn5Eu7lFBALGKTLv8GlFsh
-----END CERTIFICATE-----";

/// Result of attestation verification: the device ID.
pub type DeviceId = String;

// ---------------------------------------------------------------------------
// Apple App Attest — Per-request assertion verification
// ---------------------------------------------------------------------------

/// Verify an Apple App Attest assertion (per-request).
///
/// Token format (base64 JSON): { keyId, assertion } or { keyId, authenticatorData, signature }
/// where `assertion` is base64 CBOR containing { authenticatorData, signature }.
///
/// Steps:
///   1. Parse base64 JSON token
///   2. Look up stored public key by keyId
///   3. Verify rpIdHash (first 32 bytes of authData == SHA256(appId))
///   4. Compute clientDataHash = SHA256(nonce)
///   5. Compute compositeHash = SHA256(authData || clientDataHash)
///   6. Verify ECDSA P-256 signature over compositeHash
///   7. Verify counter is monotonically increasing
pub fn verify_apple_assertion(
    token_b64: &str,
    nonce: &str,
    app_id: &str,
    key_store: &mut DeviceKeyStore,
) -> Result<DeviceId, String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. Parse the base64 JSON token
    let token_json = b64
        .decode(token_b64)
        .map_err(|e| format!("invalid base64 token: {e}"))?;
    let token_str =
        String::from_utf8(token_json).map_err(|e| format!("invalid UTF-8 in token: {e}"))?;

    let parsed: serde_json::Value =
        serde_json::from_str(&token_str).map_err(|e| format!("invalid JSON in token: {e}"))?;

    let key_id = parsed["keyId"]
        .as_str()
        .ok_or("assertion missing keyId")?
        .to_string();

    // Extract authenticatorData and signature
    let (auth_data, signature) = if let Some(assertion_b64) = parsed["assertion"].as_str() {
        // CBOR-encoded assertion
        let assertion_bytes = b64
            .decode(assertion_b64)
            .map_err(|e| format!("invalid assertion base64: {e}"))?;

        decode_cbor_assertion(&assertion_bytes)?
    } else if let (Some(auth_data_b64), Some(sig_b64)) = (
        parsed["authenticatorData"].as_str(),
        parsed["signature"].as_str(),
    ) {
        // Pre-decoded fields
        let auth_data = b64
            .decode(auth_data_b64)
            .map_err(|e| format!("invalid authenticatorData base64: {e}"))?;
        let signature = b64
            .decode(sig_b64)
            .map_err(|e| format!("invalid signature base64: {e}"))?;
        (auth_data, signature)
    } else {
        return Err("assertion missing required fields".into());
    };

    // 2. Validate authData length upfront (need at least 37 bytes: 32 rpIdHash + 1 flags + 4 counter)
    if auth_data.len() < 37 {
        return Err("authenticator data too short".into());
    }

    // 3. Look up stored public key
    let entry = key_store
        .get_key(&key_id)
        .ok_or_else(|| format!("unknown device key: {key_id}"))?
        .clone();

    // 4. Verify rpIdHash (first 32 bytes of authData == SHA256(appId))
    let expected_rp_id_hash = Sha256::digest(app_id.as_bytes());
    if auth_data[..32] != expected_rp_id_hash[..] {
        return Err("assertion rpIdHash does not match app ID".into());
    }

    // 5. Compute clientDataHash = SHA256(nonce)
    let client_data_hash = Sha256::digest(nonce.as_bytes());

    // 6. Compute compositeHash = SHA256(authData || clientDataHash)
    let mut composite = Vec::with_capacity(auth_data.len() + 32);
    composite.extend_from_slice(&auth_data);
    composite.extend_from_slice(&client_data_hash);
    let composite_hash = Sha256::digest(&composite);

    // 7. Verify ECDSA P-256 signature
    verify_p256_signature(&entry.public_key_pem, &composite_hash, &signature)?;

    // 8. Verify and update counter (bytes 33-36 of authData, big-endian)
    let new_counter =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if new_counter <= entry.counter {
        return Err(format!(
            "counter replay: received {new_counter}, expected > {}",
            entry.counter
        ));
    }

    key_store
        .update_counter(&key_id, new_counter)
        .map_err(|e| format!("failed to update counter: {e}"))?;

    Ok(key_id)
}

// ---------------------------------------------------------------------------
// Apple App Attest — One-time registration
// ---------------------------------------------------------------------------

/// Register a device via Apple App Attest (one-time).
///
/// Validates the CBOR attestation object, verifies the certificate chain,
/// extracts the EC public key, and stores it for future assertions.
pub fn verify_apple_attestation(
    attestation_object_b64: &str,
    key_id: &str,
    challenge: &str,
    app_id: &str,
    key_store: &mut DeviceKeyStore,
) -> Result<DeviceId, String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. Decode CBOR attestation object
    let att_bytes = b64
        .decode(attestation_object_b64)
        .map_err(|e| format!("invalid attestation base64: {e}"))?;

    let att_value: ciborium::Value =
        ciborium::from_reader(&att_bytes[..]).map_err(|e| format!("invalid CBOR: {e}"))?;

    let att_map = match &att_value {
        ciborium::Value::Map(m) => m,
        _ => return Err("attestation object is not a CBOR map".into()),
    };

    // Extract fmt
    let fmt = get_cbor_text(att_map, "fmt").ok_or("missing fmt")?;
    if fmt != "apple-appattest" {
        return Err(format!("unexpected attestation format: {fmt}"));
    }

    // Extract authData
    let auth_data = get_cbor_bytes(att_map, "authData").ok_or("missing authData")?;

    // Extract attStmt.x5c
    let att_stmt = get_cbor_map(att_map, "attStmt").ok_or("missing attStmt")?;
    let x5c = get_cbor_array_of_bytes(att_stmt, "x5c").ok_or("missing x5c")?;
    if x5c.len() < 2 {
        return Err("x5c chain too short".into());
    }

    // 1a. Verify rpIdHash
    let expected_rp_id_hash = Sha256::digest(app_id.as_bytes());
    if auth_data.len() < 32 || auth_data[..32] != expected_rp_id_hash[..] {
        return Err("attestation rpIdHash does not match app ID".into());
    }

    // 2. Parse the credential certificate (leaf)
    let (_, cred_cert) = x509_parser::parse_x509_certificate(&x5c[0])
        .map_err(|e| format!("failed to parse credential cert: {e}"))?;

    // 3. Verify certificate chain leads to Apple root CA
    verify_apple_cert_chain(&x5c)?;

    // 4. Verify nonce: SHA256(authData || SHA256(challenge)) must match the cert extension
    let client_data_hash = Sha256::digest(challenge.as_bytes());
    let mut nonce_input = Vec::with_capacity(auth_data.len() + 32);
    nonce_input.extend_from_slice(&auth_data);
    nonce_input.extend_from_slice(&client_data_hash);
    let expected_nonce = Sha256::digest(&nonce_input);

    verify_attestation_nonce(&cred_cert, &expected_nonce)?;

    // 5. Extract EC public key PEM from the leaf cert
    let public_key_pem = extract_public_key_pem(&cred_cert)?;

    // 5a. Verify key_id matches SHA-256 of the public key's raw bytes.
    // Apple's key_id is the SHA-256 hash of the EC public key point, base64-encoded.
    let public_key_bytes = cred_cert.public_key().subject_public_key.data.to_vec();
    let computed_key_id_hash = Sha256::digest(&public_key_bytes);
    let computed_key_id_b64 =
        base64::engine::general_purpose::STANDARD.encode(computed_key_id_hash);
    if key_id != computed_key_id_b64 {
        return Err(format!(
            "key_id mismatch: provided {} but cert public key hashes to {}",
            key_id, computed_key_id_b64
        ));
    }

    // 6. Store the key (rejects re-registration of existing keys)
    key_store
        .save_key(key_id, &public_key_pem, 0)
        .map_err(|e| format!("failed to store device key: {e}"))?;

    info!(key_id = %key_id, "Apple App Attest device registered");

    Ok(key_id.to_string())
}

// ---------------------------------------------------------------------------
// Google Play Integrity
// ---------------------------------------------------------------------------

/// Verify a Google Play Integrity token.
///
/// 1. Decodes the base64 token to extract the integrity token string.
/// 2. Obtains an OAuth2 access token using the service account key (JWT assertion flow).
/// 3. Calls the Google Play Integrity API to decode the integrity token.
/// 4. Validates nonce, package name, device integrity, and app integrity.
/// 5. Returns a device ID derived from a SHA-256 hash of the token.
pub async fn verify_google_play_integrity(
    token_b64: &str,
    nonce: &str,
    package_name: &str,
    service_account_key: &str,
    http_client: &reqwest::Client,
) -> Result<DeviceId, String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. Decode the base64 token to get the integrity token string from JSON
    let token_json_bytes = b64
        .decode(token_b64)
        .map_err(|e| format!("invalid base64 token: {e}"))?;
    let token_json_str =
        String::from_utf8(token_json_bytes).map_err(|e| format!("invalid UTF-8 in token: {e}"))?;
    let token_parsed: serde_json::Value =
        serde_json::from_str(&token_json_str).map_err(|e| format!("invalid JSON in token: {e}"))?;
    let integrity_token = token_parsed["integrityToken"]
        .as_str()
        .ok_or("token JSON missing integrityToken field")?
        .to_string();

    // 2. Get an OAuth2 access token using the service account key
    let access_token = get_google_access_token(service_account_key, http_client).await?;

    // 3. Call Google Play Integrity API to decode the token
    let api_url = format!(
        "https://playintegrity.googleapis.com/v1/{}:decodeIntegrityToken",
        package_name
    );

    let decode_body = serde_json::json!({
        "integrity_token": integrity_token
    });

    let api_response = http_client
        .post(&api_url)
        .bearer_auth(&access_token)
        .json(&decode_body)
        .send()
        .await
        .map_err(|e| format!("Play Integrity API request failed: {e}"))?;

    if !api_response.status().is_success() {
        let status = api_response.status();
        let body = api_response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".into());
        return Err(format!("Play Integrity API returned {status}: {body}"));
    }

    let response_json: serde_json::Value = api_response
        .json()
        .await
        .map_err(|e| format!("failed to parse Play Integrity API response: {e}"))?;

    // 4. Validate the response
    let token_payload = &response_json["tokenPayloadExternal"];

    // 4a. Validate nonce — Google returns it in requestDetails.nonce (base64-encoded)
    let response_nonce = token_payload["requestDetails"]["nonce"]
        .as_str()
        .ok_or("response missing requestDetails.nonce")?;
    let expected_nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes());
    if response_nonce != expected_nonce_b64 {
        return Err(format!(
            "nonce mismatch: expected {expected_nonce_b64}, got {response_nonce}"
        ));
    }

    // 4b. Validate package name
    let response_package = token_payload["requestDetails"]["requestPackageName"]
        .as_str()
        .ok_or("response missing requestDetails.requestPackageName")?;
    if response_package != package_name {
        return Err(format!(
            "package name mismatch: expected {package_name}, got {response_package}"
        ));
    }

    // 4c. Validate device integrity
    let device_verdict = token_payload["deviceIntegrity"]["deviceRecognitionVerdict"]
        .as_array()
        .ok_or("response missing deviceIntegrity.deviceRecognitionVerdict")?;
    let has_device_integrity = device_verdict
        .iter()
        .any(|v| v.as_str() == Some("MEETS_DEVICE_INTEGRITY"));
    if !has_device_integrity {
        return Err(format!(
            "device does not meet integrity requirements: {:?}",
            device_verdict
        ));
    }

    // 4d. Validate app integrity
    let app_verdict = token_payload["appIntegrity"]["appRecognitionVerdict"]
        .as_str()
        .ok_or("response missing appIntegrity.appRecognitionVerdict")?;
    if app_verdict != "PLAY_RECOGNIZED" {
        return Err(format!("app not recognized by Play: {app_verdict}"));
    }

    // 5. Derive a device ID from the token hash
    let token_hash = Sha256::digest(integrity_token.as_bytes());
    let device_id = hex::encode(token_hash);

    info!(device_id = %device_id, "Google Play Integrity verification succeeded");

    Ok(device_id)
}

/// Service account key JSON structure (subset of fields we need).
#[derive(serde::Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

/// Google OAuth2 token response.
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Obtain a Google OAuth2 access token using a service account key (JWT assertion flow).
///
/// Creates a JWT signed with the service account's RSA private key, then exchanges
/// it at Google's token endpoint for an access token.
async fn get_google_access_token(
    service_account_key_json: &str,
    http_client: &reqwest::Client,
) -> Result<String, String> {
    let sa_key: ServiceAccountKey = serde_json::from_str(service_account_key_json)
        .map_err(|e| format!("invalid service account key JSON: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?
        .as_secs();

    let token_uri = sa_key
        .token_uri
        .as_deref()
        .unwrap_or("https://oauth2.googleapis.com/token");

    // Build JWT claims
    let claims = serde_json::json!({
        "iss": sa_key.client_email,
        "sub": sa_key.client_email,
        "aud": "https://oauth2.googleapis.com/token",
        "scope": "https://www.googleapis.com/auth/playintegrity",
        "iat": now,
        "exp": now + 3600,
    });

    // Sign the JWT with RS256
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(sa_key.private_key.as_bytes())
        .map_err(|e| format!("invalid RSA private key in service account: {e}"))?;

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let jwt_assertion = jsonwebtoken::encode(&header, &claims, &encoding_key)
        .map_err(|e| format!("failed to encode JWT assertion: {e}"))?;

    // Exchange JWT for access token
    let token_response = http_client
        .post(token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt_assertion),
        ])
        .send()
        .await
        .map_err(|e| format!("OAuth2 token request failed: {e}"))?;

    if !token_response.status().is_success() {
        let status = token_response.status();
        let body = token_response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".into());
        return Err(format!("OAuth2 token endpoint returned {status}: {body}"));
    }

    let token_data: TokenResponse = token_response
        .json()
        .await
        .map_err(|e| format!("failed to parse OAuth2 token response: {e}"))?;

    Ok(token_data.access_token)
}

// ---------------------------------------------------------------------------
// Multi-platform auto-detection
// ---------------------------------------------------------------------------

/// Detect platform from token format and verify accordingly.
///
/// - Contains "keyId" → Apple assertion
/// - Contains "integrityToken" → Google Play Integrity
pub async fn verify_attestation(
    token_b64: &str,
    nonce: &str,
    app_id: &str,
    package_name: &str,
    key_store: &mut DeviceKeyStore,
    http_client: &reqwest::Client,
) -> Result<DeviceId, String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let decoded = b64
        .decode(token_b64)
        .map_err(|e| format!("invalid base64: {e}"))?;
    let decoded_str = String::from_utf8_lossy(&decoded);

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded_str) {
        if parsed.get("integrityToken").is_some() {
            return verify_google_play_integrity(
                token_b64,
                nonce,
                package_name,
                "", // service account key — configured separately in production
                http_client,
            )
            .await;
        }

        if parsed.get("keyId").is_some() {
            return verify_apple_assertion(token_b64, nonce, app_id, key_store);
        }
    }

    Err("unable to detect attestation platform from token format".into())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decode a CBOR-encoded Apple assertion into (authenticatorData, signature).
fn decode_cbor_assertion(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| format!("invalid CBOR assertion: {e}"))?;

    let map = match &value {
        ciborium::Value::Map(m) => m,
        _ => return Err("CBOR assertion is not a map".into()),
    };

    let auth_data = get_cbor_bytes(map, "authenticatorData")
        .ok_or("CBOR assertion missing authenticatorData")?;
    let signature = get_cbor_bytes(map, "signature").ok_or("CBOR assertion missing signature")?;

    Ok((auth_data, signature))
}

/// Verify a P-256 ECDSA signature.
fn verify_p256_signature(
    public_key_pem: &str,
    message_hash: &[u8],
    signature_der: &[u8],
) -> Result<(), String> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("invalid public key PEM: {e}"))?;

    // The signature from Apple is DER-encoded. Convert to fixed-size format.
    let signature =
        Signature::from_der(signature_der).map_err(|e| format!("invalid DER signature: {e}"))?;

    // Apple signs the raw hash (no additional hashing), so we use verify_prehash
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(message_hash, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Verify the x5c certificate chain against Apple's root CA using cryptographic
/// signature verification (not just issuer/subject name matching).
fn verify_apple_cert_chain(x5c: &[Vec<u8>]) -> Result<(), String> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    if x5c.is_empty() {
        return Err("empty certificate chain".into());
    }

    // Parse Apple root CA from PEM → DER → X509Certificate
    let root_pem_parsed = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA)
        .map_err(|e| format!("failed to parse root CA PEM: {e}"))?;
    let (_, apple_root) = X509Certificate::from_der(root_pem_parsed.contents())
        .map_err(|e| format!("failed to parse Apple root CA: {e}"))?;

    // Verify root is self-signed (passes None → uses its own public key)
    apple_root
        .verify_signature(None)
        .map_err(|e| format!("Apple root CA self-signature invalid: {e}"))?;

    // Check root CA validity
    if !apple_root.validity().is_valid() {
        return Err("Apple root CA certificate has expired or is not yet valid".into());
    }

    // Parse all certs in the chain
    let mut parsed_certs = Vec::new();
    for (i, cert_der) in x5c.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| format!("failed to parse cert at index {i}: {e}"))?;
        parsed_certs.push(cert);
    }

    // The chain is [leaf, intermediate, ...].
    // Verify each cert is signed by the next one in the chain.
    for i in 0..parsed_certs.len() - 1 {
        let issuer = &parsed_certs[i + 1];
        parsed_certs[i]
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| format!("cert chain signature verification failed at index {i}: {e}"))?;

        if !parsed_certs[i].validity().is_valid() {
            return Err(format!(
                "certificate at index {} has expired or is not yet valid",
                i
            ));
        }
    }

    // Verify the last cert in the chain is signed by Apple root
    let last_idx = parsed_certs.len() - 1;
    let last = parsed_certs.last().unwrap();
    last.verify_signature(Some(apple_root.public_key()))
        .map_err(|e| format!("intermediate not signed by Apple root: {e}"))?;

    if !last.validity().is_valid() {
        return Err(format!(
            "certificate at index {} has expired or is not yet valid",
            last_idx
        ));
    }

    Ok(())
}

/// Verify the attestation nonce in the credential certificate's extension.
/// OID 1.2.840.113635.100.8.2 contains the nonce.
///
/// The extension value is DER-encoded with the following ASN.1 structure:
///   SEQUENCE { SET { SEQUENCE { INTEGER, OCTET STRING <nonce> } } }
/// We parse the structure properly rather than relying on byte offsets.
fn verify_attestation_nonce(
    cert: &x509_parser::certificate::X509Certificate,
    expected_nonce: &[u8],
) -> Result<(), String> {
    use x509_parser::der_parser::parse_der;

    // Apple App Attest nonce OID: 1.2.840.113635.100.8.2
    let nonce_oid =
        x509_parser::oid_registry::Oid::from(&[1, 2, 840, 113635, 100, 8, 2]).expect("invalid OID");

    let ext = cert
        .get_extension_unique(&nonce_oid)
        .map_err(|e| format!("error reading nonce extension: {e}"))?
        .ok_or("attestation cert missing nonce extension")?;

    let ext_value = ext.value;

    // Parse the DER-encoded extension value
    let (_, parsed) =
        parse_der(ext_value).map_err(|e| format!("failed to parse nonce extension ASN.1: {e}"))?;

    // Walk the ASN.1 structure to extract the OCTET STRING containing the nonce.
    // Expected: SEQUENCE { SET/SEQUENCE { ... OCTET STRING } }
    // We recursively descend into constructed types (SEQUENCE/SET/context-tagged)
    // until we find the first OCTET STRING.
    let nonce_from_cert =
        find_octet_string(&parsed).ok_or("nonce extension does not contain an OCTET STRING")?;

    if nonce_from_cert != expected_nonce {
        return Err("attestation nonce mismatch".into());
    }

    Ok(())
}

/// Recursively search a parsed DER object for the first OCTET STRING value.
fn find_octet_string<'a>(obj: &'a x509_parser::der_parser::ber::BerObject<'a>) -> Option<&'a [u8]> {
    use x509_parser::der_parser::ber::BerObjectContent;

    match &obj.content {
        BerObjectContent::OctetString(data) => Some(data),
        BerObjectContent::Sequence(items) | BerObjectContent::Set(items) => {
            for item in items {
                if let Some(found) = find_octet_string(item) {
                    return Some(found);
                }
            }
            None
        }
        // Context-tagged (constructed) — e.g., [1] EXPLICIT wrapping
        BerObjectContent::Tagged(_, _, inner) => find_octet_string(inner),
        _ => None,
    }
}

/// Extract the public key PEM from an X.509 certificate.
fn extract_public_key_pem(
    cert: &x509_parser::certificate::X509Certificate,
) -> Result<String, String> {
    let spki = cert.public_key();
    let spki_der = spki.raw;

    // Encode as PEM
    let pem_block = pem::Pem::new("PUBLIC KEY", spki_der.to_vec());
    Ok(pem::encode(&pem_block))
}

// CBOR helpers

fn get_cbor_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| {
        if let (ciborium::Value::Text(k), ciborium::Value::Text(v)) = (k, v) {
            if k == key {
                return Some(v.clone());
            }
        }
        None
    })
}

fn get_cbor_bytes(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        if let ciborium::Value::Text(k) = k {
            if k == key {
                if let ciborium::Value::Bytes(b) = v {
                    return Some(b.clone());
                }
            }
        }
        None
    })
}

fn get_cbor_map<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [(ciborium::Value, ciborium::Value)]> {
    map.iter().find_map(|(k, v)| {
        if let ciborium::Value::Text(k) = k {
            if k == key {
                if let ciborium::Value::Map(m) = v {
                    return Some(m.as_slice());
                }
            }
        }
        None
    })
}

fn get_cbor_array_of_bytes(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<Vec<Vec<u8>>> {
    map.iter().find_map(|(k, v)| {
        if let ciborium::Value::Text(k) = k {
            if k == key {
                if let ciborium::Value::Array(arr) = v {
                    let mut certs = Vec::new();
                    for (i, item) in arr.iter().enumerate() {
                        match item {
                            ciborium::Value::Bytes(b) => certs.push(b.clone()),
                            _ => {
                                tracing::error!(
                                    index = i,
                                    key = key,
                                    "x5c element is not bytes, rejecting"
                                );
                                return None;
                            }
                        }
                    }
                    if !certs.is_empty() {
                        return Some(certs);
                    }
                }
            }
        }
        None
    })
}
