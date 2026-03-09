//! AMD SEV-SNP attestation verification.
//!
//! Verifies an SNP report's ECDSA-P384-SHA384 signature against AMD's
//! certificate chain by fetching the VCEK certificate from AMD's Key
//! Distribution Service (KDS) and validating the full chain (VCEK -> ASK -> ARK).

use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

use crate::snp_report::SnpReport;
use crate::SealError;

pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify the SNP report's signature against AMD's certificate chain.
    ///
    /// 1. Extract chip_id and TCB from report
    /// 2. Fetch VCEK certificate from AMD KDS
    /// 3. Fetch and verify the AMD certificate chain (ASK + ARK)
    /// 4. Verify VCEK is signed by ASK, ASK is signed by ARK, ARK is self-signed
    /// 5. Verify ARK fingerprint against pinned value (if configured)
    /// 6. Parse VCEK cert, extract P-384 public key
    /// 7. Verify ECDSA-P384-SHA384 signature over report body
    pub async fn verify_report(report: &SnpReport) -> Result<(), SealError> {
        let vcek_der = Self::fetch_vcek_cert(report).await?;
        let product = Self::detect_product(report);

        // Fetch and verify the AMD certificate chain
        let (ask_der, ark_der) = Self::fetch_cert_chain(&product).await?;

        // Verify ARK is self-signed
        Self::verify_cert_signature(&ark_der, &ark_der)?;
        // Verify ASK is signed by ARK
        Self::verify_cert_signature(&ask_der, &ark_der)?;
        // Verify VCEK is signed by ASK
        Self::verify_cert_signature(&vcek_der, &ask_der)?;

        // Verify ARK fingerprint against pinned value (if configured via
        // AMD_ARK_FINGERPRINT env var). The value must be the lowercase hex
        // SHA-256 digest of the DER-encoded ARK certificate.
        Self::verify_ark_fingerprint(&ark_der)?;

        let pubkey_bytes = Self::extract_vcek_pubkey(&vcek_der)?;
        Self::verify_signature(report, &pubkey_bytes)
    }

    /// Fetch the VCEK certificate from AMD Key Distribution Service.
    ///
    /// URL format:
    /// `https://kdsintf.amd.com/vcek/v1/{product}/{chip_id_hex}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}`
    async fn fetch_vcek_cert(report: &SnpReport) -> Result<Vec<u8>, SealError> {
        let product = Self::detect_product(report);
        let chip_id = report.chip_id_hex();
        let (bl, tee, snp, ucode) = report.tcb_parts();

        let url = format!(
            "https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}"
        );

        tracing::debug!(url = %url, "fetching VCEK certificate from AMD KDS");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SealError::NetworkError(format!("failed to build HTTP client: {e}")))?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| SealError::NetworkError(format!("failed to fetch VCEK cert: {e}")))?;

        if !resp.status().is_success() {
            return Err(SealError::NetworkError(format!(
                "AMD KDS returned status {}: {}",
                resp.status(),
                url
            )));
        }

        let der_bytes = resp
            .bytes()
            .await
            .map_err(|e| SealError::NetworkError(format!("failed to read VCEK response: {e}")))?;
        if der_bytes.len() > 65536 {
            return Err(SealError::NetworkError("response too large (>64KB)".into()));
        }

        Ok(der_bytes.to_vec())
    }

    /// Fetch the AMD certificate chain (ASK + ARK) from AMD KDS.
    async fn fetch_cert_chain(product: &str) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let url = format!("https://kdsintf.amd.com/vcek/v1/{}/cert_chain", product);

        tracing::debug!(url = %url, "fetching AMD certificate chain from KDS");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SealError::NetworkError(e.to_string()))?;
        let resp = client.get(&url).send().await
            .map_err(|e| SealError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SealError::NetworkError(format!(
                "AMD KDS cert_chain returned status {}: {}",
                resp.status(),
                url
            )));
        }

        let pem_data = resp.bytes().await
            .map_err(|e| SealError::NetworkError(e.to_string()))?;
        if pem_data.len() > 65536 {
            return Err(SealError::NetworkError("response too large (>64KB)".into()));
        }

        // Parse PEM - the chain contains ASK then ARK
        let pem_str = std::str::from_utf8(&pem_data)
            .map_err(|e| SealError::AttestationFailed(format!("invalid PEM: {e}")))?;
        let pems: Vec<_> = ::pem::parse_many(pem_str)
            .map_err(|e| SealError::AttestationFailed(format!("PEM parse error: {e}")))?;

        if pems.len() < 2 {
            return Err(SealError::AttestationFailed(
                "cert chain must contain ASK and ARK".into(),
            ));
        }

        Ok((pems[0].contents().to_vec(), pems[1].contents().to_vec()))
    }

    /// Verify that `cert_der` was signed by the issuer whose public key is in
    /// `issuer_der`.
    fn verify_cert_signature(
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<(), SealError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| SealError::AttestationFailed(format!("failed to parse cert: {e}")))?;
        let (_, issuer) = X509Certificate::from_der(issuer_der)
            .map_err(|e| SealError::AttestationFailed(format!("failed to parse issuer cert: {e}")))?;

        // Verify the certificate is within its validity period
        let now = ASN1Time::now();
        if !cert.validity().is_valid_at(now) {
            return Err(SealError::AttestationFailed(
                "certificate expired or not yet valid".into(),
            ));
        }

        // Use x509-parser's built-in verify_signature which handles the TBS
        // extraction and signature algorithm correctly
        cert.verify_signature(Some(&issuer.tbs_certificate.subject_pki))
            .map_err(|e| SealError::AttestationFailed(format!("cert signature verification failed: {e}")))?;

        Ok(())
    }

    /// Extract the P-384 public key bytes from a DER-encoded VCEK certificate.
    fn extract_vcek_pubkey(vcek_der: &[u8]) -> Result<Vec<u8>, SealError> {
        let (_, cert) = X509Certificate::from_der(vcek_der)
            .map_err(|e| SealError::AttestationFailed(format!("failed to parse VCEK cert: {e}")))?;

        let pubkey = cert.public_key();
        let key_data = pubkey.subject_public_key.data.to_vec();

        if key_data.is_empty() {
            return Err(SealError::AttestationFailed(
                "VCEK certificate has empty public key".into(),
            ));
        }

        Ok(key_data)
    }

    /// Verify the ECDSA-P384-SHA384 signature over the report body using
    /// the VCEK public key.
    fn verify_signature(
        report: &SnpReport,
        vcek_pubkey_bytes: &[u8],
    ) -> Result<(), SealError> {
        // Parse the P-384 verifying key from the uncompressed point
        let verifying_key = VerifyingKey::from_sec1_bytes(vcek_pubkey_bytes)
            .map_err(|e| SealError::AttestationFailed(format!("invalid VCEK public key: {e}")))?;

        // Build the ECDSA signature from r and s components.
        // The p384 crate's Signature::from_scalars expects 48-byte big-endian
        // r and s values. The SNP report stores them in little-endian, so we
        // must reverse.
        let mut r_be = report.signature_r;
        let mut s_be = report.signature_s;
        r_be.reverse();
        s_be.reverse();

        let signature = Signature::from_scalars(
            *p384::FieldBytes::from_slice(&r_be),
            *p384::FieldBytes::from_slice(&s_be),
        )
        .map_err(|e| SealError::AttestationFailed(format!("invalid signature encoding: {e}")))?;

        // Verify — the p384 crate handles hashing internally when using
        // the `verify` method with the message (not pre-hashed).
        verifying_key
            .verify(&report.body_bytes, &signature)
            .map_err(|e| SealError::AttestationFailed(format!("signature verification failed: {e}")))?;

        tracing::info!("SNP report signature verified successfully");
        Ok(())
    }

    /// Verify the ARK certificate fingerprint against the pinned value.
    ///
    /// If the `AMD_ARK_FINGERPRINT` environment variable is set, compute the
    /// SHA-256 digest of the DER-encoded ARK certificate and compare it against
    /// the expected value. If the variable is not set, log a warning and allow
    /// (defense in depth — operators should always pin in production).
    fn verify_ark_fingerprint(ark_der: &[u8]) -> Result<(), SealError> {
        match std::env::var("AMD_ARK_FINGERPRINT") {
            Ok(expected_hex) => {
                let expected_hex = expected_hex.trim().to_lowercase();
                let actual = Sha256::digest(ark_der);
                let actual_hex = hex::encode(actual);

                if actual_hex != expected_hex {
                    return Err(SealError::AttestationFailed(format!(
                        "AMD ARK fingerprint mismatch: expected {expected_hex}, got {actual_hex}"
                    )));
                }

                tracing::info!("AMD ARK fingerprint verified: {actual_hex}");
                Ok(())
            }
            Err(_) => {
                tracing::warn!(
                    "AMD_ARK_FINGERPRINT not set — ARK certificate is NOT pinned. \
                     Set this env var to the SHA-256 hex digest of the ARK DER certificate \
                     for your AMD product family to defend against MITM on the KDS connection."
                );
                Ok(())
            }
        }
    }

    /// Detect the AMD product name from the report.
    ///
    /// Uses `current_major` from the report to heuristically distinguish:
    ///   - Milan = EPYC 7003 (Zen 3), current_major <= 25
    ///   - Genoa = EPYC 9004 (Zen 4+), current_major > 25
    fn detect_product(report: &SnpReport) -> String {
        match report.current_major {
            0..=25 => "Milan".to_string(),
            _ => "Genoa".to_string(),
        }
    }
}
