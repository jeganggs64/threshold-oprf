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

// ---------------------------------------------------------------------------
// Certificate table parsing (from SNP_GET_EXT_REPORT)
// ---------------------------------------------------------------------------

/// Certificate chain extracted from the SNP extended report cert table.
pub struct CertChain {
    /// VCEK certificate (DER-encoded).
    pub vcek: Vec<u8>,
    /// ASK certificate (DER-encoded).
    pub ask: Vec<u8>,
    /// ARK certificate (DER-encoded).
    pub ark: Vec<u8>,
}

/// Known AMD certificate GUIDs (mixed-endian UUID byte representation).
const GUID_VCEK: [u8; 16] = [
    0x8d, 0x75, 0xda, 0x63, 0x64, 0xe6, 0x64, 0x45, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
const GUID_VLEK: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];
const GUID_ASK: [u8; 16] = [
    0x79, 0xb3, 0xb7, 0x4a, 0xac, 0xbb, 0xe4, 0x4f, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
const GUID_ARK: [u8; 16] = [
    0xa4, 0x06, 0xb4, 0xc0, 0x03, 0xa8, 0x52, 0x49, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];

/// Size of a cert table entry: 16 (GUID) + 4 (offset) + 4 (length) = 24 bytes.
const CERT_TABLE_ENTRY_SIZE: usize = 24;

/// Parse the certificate table from an `SNP_GET_EXT_REPORT` response.
///
/// The table is a sequence of `{guid[16], offset[4], length[4]}` entries,
/// terminated by an all-zero GUID. Certificate data follows at the
/// specified offsets within the same buffer.
pub fn parse_cert_table(raw: &[u8]) -> Result<CertChain, SealError> {
    let mut vcek: Option<Vec<u8>> = None;
    let mut ask: Option<Vec<u8>> = None;
    let mut ark: Option<Vec<u8>> = None;

    let zero_guid = [0u8; 16];
    let mut pos = 0;

    loop {
        if pos + CERT_TABLE_ENTRY_SIZE > raw.len() {
            break;
        }

        let guid: [u8; 16] = raw[pos..pos + 16].try_into().unwrap();
        if guid == zero_guid {
            break; // end of table
        }

        let offset = u32::from_le_bytes(raw[pos + 16..pos + 20].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(raw[pos + 20..pos + 24].try_into().unwrap()) as usize;

        if offset + length > raw.len() {
            return Err(SealError::AttestationFailed(format!(
                "cert table entry at offset {pos} references data beyond buffer \
                 (offset={offset}, length={length}, buf_len={})",
                raw.len()
            )));
        }

        let cert_data = raw[offset..offset + length].to_vec();

        if guid == GUID_VCEK || guid == GUID_VLEK {
            vcek = Some(cert_data);
        } else if guid == GUID_ASK {
            ask = Some(cert_data);
        } else if guid == GUID_ARK {
            ark = Some(cert_data);
        }
        // Skip unknown GUIDs

        pos += CERT_TABLE_ENTRY_SIZE;
    }

    Ok(CertChain {
        vcek: vcek
            .ok_or_else(|| SealError::AttestationFailed("VCEK not found in cert table".into()))?,
        ask: ask
            .ok_or_else(|| SealError::AttestationFailed("ASK not found in cert table".into()))?,
        ark: ark
            .ok_or_else(|| SealError::AttestationFailed("ARK not found in cert table".into()))?,
    })
}

// ---------------------------------------------------------------------------
// Attestation verifier
// ---------------------------------------------------------------------------

pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify the SNP report using a pre-provided certificate chain.
    ///
    /// Use this when the cert chain comes from `SNP_GET_EXT_REPORT` (e.g., on
    /// AWS EC2 where the chip ID is masked and AMD KDS is unavailable).
    pub fn verify_report_with_certs(
        report: &SnpReport,
        certs: &CertChain,
    ) -> Result<(), SealError> {
        // Verify ARK is self-signed
        Self::verify_cert_signature(&certs.ark, &certs.ark)?;
        // Verify ASK is signed by ARK
        Self::verify_cert_signature(&certs.ask, &certs.ark)?;
        // Verify VCEK is signed by ASK
        Self::verify_cert_signature(&certs.vcek, &certs.ask)?;

        // Verify ARK fingerprint (mandatory)
        Self::verify_ark_fingerprint(&certs.ark)?;

        // Check VCEK against CRL if AMD_CRL_URL is set
        Self::check_vcek_revocation(&certs.vcek)?;

        // Verify report signature with VCEK
        let pubkey_bytes = Self::extract_vcek_pubkey(&certs.vcek)?;
        Self::verify_signature(report, &pubkey_bytes)
    }

    /// Verify the SNP report by fetching certificates from AMD KDS.
    ///
    /// This requires a non-zero chip ID (won't work on AWS EC2).
    /// Use `verify_report_with_certs()` with certs from `SNP_GET_EXT_REPORT` instead.
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

        // Verify ARK fingerprint (mandatory)
        Self::verify_ark_fingerprint(&ark_der)?;

        // Check VCEK against CRL if AMD_CRL_URL is set
        Self::check_vcek_revocation(&vcek_der)?;

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

    /// Build a complete certificate chain from an extended report's cert table.
    ///
    /// On AWS with VLEK, the cert table only contains the VLEK certificate.
    /// ASK and ARK are fetched from AMD KDS when missing.
    pub async fn build_cert_chain(
        cert_table: &[u8],
        report: &SnpReport,
    ) -> Result<CertChain, SealError> {
        let mut signing_cert: Option<Vec<u8>> = None;
        let mut is_vlek = false;
        let mut ask: Option<Vec<u8>> = None;
        let mut ark: Option<Vec<u8>> = None;

        let zero_guid = [0u8; 16];
        let mut pos = 0;

        loop {
            if pos + CERT_TABLE_ENTRY_SIZE > cert_table.len() {
                break;
            }

            let guid: [u8; 16] = cert_table[pos..pos + 16].try_into().unwrap();
            if guid == zero_guid {
                break;
            }

            let offset =
                u32::from_le_bytes(cert_table[pos + 16..pos + 20].try_into().unwrap()) as usize;
            let length =
                u32::from_le_bytes(cert_table[pos + 20..pos + 24].try_into().unwrap()) as usize;

            if offset + length > cert_table.len() {
                return Err(SealError::AttestationFailed(format!(
                    "cert table entry at offset {pos} references data beyond buffer \
                     (offset={offset}, length={length}, buf_len={})",
                    cert_table.len()
                )));
            }

            let cert_data = cert_table[offset..offset + length].to_vec();

            if guid == GUID_VCEK {
                signing_cert = Some(cert_data);
            } else if guid == GUID_VLEK {
                signing_cert = Some(cert_data);
                is_vlek = true;
            } else if guid == GUID_ASK {
                ask = Some(cert_data);
            } else if guid == GUID_ARK {
                ark = Some(cert_data);
            }

            pos += CERT_TABLE_ENTRY_SIZE;
        }

        let vcek = signing_cert.ok_or_else(|| {
            SealError::AttestationFailed(
                "no signing certificate (VCEK or VLEK) found in cert table".into(),
            )
        })?;

        // If ASK/ARK missing (common on AWS with VLEK), fetch from AMD KDS
        if ask.is_none() || ark.is_none() {
            let product = Self::detect_product(report);
            let key_type = if is_vlek { "vlek" } else { "vcek" };
            tracing::info!(
                product = %product,
                key_type = %key_type,
                "ASK/ARK not in cert table, fetching from AMD KDS"
            );
            let (fetched_ask, fetched_ark) =
                Self::fetch_cert_chain_by_type(&product, key_type).await?;
            ask = ask.or(Some(fetched_ask));
            ark = ark.or(Some(fetched_ark));
        }

        Ok(CertChain {
            vcek,
            ask: ask.unwrap(),
            ark: ark.unwrap(),
        })
    }

    /// Fetch the AMD certificate chain (ASK + ARK) from AMD KDS.
    async fn fetch_cert_chain(product: &str) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        Self::fetch_cert_chain_by_type(product, "vcek").await
    }

    /// Fetch the AMD certificate chain for a given key type (vcek or vlek).
    async fn fetch_cert_chain_by_type(
        product: &str,
        key_type: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let url = format!("https://kdsintf.amd.com/{key_type}/v1/{product}/cert_chain");

        tracing::debug!(url = %url, "fetching AMD certificate chain from KDS");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SealError::NetworkError(e.to_string()))?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| SealError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SealError::NetworkError(format!(
                "AMD KDS cert_chain returned status {}: {}",
                resp.status(),
                url
            )));
        }

        let pem_data = resp
            .bytes()
            .await
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
    /// `issuer_der`. Supports both ECDSA-P384 (VCEK chain) and RSA-PSS (VLEK chain).
    fn verify_cert_signature(cert_der: &[u8], issuer_der: &[u8]) -> Result<(), SealError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| SealError::AttestationFailed(format!("failed to parse cert: {e}")))?;
        let (_, issuer) = X509Certificate::from_der(issuer_der).map_err(|e| {
            SealError::AttestationFailed(format!("failed to parse issuer cert: {e}"))
        })?;

        // Verify the certificate is within its validity period
        let now = ASN1Time::now();
        if !cert.validity().is_valid_at(now) {
            return Err(SealError::AttestationFailed(
                "certificate expired or not yet valid".into(),
            ));
        }

        // Try x509-parser's built-in verification first (handles ECDSA).
        // Fall back to ring for RSA-PSS which x509-parser 0.16 doesn't support.
        match cert.verify_signature(Some(&issuer.tbs_certificate.subject_pki)) {
            Ok(()) => Ok(()),
            Err(_) => Self::verify_cert_signature_ring(&cert, &issuer),
        }
    }

    /// Verify a certificate signature using ring directly.
    /// Handles RSA-PSS with SHA-256/SHA-384/SHA-512 (used by VLEK chains).
    fn verify_cert_signature_ring(
        cert: &X509Certificate<'_>,
        issuer: &X509Certificate<'_>,
    ) -> Result<(), SealError> {
        use ring::signature as ring_sig;

        let sig_alg_oid = cert.signature_algorithm.algorithm.to_id_string();

        // Select the ring verification algorithm based on the signature OID
        let algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_alg_oid.as_str() {
            // RSA-PSS (OID 1.2.840.113549.1.1.10) — need to check hash from params
            "1.2.840.113549.1.1.10" => {
                // Determine hash algorithm from PSS parameters.
                // AMD VLEK chains use SHA-384, but we try to detect from the cert.
                Self::detect_rsa_pss_algorithm(cert)?
            }
            // RSASSA-PKCS1-v1_5 with SHA-256/384/512
            "1.2.840.113549.1.1.11" => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            "1.2.840.113549.1.1.12" => &ring_sig::RSA_PKCS1_2048_8192_SHA384,
            "1.2.840.113549.1.1.13" => &ring_sig::RSA_PKCS1_2048_8192_SHA512,
            oid => {
                return Err(SealError::AttestationFailed(format!(
                    "unsupported signature algorithm OID: {oid}"
                )));
            }
        };

        let public_key = ring_sig::UnparsedPublicKey::new(
            algorithm,
            &issuer.tbs_certificate.subject_pki.subject_public_key.data,
        );

        // The TBS (to-be-signed) certificate bytes and signature value
        let tbs_bytes = cert.tbs_certificate.as_ref();
        let sig_bytes = &cert.signature_value.data;

        public_key.verify(tbs_bytes, sig_bytes).map_err(|_| {
            SealError::AttestationFailed("cert signature verification failed (ring)".into())
        })
    }

    /// Detect the RSA-PSS hash algorithm from certificate parameters.
    fn detect_rsa_pss_algorithm(
        cert: &X509Certificate<'_>,
    ) -> Result<&'static dyn ring::signature::VerificationAlgorithm, SealError> {
        use ring::signature as ring_sig;

        // Try to extract hash algorithm OID from PSS parameters.
        // If we can't parse params, default to SHA-384 (AMD VLEK standard).
        if let Some(params) = &cert.signature_algorithm.parameters {
            let param_bytes = params.as_bytes();
            // Look for SHA-256 OID (2.16.840.1.101.3.4.2.1) = 60 86 48 01 65 03 04 02 01
            if param_bytes
                .windows(9)
                .any(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
            {
                return Ok(&ring_sig::RSA_PSS_2048_8192_SHA256);
            }
            // Look for SHA-384 OID (2.16.840.1.101.3.4.2.2) = 60 86 48 01 65 03 04 02 02
            if param_bytes
                .windows(9)
                .any(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02])
            {
                return Ok(&ring_sig::RSA_PSS_2048_8192_SHA384);
            }
            // Look for SHA-512 OID (2.16.840.1.101.3.4.2.3) = 60 86 48 01 65 03 04 02 03
            if param_bytes
                .windows(9)
                .any(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
            {
                return Ok(&ring_sig::RSA_PSS_2048_8192_SHA512);
            }
        }

        // Default to SHA-384 (used by AMD SEV-SNP VLEK chains)
        Ok(&ring::signature::RSA_PSS_2048_8192_SHA384)
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
    fn verify_signature(report: &SnpReport, vcek_pubkey_bytes: &[u8]) -> Result<(), SealError> {
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
            .map_err(|e| {
                SealError::AttestationFailed(format!("signature verification failed: {e}"))
            })?;

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
            Err(_) => Err(SealError::AttestationFailed(
                "AMD_ARK_FINGERPRINT env var is not set — ARK certificate pinning is \
                     mandatory. Set this to the SHA-256 hex digest of the DER-encoded ARK \
                     certificate for your AMD product family."
                    .into(),
            )),
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

    /// Check VCEK certificate against AMD's Certificate Revocation List.
    ///
    /// If the `AMD_CRL_PEM` environment variable is set, it should contain the
    /// path to a PEM-encoded CRL file downloaded from AMD KDS
    /// (`https://kdsintf.amd.com/vcek/v1/{product}/crl`). The VCEK serial
    /// number is checked against the revoked list.
    ///
    /// If `AMD_CRL_PEM` is not set, CRL checking is skipped with a warning.
    /// Operators should periodically download the CRL and set this variable.
    fn check_vcek_revocation(vcek_der: &[u8]) -> Result<(), SealError> {
        let crl_path = match std::env::var("AMD_CRL_PEM") {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "AMD_CRL_PEM not set — skipping VCEK revocation check. \
                     Download the CRL from AMD KDS and set this env var for production."
                );
                return Ok(());
            }
        };

        // Parse the VCEK serial number
        let (_, vcek) = X509Certificate::from_der(vcek_der)
            .map_err(|e| SealError::AttestationFailed(format!("failed to parse VCEK: {e}")))?;
        let vcek_serial = vcek.tbs_certificate.raw_serial();

        // Read and parse the CRL
        let crl_data = std::fs::read(&crl_path).map_err(|e| {
            SealError::AttestationFailed(format!("failed to read CRL file {crl_path}: {e}"))
        })?;

        // Try DER first, then PEM
        let crl_der = if crl_data.starts_with(b"-----") {
            let pem_str = std::str::from_utf8(&crl_data)
                .map_err(|e| SealError::AttestationFailed(format!("invalid CRL PEM: {e}")))?;
            let pem = ::pem::parse(pem_str)
                .map_err(|e| SealError::AttestationFailed(format!("CRL PEM parse error: {e}")))?;
            pem.contents().to_vec()
        } else {
            crl_data
        };

        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&crl_der)
            .map_err(|e| SealError::AttestationFailed(format!("failed to parse CRL: {e}")))?;

        // Check if the VCEK serial number is in the revocation list
        for revoked in crl.iter_revoked_certificates() {
            if revoked.raw_serial() == vcek_serial {
                return Err(SealError::AttestationFailed(format!(
                    "VCEK certificate serial {} is REVOKED according to AMD CRL",
                    hex::encode(vcek_serial)
                )));
            }
        }

        tracing::info!(
            serial = %hex::encode(vcek_serial),
            "VCEK not revoked (checked against CRL)"
        );
        Ok(())
    }
}
