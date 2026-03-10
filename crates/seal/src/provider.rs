//! Hardware attestation report retrieval and key derivation.
//!
//! Supports two provider backends:
//! - `/dev/sev-guest` ioctl (bare-metal SEV-SNP hosts: OVHcloud, Hetzner, etc.)
//! - GCP Confidential VM metadata endpoint
//!
//! Also provides `get_derived_key()` for MSG_KEY_REQ (SNP_GET_DERIVED_KEY),
//! which requests a hardware-derived key from the AMD Secure Processor.

use crate::snp_report::SnpReport;
#[cfg(target_os = "linux")]
use crate::snp_report::REPORT_TOTAL_SIZE;
use crate::SealError;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// MSG_KEY_REQ field selector constants (GUEST_FIELD_SELECT bitmask)
// ---------------------------------------------------------------------------

/// Fields that can be mixed into MSG_KEY_REQ key derivation.
/// AMD SEV-SNP Firmware ABI, Table 19 (GUEST_FIELD_SELECT).
///
/// IMPORTANT: Only MEASUREMENT and TCB_VERSION are safe to use.
/// Other fields (GUEST_POLICY, IMAGE_ID, FAMILY_ID, GUEST_SVN)
/// may change between boots or deployments, causing the derived
/// key to change and sealed blobs to become undecryptable.
pub const FIELD_GUEST_POLICY: u64 = 1 << 0;
pub const FIELD_IMAGE_ID: u64 = 1 << 1;
pub const FIELD_FAMILY_ID: u64 = 1 << 2;
pub const FIELD_MEASUREMENT: u64 = 1 << 3;
pub const FIELD_GUEST_SVN: u64 = 1 << 4;
pub const FIELD_TCB_VERSION: u64 = 1 << 5;

/// Safe field selector for sealing: MEASUREMENT + TCB_VERSION only.
/// These are stable across reboots on the same chip with the same image.
/// - MEASUREMENT: SHA-384 of firmware + kernel + initrd + VMSAs
/// - TCB_VERSION: firmware and microcode security versions
///
/// DO NOT add other fields without understanding the consequences:
/// - GUEST_POLICY: changes if VM policy is reconfigured
/// - IMAGE_ID / FAMILY_ID: operator-set, may vary between deployments
/// - GUEST_SVN: changes with guest software version updates
pub const SAFE_FIELD_SELECT: u64 = FIELD_MEASUREMENT | FIELD_TCB_VERSION;

#[derive(Debug, Clone, Copy)]
pub enum SnpProvider {
    /// Raw /dev/sev-guest ioctl (OVHcloud, Hetzner, any bare-metal SEV-SNP).
    DevSevGuest,
    /// GCP metadata endpoint for Confidential VMs.
    GcpMetadata,
}

/// Fetch an attestation report from the local hardware.
///
/// `report_data`: optional 64-byte user data to include in the report.
pub async fn get_attestation_report(
    provider: SnpProvider,
    report_data: Option<&[u8; 64]>,
) -> Result<SnpReport, SealError> {
    match provider {
        SnpProvider::DevSevGuest => get_report_dev_sev_guest(report_data),
        SnpProvider::GcpMetadata => get_report_gcp_metadata(report_data).await,
    }
}

// ---------------------------------------------------------------------------
// MSG_KEY_REQ / SNP_GET_DERIVED_KEY (Linux only)
// ---------------------------------------------------------------------------

/// Request a hardware-derived key from the AMD Secure Processor via MSG_KEY_REQ.
///
/// The derived key is unique to this specific physical CPU chip AND the selected
/// guest fields (measurement, TCB version). A different chip or different
/// measurement will produce a completely different key.
///
/// Uses VCEK (Versioned Chip Endorsement Key) as the root key, which is
/// unique per physical CPU die and cannot be extracted.
///
/// `field_select` controls which guest fields are mixed into the derivation.
/// Use `SAFE_FIELD_SELECT` (MEASUREMENT | TCB_VERSION) for sealing.
#[cfg(target_os = "linux")]
pub fn get_derived_key(field_select: u64) -> Result<Zeroizing<[u8; 32]>, SealError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    /// SNP_GET_DERIVED_KEY ioctl number.
    /// Computed as _IOWR('S', 0x01, struct snp_user_key_req)
    /// where 'S' = 0x53, nr = 0x01, size = 88 bytes = 0x58.
    const SNP_GET_DERIVED_KEY_IOCTL: libc::c_ulong = 0xC058_5301;

    #[repr(C)]
    struct SnpDerivedKeyReq {
        root_key_select: u32, // 0 = VCEK (chip-specific), 1 = VMRK
        reserved: u32,
        guest_field_select: u64, // Bitmask of fields to mix into key derivation
    }

    #[repr(C)]
    struct SnpDerivedKeyResp {
        data: [u8; 64], // Derived key (we use first 32 bytes for AES-256)
    }

    #[repr(C)]
    struct SnpUserKeyReq {
        req: SnpDerivedKeyReq,   // 16 bytes
        resp: SnpDerivedKeyResp, // 64 bytes
        fw_err: u64,             // 8 bytes
    }
    // Total: 88 bytes

    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| SealError::ProviderError(format!("failed to open /dev/sev-guest: {e}")))?;

    let mut user_req = SnpUserKeyReq {
        req: SnpDerivedKeyReq {
            root_key_select: 0, // VCEK — chip-unique root key
            reserved: 0,
            guest_field_select: field_select,
        },
        resp: SnpDerivedKeyResp { data: [0u8; 64] },
        fw_err: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SNP_GET_DERIVED_KEY_IOCTL,
            &mut user_req as *mut SnpUserKeyReq,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SealError::ProviderError(format!(
            "SNP_GET_DERIVED_KEY ioctl failed: {errno}"
        )));
    }

    if user_req.fw_err != 0 {
        return Err(SealError::ProviderError(format!(
            "SNP_GET_DERIVED_KEY firmware error: 0x{:X}",
            user_req.fw_err
        )));
    }

    // Extract the first 32 bytes as the AES-256 key
    let mut key = [0u8; 32];
    key.copy_from_slice(&user_req.resp.data[..32]);

    // Zero out the remaining 32 bytes of the response that we don't use
    user_req.resp.data[32..64].fill(0);

    Ok(Zeroizing::new(key))
}

#[cfg(not(target_os = "linux"))]
pub fn get_derived_key(_field_select: u64) -> Result<Zeroizing<[u8; 32]>, SealError> {
    Err(SealError::ProviderError(
        "SNP_GET_DERIVED_KEY only available on Linux".into(),
    ))
}

// ---------------------------------------------------------------------------
// /dev/sev-guest provider (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn get_report_dev_sev_guest(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // SNP_GET_REPORT ioctl number from the Linux kernel ABI
    const SNP_GET_REPORT_IOCTL: libc::c_ulong = 0xC018_5300;

    // Request structure passed to the kernel
    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        rsvd: [u8; 28],
    }

    // Response structure filled by the kernel
    #[repr(C)]
    struct SnpReportResp {
        status: u32,
        report_size: u32,
        rsvd: [u8; 24],
        report: [u8; 4000],
    }

    // Top-level ioctl structure
    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8,
        _pad: [u8; 7],
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
    }

    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| SealError::ProviderError(format!("failed to open /dev/sev-guest: {e}")))?;

    let mut req = SnpReportReq {
        user_data: [0u8; 64],
        vmpl: 0,
        rsvd: [0u8; 28],
    };
    if let Some(data) = report_data {
        req.user_data = *data;
    }

    let mut resp = SnpReportResp {
        status: 0,
        report_size: 0,
        rsvd: [0u8; 24],
        report: [0u8; 4000],
    };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &req as *const SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SNP_GET_REPORT_IOCTL,
            &mut ioctl_req as *mut SnpGuestRequestIoctl,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SealError::ProviderError(format!(
            "SNP_GET_REPORT ioctl failed: {errno}"
        )));
    }

    if resp.status != 0 {
        return Err(SealError::ProviderError(format!(
            "SNP_GET_REPORT returned error status: {}",
            resp.status
        )));
    }

    let report_size = resp.report_size as usize;
    if report_size < REPORT_TOTAL_SIZE {
        return Err(SealError::ProviderError(format!(
            "SNP report too small: {report_size} bytes (expected >= {REPORT_TOTAL_SIZE})"
        )));
    }

    SnpReport::from_bytes(&resp.report[..REPORT_TOTAL_SIZE])
}

#[cfg(not(target_os = "linux"))]
fn get_report_dev_sev_guest(_report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    Err(SealError::ProviderError(
        "SEV-SNP /dev/sev-guest only available on Linux".into(),
    ))
}

// ---------------------------------------------------------------------------
// GCP Confidential VM metadata provider
// ---------------------------------------------------------------------------

async fn get_report_gcp_metadata(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    let url = "http://metadata.google.internal/computeMetadata/v1/instance/confidential-computing/attestation-report";

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| SealError::ProviderError(format!("failed to build HTTP client: {e}")))?;
    let resp = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .map_err(|e| SealError::ProviderError(format!("failed to fetch GCP attestation: {e}")))?;

    if !resp.status().is_success() {
        return Err(SealError::ProviderError(format!(
            "GCP metadata endpoint returned status {}",
            resp.status()
        )));
    }

    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| SealError::ProviderError(format!("failed to read GCP response: {e}")))?;

    // Try JSON first: {"report": "<base64>"}
    let raw_report = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
    {
        if let Some(report_b64) = json_val.get("report").and_then(|v| v.as_str()) {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(report_b64)
                .map_err(|e| {
                    SealError::ProviderError(format!("failed to base64-decode report: {e}"))
                })?
        } else {
            // JSON but no "report" field — treat the raw body as binary
            body_bytes.to_vec()
        }
    } else {
        // Not JSON — treat as raw binary
        body_bytes.to_vec()
    };

    let report = SnpReport::from_bytes(&raw_report)?;

    // If the caller provided report_data, verify it matches what's in the report
    // (some providers embed it, others require a separate request parameter)
    if let Some(data) = report_data {
        if report.report_data != *data {
            return Err(SealError::AttestationFailed(
                "report_data mismatch: GCP report does not contain expected data".into(),
            ));
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_dev_sev_guest_not_available() {
        let result = get_report_dev_sev_guest(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            SealError::ProviderError(msg) => {
                assert!(msg.contains("only available on Linux"));
            }
            other => panic!("expected ProviderError, got: {other:?}"),
        }
    }
}
