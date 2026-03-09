//! Hardware attestation report retrieval.
//!
//! Supports two provider backends:
//! - `/dev/sev-guest` ioctl (bare-metal SEV-SNP hosts: OVHcloud, Hetzner, etc.)
//! - GCP Confidential VM metadata endpoint

use crate::snp_report::SnpReport;
#[cfg(target_os = "linux")]
use crate::snp_report::REPORT_TOTAL_SIZE;
use crate::SealError;

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
    let raw_report = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
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
            tracing::warn!(
                "GCP report_data does not match requested data — \
                 GCP may not support custom report_data via this endpoint"
            );
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
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
