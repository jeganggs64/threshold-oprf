//! Hardware attestation report retrieval and key derivation.
//!
//! Supports two provider backends (auto-detected):
//! - TSM configfs (`/sys/kernel/config/tsm/report/`) — Linux kernel 6.7+
//! - `/dev/sev-guest` ioctl — older kernels (< 6.7)
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
    /// Auto-detect: TSM configfs (kernel 6.7+) → /dev/sev-guest ioctl fallback.
    DevSevGuest,
    /// Alias for DevSevGuest — GCP, Azure, and AWS all use the same kernel
    /// interfaces. The old GCP metadata endpoint does not exist.
    #[deprecated(note = "Use DevSevGuest — GCP uses the same kernel interface")]
    GcpMetadata,
}

/// Fetch an attestation report from the local hardware.
///
/// Auto-detects the kernel interface: tries TSM configfs first (kernel 6.7+),
/// then falls back to the legacy `/dev/sev-guest` ioctl.
///
/// `report_data`: optional 64-byte user data to include in the report.
pub async fn get_attestation_report(
    _provider: SnpProvider,
    report_data: Option<&[u8; 64]>,
) -> Result<SnpReport, SealError> {
    // All providers now use the same auto-detect logic
    get_report_auto(report_data)
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

    // SNP_GET_DERIVED_KEY = _IOWR('S', 0x1, struct snp_guest_request_ioctl)
    // The ioctl number encodes the size of snp_guest_request_ioctl, which
    // changed between kernel versions:
    //
    // Kernel 6.7+: struct is __packed__, 33 bytes (added fw_err field)
    //   _IOWR('S', 0x1, 33) = 0xC021_5301
    //
    // Kernel < 6.7: struct is __packed__, 25 bytes (no fw_err)
    //   _IOWR('S', 0x1, 25) = 0xC019_5301
    const SNP_GET_DERIVED_KEY_V2: libc::c_ulong = 0xC021_5301; // kernel 6.7+
    const SNP_GET_DERIVED_KEY_V1: libc::c_ulong = 0xC019_5301; // kernel < 6.7

    // Payload: request for a derived key
    #[repr(C)]
    struct SnpDerivedKeyReq {
        root_key_select: u32,
        reserved: u32,
        guest_field_select: u64,
    }

    // Payload: response containing the derived key
    #[repr(C)]
    struct SnpDerivedKeyResp {
        data: [u8; 64],
    }

    // Kernel 6.7+: snp_guest_request_ioctl with fw_err (33 bytes packed)
    #[repr(C, packed)]
    struct SnpGuestRequestIoctlV2 {
        msg_version: u8,
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
        fw_err: u64,
    }

    // Kernel < 6.7: snp_guest_request_ioctl without fw_err (25 bytes packed)
    #[repr(C, packed)]
    struct SnpGuestRequestIoctlV1 {
        msg_version: u8,
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
    }

    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| SealError::ProviderError(format!("failed to open /dev/sev-guest: {e}")))?;

    let mut req = SnpDerivedKeyReq {
        root_key_select: 0, // VCEK — chip-unique root key
        reserved: 0,
        guest_field_select: field_select,
    };

    let mut resp = SnpDerivedKeyResp { data: [0u8; 64] };

    // Try kernel 6.7+ ioctl first (with fw_err field)
    let mut ioctl_v2 = SnpGuestRequestIoctlV2 {
        msg_version: 1,
        req_data: &mut req as *mut SnpDerivedKeyReq as u64,
        resp_data: &mut resp as *mut SnpDerivedKeyResp as u64,
        exitinfo2: 0,
        fw_err: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SNP_GET_DERIVED_KEY_V2,
            &mut ioctl_v2 as *mut SnpGuestRequestIoctlV2,
        )
    };

    if ret == 0 {
        let fw_err = ioctl_v2.fw_err;
        if fw_err != 0 {
            return Err(SealError::ProviderError(format!(
                "SNP_GET_DERIVED_KEY firmware error: 0x{fw_err:X}"
            )));
        }
    } else {
        let errno_v2 = std::io::Error::last_os_error();

        // If ENOTTY (ioctl not recognized), try older kernel ABI
        if errno_v2.raw_os_error() == Some(libc::ENOTTY) {
            tracing::info!("SNP_GET_DERIVED_KEY v2 ioctl not supported, trying v1 (kernel < 6.7)");

            // Reset payloads
            req.root_key_select = 0;
            req.reserved = 0;
            req.guest_field_select = field_select;
            resp.data = [0u8; 64];

            let mut ioctl_v1 = SnpGuestRequestIoctlV1 {
                msg_version: 1,
                req_data: &mut req as *mut SnpDerivedKeyReq as u64,
                resp_data: &mut resp as *mut SnpDerivedKeyResp as u64,
                exitinfo2: 0,
            };

            let ret = unsafe {
                libc::ioctl(
                    fd.as_raw_fd(),
                    SNP_GET_DERIVED_KEY_V1,
                    &mut ioctl_v1 as *mut SnpGuestRequestIoctlV1,
                )
            };

            if ret != 0 {
                let errno_v1 = std::io::Error::last_os_error();
                return Err(SealError::ProviderError(format!(
                    "SNP_GET_DERIVED_KEY ioctl failed (tried v2: {errno_v2}, v1: {errno_v1})"
                )));
            }
        } else {
            return Err(SealError::ProviderError(format!(
                "SNP_GET_DERIVED_KEY ioctl failed: {errno_v2}"
            )));
        }
    }

    // Extract the first 32 bytes as the AES-256 key
    let mut key = [0u8; 32];
    key.copy_from_slice(&resp.data[..32]);

    // Zero out the response buffer
    resp.data.fill(0);

    Ok(Zeroizing::new(key))
}

#[cfg(not(target_os = "linux"))]
pub fn get_derived_key(_field_select: u64) -> Result<Zeroizing<[u8; 32]>, SealError> {
    Err(SealError::ProviderError(
        "SNP_GET_DERIVED_KEY only available on Linux".into(),
    ))
}

// ---------------------------------------------------------------------------
// Auto-detect provider: TSM configfs (kernel 6.7+) → /dev/sev-guest fallback
// ---------------------------------------------------------------------------

/// TSM configfs base path (available on Linux kernel 6.7+).
#[cfg(target_os = "linux")]
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

#[cfg(target_os = "linux")]
fn get_report_auto(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    // Try TSM configfs first (kernel 6.7+)
    if std::path::Path::new(TSM_REPORT_PATH).exists() {
        tracing::info!("Using TSM configfs interface for attestation report");
        match get_report_tsm_configfs(report_data) {
            Ok(report) => return Ok(report),
            Err(e) => {
                tracing::warn!("TSM configfs failed ({e}), falling back to /dev/sev-guest ioctl");
            }
        }
    }

    // Fallback: legacy /dev/sev-guest ioctl (kernel < 6.7)
    tracing::info!("Using /dev/sev-guest ioctl for attestation report");
    get_report_dev_sev_guest_ioctl(report_data)
}

#[cfg(not(target_os = "linux"))]
fn get_report_auto(_report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    Err(SealError::ProviderError(
        "SEV-SNP attestation only available on Linux".into(),
    ))
}

// ---------------------------------------------------------------------------
// TSM configfs provider (Linux kernel 6.7+)
// ---------------------------------------------------------------------------

/// Get an attestation report via the TSM configfs interface.
///
/// Flow:
///   1. mkdir /sys/kernel/config/tsm/report/<unique-name>
///   2. Write 64-byte report_data to <name>/inblob
///   3. Read binary attestation report from <name>/outblob
///   4. rmdir <name>
#[cfg(target_os = "linux")]
fn get_report_tsm_configfs(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    use std::fs;
    use std::io::Write;

    // Use a unique directory name to avoid collisions
    let name = format!(
        "toprf-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let report_dir = format!("{TSM_REPORT_PATH}/{name}");

    // Step 1: Create the report entry
    fs::create_dir(&report_dir).map_err(|e| {
        SealError::ProviderError(format!("failed to create TSM report dir {report_dir}: {e}"))
    })?;

    // Ensure cleanup on all exit paths
    let _cleanup = scopeguard::guard((), |_| {
        let _ = std::fs::remove_dir(&report_dir);
    });

    // Step 2: Write report_data (64 bytes) to inblob
    let inblob_path = format!("{report_dir}/inblob");
    let blob_data = report_data.map(|d| d.as_slice()).unwrap_or(&[0u8; 64]);
    let mut f = fs::File::create(&inblob_path).map_err(|e| {
        SealError::ProviderError(format!("failed to open {inblob_path}: {e}"))
    })?;
    f.write_all(blob_data).map_err(|e| {
        SealError::ProviderError(format!("failed to write inblob: {e}"))
    })?;
    drop(f);

    // Step 3: Read the attestation report from outblob
    let outblob_path = format!("{report_dir}/outblob");
    let report_bytes = fs::read(&outblob_path).map_err(|e| {
        SealError::ProviderError(format!("failed to read {outblob_path}: {e}"))
    })?;

    tracing::info!(
        report_size = report_bytes.len(),
        "TSM configfs: read attestation report"
    );

    if report_bytes.len() < REPORT_TOTAL_SIZE {
        return Err(SealError::ProviderError(format!(
            "TSM report too small: {} bytes (expected >= {REPORT_TOTAL_SIZE})",
            report_bytes.len()
        )));
    }

    SnpReport::from_bytes(&report_bytes[..REPORT_TOTAL_SIZE])
}

// ---------------------------------------------------------------------------
// /dev/sev-guest ioctl fallback (Linux kernel < 6.7)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn get_report_dev_sev_guest_ioctl(
    report_data: Option<&[u8; 64]>,
) -> Result<SnpReport, SealError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
    // Kernel 6.7+: size 33 (packed, with fw_err)
    // Kernel < 6.7: size 25 (packed, no fw_err)
    const SNP_GET_REPORT_V2: libc::c_ulong = 0xC021_5300; // kernel 6.7+
    const SNP_GET_REPORT_V1: libc::c_ulong = 0xC019_5300; // kernel < 6.7

    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        rsvd: [u8; 28],
    }

    #[repr(C)]
    struct SnpReportResp {
        status: u32,
        report_size: u32,
        rsvd: [u8; 24],
        report: [u8; 4000],
    }

    // Kernel 6.7+: packed with fw_err (33 bytes)
    #[repr(C, packed)]
    struct SnpGuestRequestIoctlV2 {
        msg_version: u8,
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
        fw_err: u64,
    }

    // Kernel < 6.7: packed without fw_err (25 bytes)
    #[repr(C, packed)]
    struct SnpGuestRequestIoctlV1 {
        msg_version: u8,
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

    // Try v2 ioctl first (kernel 6.7+)
    let mut ioctl_v2 = SnpGuestRequestIoctlV2 {
        msg_version: 1,
        req_data: &req as *const SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
        fw_err: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SNP_GET_REPORT_V2,
            &mut ioctl_v2 as *mut SnpGuestRequestIoctlV2,
        )
    };

    if ret != 0 {
        let errno_v2 = std::io::Error::last_os_error();
        if errno_v2.raw_os_error() == Some(libc::ENOTTY) {
            // Try v1 ioctl (kernel < 6.7)
            let mut ioctl_v1 = SnpGuestRequestIoctlV1 {
                msg_version: 1,
                req_data: &req as *const SnpReportReq as u64,
                resp_data: &mut resp as *mut SnpReportResp as u64,
                exitinfo2: 0,
            };

            let ret = unsafe {
                libc::ioctl(
                    fd.as_raw_fd(),
                    SNP_GET_REPORT_V1,
                    &mut ioctl_v1 as *mut SnpGuestRequestIoctlV1,
                )
            };

            if ret != 0 {
                let errno_v1 = std::io::Error::last_os_error();
                return Err(SealError::ProviderError(format!(
                    "SNP_GET_REPORT ioctl failed (tried v2: {errno_v2}, v1: {errno_v1})"
                )));
            }
        } else {
            return Err(SealError::ProviderError(format!(
                "SNP_GET_REPORT ioctl failed: {errno_v2}"
            )));
        }
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

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_not_available_on_non_linux() {
        let result = get_report_auto(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            SealError::ProviderError(msg) => {
                assert!(msg.contains("only available on Linux"));
            }
            other => panic!("expected ProviderError, got: {other:?}"),
        }
    }
}
