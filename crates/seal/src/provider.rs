//! Hardware attestation report retrieval and key derivation.
//!
//! Uses the `/dev/sev-guest` ioctl interface (Linux kernel 6.1+, AMD SEV-SNP).
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

/// Fetch an attestation report from the local hardware via `/dev/sev-guest` ioctl.
///
/// `report_data`: optional 64-byte user data to include in the report.
pub async fn get_attestation_report(
    report_data: Option<&[u8; 64]>,
) -> Result<SnpReport, SealError> {
    get_report_sev_guest(report_data)
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
    //
    // struct snp_guest_request_ioctl (from kernel headers, naturally aligned):
    //   u8  msg_version;   // offset 0 (+ 7 bytes padding)
    //   u64 req_data;      // offset 8
    //   u64 resp_data;     // offset 16
    //   u64 exitinfo2;     // offset 24
    //   Total: 32 bytes → _IOWR('S', 0x1, 32) = 0xC020_5301
    const SNP_GET_DERIVED_KEY: libc::c_ulong = 0xC020_5301;

    // Payload: request for a derived key (matches kernel's snp_derived_key_req)
    #[repr(C)]
    struct SnpDerivedKeyReq {
        root_key_select: u32, // 0 = VCEK, 1 = VMRK
        rsvd: u32,
        guest_field_select: u64, // bitmask of fields to mix in
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    }

    // Payload: response containing the derived key
    #[repr(C)]
    struct SnpDerivedKeyResp {
        data: [u8; 64],
    }

    // ioctl wrapper (naturally aligned, NOT packed)
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

    let mut req = SnpDerivedKeyReq {
        root_key_select: 0, // VCEK — chip-unique root key
        rsvd: 0,
        guest_field_select: field_select,
        vmpl: 0,
        guest_svn: 0,
        tcb_version: 0,
    };

    let mut resp = SnpDerivedKeyResp { data: [0u8; 64] };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &mut req as *mut SnpDerivedKeyReq as u64,
        resp_data: &mut resp as *mut SnpDerivedKeyResp as u64,
        exitinfo2: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SNP_GET_DERIVED_KEY,
            &mut ioctl_req as *mut SnpGuestRequestIoctl,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SealError::ProviderError(format!(
            "SNP_GET_DERIVED_KEY ioctl failed: {errno}"
        )));
    }

    // Check firmware error (lower 32 bits of exitinfo2)
    let fw_err = ioctl_req.exitinfo2 & 0xFFFF_FFFF;
    if fw_err != 0 {
        return Err(SealError::ProviderError(format!(
            "SNP_GET_DERIVED_KEY firmware error: 0x{fw_err:X}"
        )));
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
// /dev/sev-guest ioctl (Linux kernel 6.1+, AMD SEV-SNP)
// ---------------------------------------------------------------------------

/// MSG_REPORT_RSP header size (status + report_size + reserved).
/// AMD SEV-SNP Firmware ABI, Table 23: the firmware response places a 32-byte
/// header before the actual attestation report.
#[cfg(target_os = "linux")]
const MSG_REPORT_RSP_HEADER_SIZE: usize = 32;

#[cfg(target_os = "linux")]
fn get_report_sev_guest(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
    // struct is naturally aligned, 32 bytes → _IOWR('S', 0x0, 32) = 0xC020_5300
    const SNP_GET_REPORT: libc::c_ulong = 0xC020_5300;

    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        rsvd: [u8; 28],
    }

    #[repr(C)]
    struct SnpReportResp {
        data: [u8; 4000],
    }

    // Naturally aligned ioctl wrapper (32 bytes)
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

    let mut resp = SnpReportResp { data: [0u8; 4000] };

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
            SNP_GET_REPORT,
            &mut ioctl_req as *mut SnpGuestRequestIoctl,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SealError::ProviderError(format!(
            "SNP_GET_REPORT ioctl failed: {errno}"
        )));
    }

    // The firmware response (MSG_REPORT_RSP) has a 32-byte header:
    //   status (4) + report_size (4) + reserved (24)
    // The actual SNP attestation report starts at offset 32.
    let report_start = MSG_REPORT_RSP_HEADER_SIZE;
    let report_end = report_start + REPORT_TOTAL_SIZE;

    if resp.data.len() < report_end {
        return Err(SealError::ProviderError(format!(
            "SNP report response too small: {} bytes (need {} + {} header)",
            resp.data.len(),
            REPORT_TOTAL_SIZE,
            MSG_REPORT_RSP_HEADER_SIZE
        )));
    }

    // Check firmware status (first 4 bytes of response)
    let fw_status = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
    if fw_status != 0 {
        return Err(SealError::ProviderError(format!(
            "SNP_GET_REPORT firmware error: status=0x{fw_status:X}"
        )));
    }

    SnpReport::from_bytes(&resp.data[report_start..report_end])
}

#[cfg(not(target_os = "linux"))]
fn get_report_sev_guest(_report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    Err(SealError::ProviderError(
        "SEV-SNP attestation only available on Linux".into(),
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_not_available_on_non_linux() {
        let result = get_report_sev_guest(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            SealError::ProviderError(msg) => {
                assert!(msg.contains("only available on Linux"));
            }
            other => panic!("expected ProviderError, got: {other:?}"),
        }
    }
}
