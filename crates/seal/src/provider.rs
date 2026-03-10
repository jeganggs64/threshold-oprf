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
// Auto-detect provider: TSM configfs (kernel 6.7+) → /dev/sev-guest → vTPM
// ---------------------------------------------------------------------------

/// TSM configfs base path (available on Linux kernel 6.7+).
/// Override via TSM_REPORT_PATH env var for containers where the host
/// configfs is bind-mounted to a different path.
#[cfg(target_os = "linux")]
fn tsm_report_path() -> String {
    std::env::var("TSM_REPORT_PATH").unwrap_or_else(|_| "/sys/kernel/config/tsm/report".to_string())
}

#[cfg(target_os = "linux")]
fn get_report_auto(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    // Try TSM configfs first (kernel 6.7+)
    let tsm_path = tsm_report_path();
    if std::path::Path::new(&tsm_path).exists() {
        tracing::info!("Using TSM configfs interface for attestation report");
        match get_report_tsm_configfs(report_data, &tsm_path) {
            Ok(report) => return Ok(report),
            Err(e) => {
                tracing::warn!("TSM configfs failed ({e}), falling back to /dev/sev-guest ioctl");
            }
        }
    }

    // Fallback 1: legacy /dev/sev-guest ioctl (kernel < 6.7)
    if std::path::Path::new("/dev/sev-guest").exists() {
        tracing::info!("Using /dev/sev-guest ioctl for attestation report");
        match get_report_dev_sev_guest_ioctl(report_data) {
            Ok(report) => return Ok(report),
            Err(e) => {
                tracing::warn!("/dev/sev-guest ioctl failed ({e}), falling back to vTPM");
            }
        }
    }

    // Fallback 2: Azure vTPM — reads pre-generated SNP report from HCL blob
    // in TPM NV index 0x01400001.  Custom report_data is NOT supported.
    tracing::info!("Trying vTPM (Azure HCL) for attestation report");
    get_report_vtpm(report_data)
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
fn get_report_tsm_configfs(
    report_data: Option<&[u8; 64]>,
    tsm_path: &str,
) -> Result<SnpReport, SealError> {
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
    let report_dir = format!("{tsm_path}/{name}");

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
    let mut f = fs::File::create(&inblob_path)
        .map_err(|e| SealError::ProviderError(format!("failed to open {inblob_path}: {e}")))?;
    f.write_all(blob_data)
        .map_err(|e| SealError::ProviderError(format!("failed to write inblob: {e}")))?;
    drop(f);

    // Step 3: Read the attestation report from outblob
    let outblob_path = format!("{report_dir}/outblob");
    let report_bytes = fs::read(&outblob_path)
        .map_err(|e| SealError::ProviderError(format!("failed to read {outblob_path}: {e}")))?;

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
fn get_report_dev_sev_guest_ioctl(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
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

    if resp.data.len() < REPORT_TOTAL_SIZE {
        return Err(SealError::ProviderError(format!(
            "SNP report too small: {} bytes (expected >= {REPORT_TOTAL_SIZE})",
            resp.data.len()
        )));
    }

    SnpReport::from_bytes(&resp.data[..REPORT_TOTAL_SIZE])
}

// ---------------------------------------------------------------------------
// Azure vTPM provider — reads SNP report from HCL blob in TPM NV index
// ---------------------------------------------------------------------------

/// Azure Confidential VMs don't expose /dev/sev-guest or functional TSM configfs.
/// Instead, the SNP attestation report is available through the vTPM: the
/// hypervisor stores an HCL (Host Compatibility Layer) report in TPM NV index
/// 0x01400001.  The HCL report wraps a standard AMD SNP attestation report.
///
/// Limitations:
/// - The report is pre-generated at boot; custom report_data is NOT embedded.
///   (report_data contains a hash of the HCL runtime JSON, not user-supplied data.)
/// - MSG_KEY_REQ (get_derived_key) is NOT available on Azure — use v1 sealing
///   (HKDF from measurement) instead of v2 (hardware-derived key).
#[cfg(target_os = "linux")]
fn get_report_vtpm(report_data: Option<&[u8; 64]>) -> Result<SnpReport, SealError> {
    if report_data.is_some() {
        tracing::warn!(
            "vTPM attestation: custom report_data is NOT supported on Azure; \
             the returned report contains the HCL runtime data hash instead"
        );
    }

    // Try /dev/tpmrm0 (resource manager) first, then /dev/tpm0
    let tpm_path = if std::path::Path::new("/dev/tpmrm0").exists() {
        "/dev/tpmrm0"
    } else if std::path::Path::new("/dev/tpm0").exists() {
        "/dev/tpm0"
    } else {
        return Err(SealError::ProviderError(
            "no TPM device found (/dev/tpmrm0 or /dev/tpm0)".into(),
        ));
    };

    tracing::info!(
        path = tpm_path,
        "vTPM: reading HCL report from NV index 0x01400001"
    );

    const HCL_NV_INDEX: u32 = 0x01400001;
    const HCL_HEADER_SIZE: usize = 32;

    // Read the HCL report from the TPM NV index (2600 bytes on Azure)
    let hcl_data = tpm2_nv_read_all(tpm_path, HCL_NV_INDEX, 2600)?;

    if hcl_data.len() < HCL_HEADER_SIZE + REPORT_TOTAL_SIZE {
        return Err(SealError::ProviderError(format!(
            "HCL report too small: {} bytes (need at least {})",
            hcl_data.len(),
            HCL_HEADER_SIZE + REPORT_TOTAL_SIZE
        )));
    }

    // Validate HCL header: magic "HCLA", report_type == 2 (SNP)
    if &hcl_data[0..4] != b"HCLA" {
        return Err(SealError::ProviderError(format!(
            "invalid HCL report magic: {:02x}{:02x}{:02x}{:02x}",
            hcl_data[0], hcl_data[1], hcl_data[2], hcl_data[3]
        )));
    }

    let report_type = u32::from_le_bytes(hcl_data[12..16].try_into().unwrap());
    if report_type != 2 {
        return Err(SealError::ProviderError(format!(
            "HCL report type {report_type} is not SNP (expected 2)"
        )));
    }

    // SNP report is embedded at offset 32 (after the HCL header)
    let snp_data = &hcl_data[HCL_HEADER_SIZE..HCL_HEADER_SIZE + REPORT_TOTAL_SIZE];

    tracing::info!(
        hcl_size = hcl_data.len(),
        snp_offset = HCL_HEADER_SIZE,
        "vTPM: extracted SNP report from HCL blob"
    );

    SnpReport::from_bytes(snp_data)
}

/// Read an NV index from the TPM, chunking if necessary (max 1024 bytes/read).
#[cfg(target_os = "linux")]
fn tpm2_nv_read_all(
    tpm_path: &str,
    nv_index: u32,
    total_size: usize,
) -> Result<Vec<u8>, SealError> {
    const MAX_CHUNK: usize = 1024;

    let mut result = Vec::with_capacity(total_size);
    while result.len() < total_size {
        let remaining = total_size - result.len();
        let chunk_size = remaining.min(MAX_CHUNK) as u16;
        let offset = result.len() as u16;

        let chunk = tpm2_nv_read_chunk(tpm_path, nv_index, chunk_size, offset)?;
        if chunk.is_empty() {
            break; // No more data
        }
        result.extend_from_slice(&chunk);
    }

    Ok(result)
}

/// Send a single TPM2_NV_Read command with owner auth (empty password).
///
/// Writes a raw TPM2 command to the device and reads the response.
/// This avoids any dependency on tpm2-tss or tpm2-tools.
#[cfg(target_os = "linux")]
fn tpm2_nv_read_chunk(
    tpm_path: &str,
    nv_index: u32,
    size: u16,
    offset: u16,
) -> Result<Vec<u8>, SealError> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};

    let mut tpm = OpenOptions::new()
        .read(true)
        .write(true)
        .open(tpm_path)
        .map_err(|e| SealError::ProviderError(format!("failed to open {tpm_path}: {e}")))?;

    // TPM2_NV_Read command with password session (owner auth, empty password)
    //
    // Layout (35 bytes total):
    //   Header (10):  tag(2) + commandSize(4) + commandCode(4)
    //   Handles (8):  authHandle(4) + nvIndex(4)
    //   Auth area:    authAreaSize(4) + session(9)
    //   Parameters:   size(2) + offset(2)
    const CMD_SIZE: u32 = 35;

    let mut cmd = Vec::with_capacity(CMD_SIZE as usize);
    cmd.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
    cmd.extend_from_slice(&CMD_SIZE.to_be_bytes());
    cmd.extend_from_slice(&0x0000_014Eu32.to_be_bytes()); // TPM2_CC_NV_Read
    cmd.extend_from_slice(&0x4000_0001u32.to_be_bytes()); // TPM_RH_OWNER
    cmd.extend_from_slice(&nv_index.to_be_bytes());
    cmd.extend_from_slice(&9u32.to_be_bytes()); // auth area size
    cmd.extend_from_slice(&0x4000_0009u32.to_be_bytes()); // TPM_RS_PW
    cmd.extend_from_slice(&0u16.to_be_bytes()); // nonce: empty
    cmd.push(0x01); // session attributes: continueSession
    cmd.extend_from_slice(&0u16.to_be_bytes()); // hmac: empty
    cmd.extend_from_slice(&size.to_be_bytes());
    cmd.extend_from_slice(&offset.to_be_bytes());

    debug_assert_eq!(cmd.len(), CMD_SIZE as usize);

    tpm.write_all(&cmd)
        .map_err(|e| SealError::ProviderError(format!("TPM2_NV_Read write failed: {e}")))?;

    // Read response (generous buffer)
    let mut resp = vec![0u8; 10 + 4 + 2 + size as usize + 64];
    let n = tpm
        .read(&mut resp)
        .map_err(|e| SealError::ProviderError(format!("TPM2_NV_Read read failed: {e}")))?;
    resp.truncate(n);

    if resp.len() < 10 {
        return Err(SealError::ProviderError(format!(
            "TPM2_NV_Read response too short: {n} bytes"
        )));
    }

    // Parse response header
    let response_code = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if response_code != 0 {
        return Err(SealError::ProviderError(format!(
            "TPM2_NV_Read failed: response code 0x{response_code:08X}"
        )));
    }

    // Response body: parameterSize(4) + TPM2B_MAX_NV_BUFFER { size(2) + data[] }
    if resp.len() < 16 {
        return Err(SealError::ProviderError(
            "TPM2_NV_Read response too short for data".into(),
        ));
    }

    let data_size = u16::from_be_bytes(resp[14..16].try_into().unwrap()) as usize;
    if resp.len() < 16 + data_size {
        return Err(SealError::ProviderError(format!(
            "TPM2_NV_Read response truncated: expected {} data bytes, got {}",
            data_size,
            resp.len() - 16
        )));
    }

    Ok(resp[16..16 + data_size].to_vec())
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
