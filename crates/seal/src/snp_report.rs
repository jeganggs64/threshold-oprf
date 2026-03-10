//! AMD SEV-SNP attestation report parsing.
//!
//! Parses the 1184-byte binary format defined by the AMD SEV-SNP
//! architecture specification. All multi-byte fields are little-endian.

use crate::SealError;

/// Size of the report body (everything before the signature).
pub const REPORT_BODY_SIZE: usize = 0x2A0; // 672

/// Total size of a complete SNP attestation report.
pub const REPORT_TOTAL_SIZE: usize = 0x4A0; // 1184

/// The only supported signature algorithm: ECDSA with P-384 and SHA-384.
pub const SIGNATURE_ALGO_ECDSA_P384: u32 = 1;

#[derive(Debug, Clone)]
pub struct SnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: u64,
    pub platform_info: u64,
    pub flags: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    pub launch_tcb: u64,
    /// Raw report body bytes (for signature verification).
    pub body_bytes: Vec<u8>,
    /// ECDSA-P384 signature r component (48 bytes).
    pub signature_r: [u8; 48],
    /// ECDSA-P384 signature s component (48 bytes).
    pub signature_s: [u8; 48],
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from a byte slice at the given offset.
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Copy a fixed-size array from a byte slice at the given offset.
fn read_array<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

impl SnpReport {
    /// Parse an AMD SEV-SNP attestation report from its binary representation.
    ///
    /// The input must be exactly `REPORT_TOTAL_SIZE` (1184) bytes. The parser
    /// validates that:
    /// - `version` >= 2 (SNP reports are version 2+)
    /// - `signature_algo` == 1 (ECDSA-P384-SHA384)
    pub fn from_bytes(data: &[u8]) -> Result<Self, SealError> {
        if data.len() < REPORT_TOTAL_SIZE {
            return Err(SealError::InvalidReport(format!(
                "report too short: expected {} bytes, got {}",
                REPORT_TOTAL_SIZE,
                data.len()
            )));
        }

        let version = read_u32(data, 0x000);
        if version < 2 {
            return Err(SealError::InvalidReport(format!(
                "unsupported report version: {version} (expected >= 2)"
            )));
        }

        let signature_algo = read_u32(data, 0x034);
        if signature_algo != SIGNATURE_ALGO_ECDSA_P384 {
            return Err(SealError::InvalidReport(format!(
                "unsupported signature algorithm: {signature_algo} (expected {SIGNATURE_ALGO_ECDSA_P384})"
            )));
        }

        let body_bytes = data[..REPORT_BODY_SIZE].to_vec();
        let signature_r: [u8; 48] = read_array(data, 0x2A0);
        let signature_s: [u8; 48] = read_array(data, 0x2A0 + 48);

        Ok(Self {
            version,
            guest_svn: read_u32(data, 0x004),
            policy: read_u64(data, 0x008),
            family_id: read_array(data, 0x010),
            image_id: read_array(data, 0x020),
            vmpl: read_u32(data, 0x030),
            signature_algo,
            current_tcb: read_u64(data, 0x038),
            platform_info: read_u64(data, 0x040),
            flags: read_u32(data, 0x048),
            report_data: read_array(data, 0x050),
            measurement: read_array(data, 0x090),
            host_data: read_array(data, 0x0C0),
            id_key_digest: read_array(data, 0x0E0),
            author_key_digest: read_array(data, 0x110),
            report_id: read_array(data, 0x140),
            report_id_ma: read_array(data, 0x160),
            reported_tcb: read_u64(data, 0x180),
            // chip_id at 0x1A0: after reported_tcb (0x180, 8 bytes) + 24 bytes reserved.
            // Per AMD SEV-SNP ABI spec Table 21 (ATTESTATION_REPORT structure).
            chip_id: read_array(data, 0x1A0),
            committed_tcb: read_u64(data, 0x1E0),
            current_build: data[0x1E8],
            current_minor: data[0x1E9],
            current_major: data[0x1EA],
            launch_tcb: read_u64(data, 0x1F0),
            body_bytes,
            signature_r,
            signature_s,
        })
    }

    /// Returns the 48-byte measurement (launch digest) of the guest VM.
    pub fn measurement(&self) -> &[u8; 48] {
        &self.measurement
    }

    /// Returns the guest policy.
    pub fn policy(&self) -> u64 {
        self.policy
    }

    /// Returns the chip ID as a lowercase hex string.
    pub fn chip_id_hex(&self) -> String {
        hex::encode(self.chip_id)
    }

    /// Extracts the TCB component versions from `current_tcb`.
    ///
    /// Per AMD SEV-SNP spec (Table 3, TCB_VERSION), the u64 is laid out
    /// in little-endian bytes as:
    /// - byte 0: BOOT_LOADER SVN
    /// - byte 1: TEE (PSP OS) SVN
    /// - bytes 2-5: reserved
    /// - byte 6: SNP SVN
    /// - byte 7: MICROCODE SVN
    ///
    /// Returns `(bl_svn, tee_svn, snp_svn, ucode_svn)`.
    pub fn tcb_parts(&self) -> (u8, u8, u8, u8) {
        let bytes = self.current_tcb.to_le_bytes();
        let bl_svn = bytes[0];
        let tee_svn = bytes[1];
        let snp_svn = bytes[6];
        let ucode_svn = bytes[7];
        (bl_svn, tee_svn, snp_svn, ucode_svn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 1184-byte SNP report for testing.
    fn build_synthetic_report() -> Vec<u8> {
        let mut report = vec![0u8; REPORT_TOTAL_SIZE];

        // version = 2
        report[0x000..0x004].copy_from_slice(&2u32.to_le_bytes());
        // guest_svn = 1
        report[0x004..0x008].copy_from_slice(&1u32.to_le_bytes());
        // policy = 0x30000
        report[0x008..0x010].copy_from_slice(&0x30000u64.to_le_bytes());
        // family_id
        report[0x010..0x020].copy_from_slice(&[0xAA; 16]);
        // image_id
        report[0x020..0x030].copy_from_slice(&[0xBB; 16]);
        // vmpl = 0
        report[0x030..0x034].copy_from_slice(&0u32.to_le_bytes());
        // signature_algo = 1 (ECDSA-P384)
        report[0x034..0x038].copy_from_slice(&1u32.to_le_bytes());
        // current_tcb per AMD spec (Table 3, TCB_VERSION):
        //   byte 0 = bl=0x03, byte 1 = tee=0x00, bytes 2-5 = reserved,
        //   byte 6 = snp=0x14, byte 7 = ucode=0x93
        let tcb: u64 = 0x03 | (0x14_u64 << 48) | (0x93_u64 << 56);
        report[0x038..0x040].copy_from_slice(&tcb.to_le_bytes());
        // platform_info
        report[0x040..0x048].copy_from_slice(&0x01u64.to_le_bytes());
        // flags
        report[0x048..0x04C].copy_from_slice(&0u32.to_le_bytes());
        // report_data — fill with 0x42
        report[0x050..0x090].copy_from_slice(&[0x42; 64]);
        // measurement — fill with 0xDD
        report[0x090..0x0C0].copy_from_slice(&[0xDD; 48]);
        // host_data at 0x0C0 (32 bytes)
        report[0x0C0..0x0E0].copy_from_slice(&[0xEE; 32]);
        // chip_id at 0x1A0 (64 bytes)
        for (i, byte) in report[0x1A0..0x1E0].iter_mut().enumerate() {
            *byte = i as u8;
        }
        // current_build, current_minor, current_major
        report[0x1E8] = 5;
        report[0x1E9] = 51;
        report[0x1EA] = 1;

        // signature r (48 bytes at 0x2A0)
        report[0x2A0..0x2D0].copy_from_slice(&[0x11; 48]);
        // signature s (48 bytes at 0x2D0)
        report[0x2D0..0x300].copy_from_slice(&[0x22; 48]);

        report
    }

    #[test]
    fn test_parse_synthetic_report() {
        let data = build_synthetic_report();
        let report = SnpReport::from_bytes(&data).expect("should parse synthetic report");

        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 1);
        assert_eq!(report.policy, 0x30000);
        assert_eq!(report.family_id, [0xAA; 16]);
        assert_eq!(report.image_id, [0xBB; 16]);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.signature_algo, SIGNATURE_ALGO_ECDSA_P384);
        assert_eq!(report.flags, 0);
        assert_eq!(report.report_data, [0x42; 64]);
        assert_eq!(report.measurement, [0xDD; 48]);
        assert_eq!(report.host_data, [0xEE; 32]);
        assert_eq!(report.current_build, 5);
        assert_eq!(report.current_minor, 51);
        assert_eq!(report.current_major, 1);
        assert_eq!(report.signature_r, [0x11; 48]);
        assert_eq!(report.signature_s, [0x22; 48]);
        assert_eq!(report.body_bytes.len(), REPORT_BODY_SIZE);
    }

    #[test]
    fn test_tcb_parts() {
        let data = build_synthetic_report();
        let report = SnpReport::from_bytes(&data).unwrap();
        let (bl, tee, snp, ucode) = report.tcb_parts();
        assert_eq!(ucode, 0x93);
        assert_eq!(snp, 0x14);
        assert_eq!(tee, 0x00);
        assert_eq!(bl, 0x03);
    }

    #[test]
    fn test_chip_id_hex() {
        let data = build_synthetic_report();
        let report = SnpReport::from_bytes(&data).unwrap();
        let hex_str = report.chip_id_hex();
        assert_eq!(hex_str.len(), 128); // 64 bytes = 128 hex chars
    }

    #[test]
    fn test_helpers() {
        let data = build_synthetic_report();
        let report = SnpReport::from_bytes(&data).unwrap();
        assert_eq!(report.measurement(), &[0xDD; 48]);
        assert_eq!(report.policy(), 0x30000);
    }

    #[test]
    fn test_report_too_short() {
        let data = vec![0u8; 100];
        let err = SnpReport::from_bytes(&data).unwrap_err();
        assert!(matches!(err, SealError::InvalidReport(_)));
    }

    #[test]
    fn test_bad_version() {
        let mut data = build_synthetic_report();
        // Set version to 1 (invalid)
        data[0x000..0x004].copy_from_slice(&1u32.to_le_bytes());
        let err = SnpReport::from_bytes(&data).unwrap_err();
        assert!(matches!(err, SealError::InvalidReport(_)));
    }

    #[test]
    fn test_bad_signature_algo() {
        let mut data = build_synthetic_report();
        // Set signature_algo to 99 (invalid)
        data[0x034..0x038].copy_from_slice(&99u32.to_le_bytes());
        let err = SnpReport::from_bytes(&data).unwrap_err();
        assert!(matches!(err, SealError::InvalidReport(_)));
    }
}
