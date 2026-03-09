pub mod snp_report;
pub mod attestation;
pub mod sealing;
pub mod provider;
pub mod error;

pub use error::SealError;

// v2 hardware-derived key sealing (MSG_KEY_REQ / SNP_GET_DERIVED_KEY)
pub use provider::{
    get_derived_key, SAFE_FIELD_SELECT,
    FIELD_GUEST_POLICY, FIELD_IMAGE_ID, FIELD_FAMILY_ID,
    FIELD_MEASUREMENT, FIELD_GUEST_SVN, FIELD_TCB_VERSION,
};
pub use sealing::{seal_derived, unseal_derived, parse_v2_header, detect_sealed_version};
