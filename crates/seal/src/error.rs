use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealError {
    #[error("invalid report: {0}")]
    InvalidReport(String),

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("sealing failed: {0}")]
    SealingFailed(String),

    #[error("unsealing failed: {0}")]
    UnsealingFailed(String),

    #[error("provider error: {0}")]
    ProviderError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("key verification failed: k_i * G != expected verification share")]
    KeyVerificationFailed,
}
