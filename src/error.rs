use thiserror::Error;

#[derive(Debug, Error)]
pub enum SipError {
    #[error("invalid SIP packet: {0}")]
    InvalidPacket(String),
    #[error("missing required SIP header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid SIP header `{name}`: {reason}")]
    InvalidHeader { name: &'static str, reason: String },
    #[error("unsupported SIP method: {0}")]
    UnsupportedMethod(String),
    #[error("SIP dialog not found: {0}")]
    DialogNotFound(String),
    #[error("SIP call not found: {0}")]
    CallNotFound(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("internal SIP error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, SipError>;
