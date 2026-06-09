//! Error handling for the safe `gmv_pjsip` wrapper.
//!
//! Keep all raw pjproject status/error conversion in this module so business
//! crates never depend on `gmv_pjsip_sys` directly.

use std::ffi::CStr;

use gmv_pjsip_sys as sys;

pub type Result<T> = std::result::Result<T, PjError>;

#[derive(Debug, thiserror::Error)]
pub enum PjError {
    #[error("pjproject error {status}: {message}")]
    Status { status: i32, message: String },

    #[error("SIP parse error: {0}")]
    Parse(String),

    #[error("SIP protocol error: {0}")]
    Protocol(String),

    #[error("transaction error: {0}")]
    Transaction(String),

    #[error("dialog error: {0}")]
    Dialog(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("invalid utf8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("nul byte in string: {0}")]
    Nul(#[from] std::ffi::NulError),

    #[error("poisoned lock: {0}")]
    Poisoned(&'static str),
}

pub fn status_to_result(status: sys::pj_status_t) -> Result<()> {
    if status == 0 {
        return Ok(());
    }

    Err(PjError::Status {
        status,
        message: pj_strerror(status),
    })
}

pub fn pj_strerror(status: sys::pj_status_t) -> String {
    let mut buf = [0i8; 256];

    unsafe {
        sys::pj_strerror(status, buf.as_mut_ptr(), buf.len() as sys::pj_size_t);
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

pub(crate) fn poisoned(name: &'static str) -> PjError {
    PjError::Poisoned(name)
}
