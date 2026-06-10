use std::ffi::CStr;

use gmv_pjsip_sys as sys;

pub type Result<T> = std::result::Result<T, PjError>;

#[derive(Debug, thiserror::Error)]
pub enum PjError {
    #[error("pjproject error {status}: {message}")]
    Status { status: i32, message: String },

    #[error("pjproject returned null pointer: {0}")]
    Null(&'static str),

    #[error("invalid nul byte in string: {0}")]
    Nul(#[from] std::ffi::NulError),

    #[error("invalid SIP message: {0}")]
    InvalidSip(String),

    #[error("missing SIP header: {0}")]
    MissingHeader(&'static str),

    #[error("unsupported SIP flow: {0}")]
    Unsupported(&'static str),

    #[error("I/O level transport is not bound: {0}")]
    TransportNotBound(&'static str),
}

#[inline]
pub fn status_to_result(status: sys::pj_status_t) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(PjError::Status {
            status,
            message: pj_strerror(status),
        })
    }
}

pub fn pj_strerror(status: sys::pj_status_t) -> String {
    let mut buf = [0i8; 256];
    unsafe {
        // pj_strerror() always writes a NUL-terminated string when buf size > 0.
        sys::pj_strerror(status, buf.as_mut_ptr(), buf.len() as sys::pj_size_t);
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}
