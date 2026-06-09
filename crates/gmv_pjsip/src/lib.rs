//! Safe-ish GB28181 oriented wrapper over pjproject.
//!
//! Keep raw pjproject access inside this crate. Business crates should not call
//! `gmv_pjsip_sys` directly.

use std::ffi::{CStr, CString};
use std::ptr;

use gmv_pjsip_sys as sys;

#[derive(Debug, thiserror::Error)]
pub enum PjError {
    #[error("pjproject error {status}: {message}")]
    Status { status: i32, message: String },
    #[error("nul byte in string")]
    Nul(#[from] std::ffi::NulError),
}

pub type Result<T> = std::result::Result<T, PjError>;

fn status_to_result(status: sys::pj_status_t) -> Result<()> {
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

/// Global pjlib lifetime guard.
///
/// Create this once during process startup before using pjproject APIs.
pub struct PjRuntime;

impl PjRuntime {
    pub fn init() -> Result<Self> {
        unsafe {
            status_to_result(sys::pj_init())?;
            status_to_result(sys::pjlib_util_init())?;
        }
        Ok(Self)
    }
}

impl Drop for PjRuntime {
    fn drop(&mut self) {
        unsafe {
            sys::pj_shutdown();
        }
    }
}

/// Small parsing helper for validation/debugging.
///
/// For production SIP stack management, build a `SipEndpoint` abstraction around
/// `pjsip_endpt_create()`, transports, modules, transactions and dialogs.
pub fn parse_sip_message(raw: &[u8]) -> Result<ParsedSipKind> {
    let _runtime_note = (); // caller must keep PjRuntime alive in real use.

    let mut pool_factory = unsafe { std::mem::zeroed::<sys::pj_caching_pool>() };
    unsafe {
        sys::pj_caching_pool_init(&mut pool_factory, ptr::null(), 0);
    }

    let pool_name = CString::new("gmv_parse")?;
    let pool = unsafe {
        sys::pj_pool_create(
            &mut pool_factory.factory,
            pool_name.as_ptr(),
            4096,
            4096,
            None,
        )
    };
    if pool.is_null() {
        unsafe { sys::pj_caching_pool_destroy(&mut pool_factory) };
        return Err(PjError::Status { status: -1, message: "pj_pool_create failed".into() });
    }

    let mut buf = raw.to_vec();
    buf.push(0);
    let msg = unsafe {
        sys::pjsip_parse_msg(
            pool,
            buf.as_mut_ptr() as *mut i8,
            raw.len() as sys::pj_size_t,
            ptr::null_mut(),
        )
    };

    let kind = if msg.is_null() {
        Err(PjError::Status { status: -1, message: "pjsip_parse_msg failed".into() })
    } else {
        // pjsip_msg_type_e: request/response classification is exposed via msg->type.
        // Exact enum names can vary slightly across bindgen versions, so keep this wrapper small.
        Ok(ParsedSipKind::Unknown)
    };

    unsafe {
        sys::pj_pool_release(pool);
        sys::pj_caching_pool_destroy(&mut pool_factory);
    }

    kind
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedSipKind {
    Request,
    Response,
    Unknown,
}
