//! pjproject process/runtime initialization.
//!
//! This module intentionally exposes a small safe surface:
//! - initialize pjlib / pjlib-util once;
//! - own a pj caching pool factory;
//! - validate raw SIP bytes with `pjsip_parse_msg()`.
//!
//! Higher level SIP transaction/dialog state is kept in Rust-side wrappers in
//! this iteration. The struct layout leaves room for adding a real
//! `pjsip_endpoint` + custom transport bridge later without changing session's
//! public dependency boundary.

use std::ffi::CString;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use gmv_pjsip_sys as sys;

use crate::error::{poisoned, status_to_result, PjError, Result};

static PJ_GLOBAL_INITED: AtomicBool = AtomicBool::new(false);
static PJ_GLOBAL_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct PjRuntime {
    inner: Arc<PjRuntimeInner>,
}

#[derive(Debug)]
struct PjRuntimeInner {
    caching_pool: Mutex<Box<sys::pj_caching_pool>>,
    owns_global_init: bool,
}

impl Clone for PjRuntime {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl PjRuntime {
    /// Initialize pjproject global state and create one caching pool factory.
    ///
    /// Create one `PjRuntime` during process startup and share it through
    /// `SipEndpoint`. Calling this repeatedly is tolerated, but the first
    /// owner performs global `pj_shutdown()` on drop.
    pub fn init() -> Result<Self> {
        let _guard = PJ_GLOBAL_LOCK.lock().map_err(|_| poisoned("PJ_GLOBAL_LOCK"))?;

        let owns_global_init = if !PJ_GLOBAL_INITED.load(Ordering::SeqCst) {
            unsafe {
                status_to_result(sys::pj_init())?;
                status_to_result(sys::pjlib_util_init())?;
            }
            PJ_GLOBAL_INITED.store(true, Ordering::SeqCst);
            true
        } else {
            false
        };

        let mut caching_pool = Box::<sys::pj_caching_pool>::new(unsafe { std::mem::zeroed() });
        unsafe {
            sys::pj_caching_pool_init(caching_pool.as_mut(), ptr::null(), 0);
        }

        Ok(Self {
            inner: Arc::new(PjRuntimeInner {
                caching_pool: Mutex::new(caching_pool),
                owns_global_init,
            }),
        })
    }

    /// Validate a SIP packet using pjproject's parser.
    ///
    /// The returned PJSIP message pointer is not exposed because it is tied to
    /// the temporary pool. Higher layers receive a Rust-owned `SipMessageView`
    /// from `message.rs`.
    pub fn validate_sip_packet(&self, raw: &[u8]) -> Result<()> {
        if raw.is_empty() {
            return Err(PjError::Parse("empty SIP packet".to_string()));
        }

        let pool_name = CString::new("gmv_pjsip_parse")?;
        let mut cp = self
            .inner
            .caching_pool
            .lock()
            .map_err(|_| poisoned("PjRuntime.caching_pool"))?;

        let pool = unsafe {
            sys::pj_pool_create(
                &mut cp.factory,
                pool_name.as_ptr(),
                4096,
                4096,
                None,
            )
        };

        if pool.is_null() {
            return Err(PjError::Status {
                status: -1,
                message: "pj_pool_create failed".to_string(),
            });
        }

        let parse_result = (|| {
            let mut buf = raw.to_vec();
            // pjsip_parse_msg() receives an explicit length, but keeping a NUL
            // guard is cheap and matches pjproject examples.
            buf.push(0);

            let msg = unsafe {
                sys::pjsip_parse_msg(
                    pool,
                    buf.as_mut_ptr() as *mut i8,
                    raw.len() as sys::pj_size_t,
                    ptr::null_mut(),
                )
            };

            if msg.is_null() {
                Err(PjError::Parse("pjsip_parse_msg failed".to_string()))
            } else {
                Ok(())
            }
        })();

        unsafe {
            sys::pj_pool_release(pool);
        }

        parse_result
    }
}

impl Drop for PjRuntimeInner {
    fn drop(&mut self) {
        if let Ok(mut cp) = self.caching_pool.lock() {
            unsafe {
                sys::pj_caching_pool_destroy(cp.as_mut());
            }
        }

        if self.owns_global_init {
            if let Ok(_guard) = PJ_GLOBAL_LOCK.lock() {
                if PJ_GLOBAL_INITED.swap(false, Ordering::SeqCst) {
                    unsafe {
                        sys::pj_shutdown();
                    }
                }
            }
        }
    }
}
