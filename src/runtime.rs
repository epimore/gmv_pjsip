use std::ffi::CString;
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};

use gmv_pjsip_sys as sys;

use crate::error::{status_to_result, PjError, Result};

static PJ_RUNTIME_ALIVE: AtomicBool = AtomicBool::new(false);

/// Owns pjlib/pjsip global initialization, caching pool, endpoint, transaction layer and UA layer.
///
/// Create one instance at process startup and keep it alive while SIP code is running.
///
/// This layer intentionally initializes only SIP-control modules. RTP/PS/FLV/HLS/DASH media stays in gmv.
pub struct PjRuntime {
    cpool: Box<sys::pj_caching_pool>,
    endpt: NonNull<sys::pjsip_endpoint>,
}

// PJSIP itself is C code with its own internal locking. The endpoint pointer may be shared by higher
// level gmv services, but callers must still serialize endpoint mutation where required.
unsafe impl Send for PjRuntime {}
unsafe impl Sync for PjRuntime {}

impl PjRuntime {
    pub fn new(name: &str) -> Result<Self> {
        if PJ_RUNTIME_ALIVE.swap(true, Ordering::SeqCst) {
            return Err(PjError::Unsupported(
                "PjRuntime::new() must be called once; share it with Arc<PjRuntime>",
            ));
        }

        let init_result = unsafe { status_to_result(sys::pj_init()) };
        if let Err(err) = init_result {
            PJ_RUNTIME_ALIVE.store(false, Ordering::SeqCst);
            return Err(err);
        }

        let util_result = unsafe { status_to_result(sys::pjlib_util_init()) };
        if let Err(err) = util_result {
            unsafe { sys::pj_shutdown() };
            PJ_RUNTIME_ALIVE.store(false, Ordering::SeqCst);
            return Err(err);
        }

        let mut cpool: Box<sys::pj_caching_pool> = Box::new(unsafe { mem::zeroed() });
        unsafe {
            sys::pj_caching_pool_init(cpool.as_mut(), ptr::null(), 0);
        }

        let mut endpt: *mut sys::pjsip_endpoint = ptr::null_mut();
        let cname = CString::new(name)?;
        let create_result = unsafe {
            status_to_result(sys::pjsip_endpt_create(
                &mut cpool.factory,
                cname.as_ptr(),
                &mut endpt,
            ))
        };
        if let Err(err) = create_result {
            unsafe {
                sys::pj_caching_pool_destroy(cpool.as_mut());
                sys::pj_shutdown();
            }
            PJ_RUNTIME_ALIVE.store(false, Ordering::SeqCst);
            return Err(err);
        }

        let endpt = NonNull::new(endpt).ok_or(PjError::Null("pjsip_endpt_create"))?;

        unsafe {
            status_to_result(sys::pjsip_tsx_layer_init_module(endpt.as_ptr()))?;
            status_to_result(sys::pjsip_ua_init_module(endpt.as_ptr(), ptr::null_mut()))?;
        }

        Ok(Self { cpool, endpt })
    }

    #[inline]
    pub fn endpoint_ptr(&self) -> *mut sys::pjsip_endpoint {
        self.endpt.as_ptr()
    }

    #[inline]
    pub fn pool_factory_ptr(&self) -> *mut sys::pj_pool_factory {
        // pjsip APIs expect pj_pool_factory*. pj_caching_pool has public `factory` field in pjlib.
        &self.cpool.factory as *const _ as *mut sys::pj_pool_factory
    }

    pub fn create_pool(&self, name: &str, initial: usize, increment: usize) -> Result<PjPool> {
        let cname = CString::new(name)?;
        let pool = unsafe {
            sys::pj_pool_create(
                self.pool_factory_ptr(),
                cname.as_ptr(),
                initial as sys::pj_size_t,
                increment as sys::pj_size_t,
                None,
            )
        };

        let pool = NonNull::new(pool).ok_or(PjError::Null("pj_pool_create"))?;
        Ok(PjPool { pool })
    }
}

impl Drop for PjRuntime {
    fn drop(&mut self) {
        unsafe {
            sys::pjsip_endpt_destroy(self.endpt.as_ptr());
            sys::pj_caching_pool_destroy(self.cpool.as_mut());
            sys::pj_shutdown();
        }
        PJ_RUNTIME_ALIVE.store(false, Ordering::SeqCst);
    }
}

pub struct PjPool {
    pool: NonNull<sys::pj_pool_t>,
}

impl PjPool {
    #[inline]
    pub fn as_ptr(&self) -> *mut sys::pj_pool_t {
        self.pool.as_ptr()
    }
}

impl Drop for PjPool {
    fn drop(&mut self) {
        unsafe { sys::pj_pool_release(self.pool.as_ptr()) };
    }
}
