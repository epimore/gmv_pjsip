//! FFI-ready boundary for the full PJSIP server-auth path.
//!
//! `pjsip_auth_srv_verify()` requires `pjsip_rx_data *` and
//! `pjsip_auth_srv_challenge2()` requires `pjsip_tx_data *`. The current GMV
//! flow still parses incoming packets into Rust `SipMessage`, so those raw PJSIP
//! handles are not available yet. This module intentionally defines the future
//! boundary to prevent the safe layer from growing another home-made auth stack.
//!
//! Next step:
//! - parse bytes through PJSIP and retain `PjRxDataHandle` until response build;
//! - initialize `pjsip_auth_srv` with an `AuthCredentialProvider` callback;
//! - call `pjsip_auth_srv_verify()` for REGISTER/MESSAGE/INVITE;
//! - call `pjsip_auth_srv_challenge2()` when the status is 401/407.

use std::marker::PhantomData;

use crate::auth::AuthAlgorithm;
use crate::error::{Result, SipError};

pub struct PjRxDataHandle<'a> {
    pub raw: *mut gmv_pjsip_sys::pjsip_rx_data,
    _lifetime: PhantomData<&'a mut gmv_pjsip_sys::pjsip_rx_data>,
}

pub struct PjTxDataHandle<'a> {
    pub raw: *mut gmv_pjsip_sys::pjsip_tx_data,
    _lifetime: PhantomData<&'a mut gmv_pjsip_sys::pjsip_tx_data>,
}

pub struct PjAuthServer;

impl PjAuthServer {
    pub fn verify_rdata(&self, _rdata: PjRxDataHandle<'_>) -> Result<()> {
        Err(SipError::AuthFailed(
            "PJSIP rdata auth path is reserved; current adapter uses PJSIP digest shim until parser retains pjsip_rx_data".into(),
        ))
    }

    pub fn challenge_tdata(&self, _tdata: PjTxDataHandle<'_>, _algorithm: AuthAlgorithm) -> Result<()> {
        Err(SipError::AuthFailed(
            "PJSIP tdata challenge path is reserved; current adapter builds textual challenge while digest verification uses PJSIP".into(),
        ))
    }
}
