//! Safe GB28181-oriented wrapper over pjproject.
//!
//! Design boundary:
//! - `gmv_pjsip_sys` mirrors raw pjproject C symbols.
//! - `gmv_pjsip` exposes safe Rust APIs for parser/builder/transaction/dialog.
//! - `session` should depend on `gmv_pjsip`, not `gmv_pjsip_sys`.
//!
//! Current scope:
//! 1. PJSIP-backed SIP packet validation through `pjsip_parse_msg()`.
//! 2. Centralized SIP builder functions with correct Content-Length.
//! 3. Rust-owned transaction/dialog state suitable for GB28181 idempotency.
//!
//! The public API is intentionally shaped so a future internal implementation
//! can switch transaction/dialog storage to PJSIP endpoint modules without
//! leaking raw pointers to business crates.

pub mod builder;
pub mod dialog;
pub mod endpoint;
pub mod error;
pub mod message;
pub mod runtime;
pub mod transaction;
pub mod transport;
mod sdp;
mod ffi;
mod auth;

pub use builder::{
    build_200_ok, build_400_bad_request, build_481, build_ack_for_invite_2xx, build_bye,
    build_request, build_response, new_branch, token, BuildRequestOptions, ResponseOptions,
};
pub use dialog::{DialogId, DialogState, DialogStore, InviteDialog, NewInviteDialog};
pub use endpoint::{SipEndpoint, SipEndpointConfig, SipEvent};
pub use error::{pj_strerror, status_to_result, PjError, Result};
pub use message::{
    canonical_header_name, ensure_name_addr, extract_branch, extract_tag, extract_uri,
    SipHeader, SipMessageView, SipPacketKind,
};
pub use runtime::PjRuntime;
pub use transaction::{
    ClientTransaction, ClientTxDecision, ClientTxKey, ClientTxState, ServerTransaction,
    ServerTxDecision, ServerTxKey, ServerTxState, TransactionStore,
};
pub use transport::{
    SipAssociation, SipRxPacket, SipTransportProtocol, SipTxPacket, TransportBridge,
};
