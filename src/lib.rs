//! Safe GB28181-oriented wrapper over pjproject.
//!
//! This crate deliberately keeps all `gmv_pjsip_sys` access inside `gmv_pjsip`.
//! `gmv_session` should use the safe structs/functions exported here and should not call raw PJSIP
//! symbols directly.
//!
//! Current integration model:
//! - PJSIP is initialized through [`runtime::PjRuntime`].
//! - PJSIP endpoint, transaction layer and UA layer are initialized by runtime.
//! - Incoming bytes are validated by `pjsip_parse_msg()` and copied into an owned [`message::SipMessage`].
//! - Tokio UDP/TCP IO stays in gmv and is bridged by [`transport::SipAssociation`].
//! - GB28181 business semantics stay in `gmv/session/src/gb/sip`.

pub mod builder;
pub mod dialog;
pub mod endpoint;
pub mod error;
pub mod message;
pub mod runtime;
pub mod transaction;
pub mod transport;

pub use builder::{
    build_ack_for_invite_2xx, build_request, build_response, new_branch_token, new_call_id,
    new_tag, RequestOptions, ResponseOptions,
};
pub use dialog::{DialogId, DialogState, DialogStore, InviteDialog};
pub use endpoint::{EndpointRxResult, SipEndpoint, SipEvent, SipEventKind};
pub use error::{pj_strerror, status_to_result, PjError, Result};
pub use message::{
    ensure_name_addr, extract_tag, extract_uri_from_name_addr, SipKind, SipMessage,
};
pub use runtime::{PjPool, PjRuntime};
pub use transaction::{
    ClientTransaction, ClientTransactionKey, ServerTransaction, ServerTransactionKey,
    ServerTxDecision, TransactionStore,
};
pub use transport::{sent_by_from_addr, sip_uri_host_port, SipAssociation, SipTransport, SipTxPacket};

/// Convenience initializer for applications that only need one SIP endpoint.
pub fn create_endpoint(user_agent: impl Into<String>) -> Result<(std::sync::Arc<PjRuntime>, SipEndpoint)> {
    let runtime = std::sync::Arc::new(PjRuntime::new("gmv_pjsip")?);
    let endpoint = SipEndpoint::new(runtime.clone(), user_agent);
    Ok((runtime, endpoint))
}
