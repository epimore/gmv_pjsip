//! Safe GB28181-oriented SIP context layer.
//!
//! Boundary:
//! - `gmv_pjsip_sys` mirrors raw pjproject C symbols.
//! - `gmv_pjsip` owns SIP parsing/building/transaction/dialog context.
//! - `session` depends on this crate and never manipulates raw PJSIP pointers.

pub mod auth;
pub mod builder;
pub mod context;
pub mod endpoint;
pub mod error;
pub mod gb28181;
pub mod message;
pub mod parser;
pub mod transport;
pub mod types;

pub use bytes::Bytes;

pub use auth::{AuthAlgorithm, AuthConfig, AuthCredential, AuthDecision, CredentialKind, PasswordProvider, StaticPasswordProvider};
pub use context::{
    CallStore, DialogId, DialogState, DialogStore, InviteCall, InviteState, RegisterBinding,
    RegisterStore, SipContext, SipLocalConfig, TransactionStore,
};
pub use endpoint::{
    AckEvent, ByeEvent, CancelEvent, CreateBye, CreateInvite, CreateMessage, IncomingInviteEvent,
    InviteAcceptedEvent, MessageEvent, MessageKind, RegisterEvent, SipAction, SipEndpoint,
    SipEvent, SipOutput,
};
pub use error::{Result, SipError};
pub use message::{HeaderMapExt, SipHeader, SipMessage, SipMethod, SipPacketKind, SipResponseStatus};
pub use transport::{SipAssociation, SipPacketMeta, SipTransportProtocol};
pub use types::{CSeq, CallId, DeviceId, SipUri, StreamId};
