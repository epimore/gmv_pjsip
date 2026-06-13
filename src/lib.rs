//! Safe GB28181-oriented native PJSIP runtime.
//!
//! Boundary:
//! - `gmv_pjsip_sys` exposes the versioned C shim and custom transport.
//! - `gmv_pjsip` owns PJSIP runtime, transaction, dialog, INVITE, and subscription state.
//! - `session` depends on this crate and never manipulates raw PJSIP pointers.

pub mod auth;
pub mod error;
pub mod gb28181;
pub mod message;
#[cfg(feature = "pjsip-sys")]
pub mod runtime;
pub mod transport;

pub use bytes::Bytes;

pub use auth::{
    AuthAlgorithm, AuthConfig, AuthCredential, AuthDecision, AuthRequirement, CredentialKind,
    PasswordProvider, StaticPasswordProvider,
};
pub use error::{Result, SipError};
pub use gb28181::sdp::{TalkAudioCodec, TalkSdpMode};
pub use message::SipMethod;
#[cfg(feature = "pjsip-sys")]
pub use runtime::{
    SipAuthLookupResult, SipDialogMethod, SipDialogRequest, SipInviteResponse, SipOutboundInvite,
    SipOutboundMessage, SipOutboundSubscribe, SipRuntime, SipRuntimeConfig, SipRuntimeEvent,
    SipRuntimeEventKind, SipRuntimeEvents, SipRuntimeTransmits, SipTransmit,
};
pub use transport::{SipAssociation, SipPacketMeta, SipTransportProtocol};
