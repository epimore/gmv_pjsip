//! Safe GB28181-oriented native PJSIP runtime.
//!
//! Boundary:
//! - `gmv_pjsip_sys` exposes the versioned C shim and private PJSIP adapter.
//! - `gmv_pjsip` owns PJSIP runtime, transaction, dialog, INVITE, and subscription state.
//! - `session` depends on this crate and never manipulates raw PJSIP pointers.

pub mod auth;
pub mod error;
pub mod gb28181;
mod io;
pub mod message;
mod runtime;
pub mod transport;

pub use base::bytes::Bytes;
pub use base::exception::{GlobalError, GlobalResult};

pub use auth::{
    AuthAlgorithm, AuthConfig, AuthCredential, AuthDecision, AuthRequirement, CredentialKind,
    PasswordProvider, StaticPasswordProvider,
};
pub use gb28181::sdp::{TalkAudioCodec, TalkSdpMode};
pub use message::SipMethod;
pub use runtime::{
    SipAuthLookupResult, SipDialogMethod, SipDialogRequest, SipDialogSnapshot,
    SipIncomingInviteAllow, SipInviteIdentity, SipInviteResponse, SipOutboundInvite,
    SipOutboundMessage, SipOutboundSubscribe, SipRegisteredSource, SipRestoredDialogRequest,
    SipRuntime, SipRuntimeConfig, SipRuntimeEvent, SipRuntimeEventKind, SipRuntimeEvents,
    SipRuntimeSockets, SipTlsConfig,
};
#[cfg(feature = "test-helpers")]
pub use runtime::{SipRuntimeTransmits, SipTransmit};
pub use transport::{SipAssociation, SipPacketMeta, SipTransportProtocol};
