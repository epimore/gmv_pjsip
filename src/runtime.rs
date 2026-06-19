use std::ffi::{c_char, c_void, CStr};
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::slice;
#[cfg(feature = "test-helpers")]
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use base::tokio::sync::mpsc as tokio_mpsc;
use gmv_pjsip_sys::{
    gmv_pjsip_auth_alg_md5, gmv_pjsip_auth_alg_sha256, gmv_pjsip_auth_alg_sha512_256,
    gmv_pjsip_auth_digest_type, gmv_pjsip_auth_plain_password_type,
    gmv_sip_auth_lookup_completion_t,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_BYPASS as AUTH_BYPASS,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_CREDENTIAL as AUTH_CREDENTIAL,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_NOT_FOUND as AUTH_NOT_FOUND,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_REJECT as AUTH_REJECT,
    gmv_sip_dialog_method_GMV_SIP_DIALOG_BYE as DIALOG_BYE,
    gmv_sip_dialog_method_GMV_SIP_DIALOG_INFO as DIALOG_INFO, gmv_sip_dialog_request_t,
    gmv_sip_error_message, gmv_sip_event_t,
    gmv_sip_event_type_GMV_SIP_EVENT_AUTH_LOOKUP_REQUIRED as EVENT_AUTH_LOOKUP_REQUIRED,
    gmv_sip_event_type_GMV_SIP_EVENT_AUTH_REJECTED as EVENT_AUTH_REJECTED,
    gmv_sip_event_type_GMV_SIP_EVENT_INCOMING_INVITE as EVENT_INCOMING_INVITE,
    gmv_sip_event_type_GMV_SIP_EVENT_OUTBOUND_RESPONSE as EVENT_OUTBOUND_RESPONSE,
    gmv_sip_event_type_GMV_SIP_EVENT_REGISTERED as EVENT_REGISTERED,
    gmv_sip_event_type_GMV_SIP_EVENT_REQUEST_RECEIVED as EVENT_REQUEST_RECEIVED,
    gmv_sip_event_type_GMV_SIP_EVENT_RESPONSE_SENT as EVENT_RESPONSE_SENT,
    gmv_sip_event_type_GMV_SIP_EVENT_RUNTIME_FAULT as EVENT_RUNTIME_FAULT,
    gmv_sip_event_type_GMV_SIP_EVENT_UNREGISTERED as EVENT_UNREGISTERED, gmv_sip_invite_response_t,
    gmv_sip_outbound_invite_t, gmv_sip_outbound_message_t, gmv_sip_outbound_subscribe_t,
    gmv_sip_received_packet_t, gmv_sip_restored_dialog_request_t, gmv_sip_runtime_close_transport,
    gmv_sip_runtime_complete_auth_lookup, gmv_sip_runtime_complete_send,
    gmv_sip_runtime_config_init, gmv_sip_runtime_config_t, gmv_sip_runtime_create,
    gmv_sip_runtime_destroy, gmv_sip_runtime_poll, gmv_sip_runtime_receive_packet,
    gmv_sip_runtime_respond_invite, gmv_sip_runtime_send_dialog_request,
    gmv_sip_runtime_send_invite, gmv_sip_runtime_send_message,
    gmv_sip_runtime_send_restored_dialog_request, gmv_sip_runtime_send_subscribe,
    gmv_sip_runtime_start, gmv_sip_runtime_stop, gmv_sip_runtime_t, gmv_sip_send_completion_t,
    gmv_sip_send_packet_t, gmv_sip_string_view_t,
    gmv_sip_transport_GMV_SIP_TRANSPORT_TCP as TRANSPORT_TCP,
    gmv_sip_transport_GMV_SIP_TRANSPORT_UDP as TRANSPORT_UDP, GMV_SIP_ABI_VERSION,
};
use uuid::Uuid;

use crate::auth::{AuthAlgorithm, AuthCredential, CredentialKind};
use crate::error::{internal_error, invalid_config, runtime_active, system_error, Result};
use crate::io::{RuntimeIoCommand, SocketIoRuntime};
use crate::transport::SipTransportProtocol;

static RUNTIME_LOCK: Mutex<()> = Mutex::new(());
const DEFAULT_IO_QUEUE_CAPACITY: usize = 32_768;

#[derive(Clone, Debug)]
pub struct SipRuntimeConfig {
    pub bind_address: Ipv4Addr,
    pub port: u16,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub async_count: u32,
    pub poll_timeout: Duration,
    pub auth_realm: String,
    pub auth_algorithm: AuthAlgorithm,
    pub max_pending_auth: u32,
    pub auth_lookup_timeout: Duration,
    pub io_queue_capacity: usize,
    pub user_agent: String,
    pub tls: Option<SipTlsConfig>,
}

#[derive(Clone, Debug)]
pub struct SipTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    pub require_client_cert: bool,
}

#[derive(Debug, Default)]
pub struct SipRuntimeSockets {
    pub udp: Option<UdpSocket>,
    pub tcp: Option<TcpListener>,
    pub tls: Option<TcpListener>,
}

impl Default for SipRuntimeConfig {
    fn default() -> Self {
        Self {
            bind_address: Ipv4Addr::LOCALHOST,
            port: 0,
            enable_udp: true,
            enable_tcp: true,
            async_count: 1,
            poll_timeout: Duration::from_millis(10),
            auth_realm: "3402000000".into(),
            auth_algorithm: AuthAlgorithm::Md5,
            max_pending_auth: 20_000,
            auth_lookup_timeout: Duration::from_secs(3),
            io_queue_capacity: DEFAULT_IO_QUEUE_CAPACITY,
            user_agent: "GMV-PJSIP/0.1".into(),
            tls: None,
        }
    }
}

impl SipRuntimeConfig {
    fn validate(&self) -> Result<(u32, u32)> {
        if !self.enable_udp && !self.enable_tcp {
            return Err(invalid_config(
                "at least one of UDP or TCP must be enabled".into(),
            ));
        }
        if self.async_count == 0 {
            return Err(invalid_config(
                "async_count must be greater than zero".into(),
            ));
        }
        if self.auth_realm.is_empty() || self.auth_realm.as_bytes().contains(&0) {
            return Err(invalid_config(
                "auth_realm must be non-empty and contain no NUL byte".into(),
            ));
        }
        if self.max_pending_auth == 0 {
            return Err(invalid_config(
                "max_pending_auth must be greater than zero".into(),
            ));
        }
        if self.io_queue_capacity == 0 {
            return Err(invalid_config(
                "io_queue_capacity must be greater than zero".into(),
            ));
        }
        if self.user_agent.is_empty()
            || self
                .user_agent
                .as_bytes()
                .iter()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(invalid_config(
                "user_agent must be non-empty and contain no NUL, CR, or LF byte".into(),
            ));
        }
        Ok((
            duration_millis("poll_timeout", self.poll_timeout)?,
            duration_millis("auth_lookup_timeout", self.auth_lookup_timeout)?,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipRuntimeEventKind {
    RequestReceived,
    ResponseSent,
    RuntimeFault,
    AuthLookupRequired,
    Registered,
    Unregistered,
    AuthRejected,
    OutboundResponse,
    IncomingInvite,
    TransportClosed,
    Unknown(i32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipRuntimeEvent {
    pub event_id: u64,
    pub kind: SipRuntimeEventKind,
    pub protocol: Option<SipTransportProtocol>,
    pub status_code: Option<u16>,
    pub pj_status: i32,
    pub method: Option<String>,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub local_addr: Option<SocketAddr>,
    pub remote_addr: Option<SocketAddr>,
    pub lookup_id: Option<u64>,
    pub device_id: Option<String>,
    pub realm: Option<String>,
    pub expires_seconds: Option<u32>,
    pub contact: Option<String>,
    pub user_agent: Option<String>,
    pub gb_version: Option<String>,
    pub operation_id: Option<u64>,
    pub association_id: Option<u64>,
    pub from_header: Option<String>,
    pub to_header: Option<String>,
    pub subject: Option<String>,
    pub event: Option<String>,
    pub subscription_state: Option<String>,
    pub dialog_snapshot: Option<SipDialogSnapshot>,
}

pub type SipRuntimeEvents = Receiver<SipRuntimeEvent>;
#[cfg(feature = "test-helpers")]
pub type SipRuntimeTransmits = Receiver<SipTransmit>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipTransmit {
    pub send_id: u64,
    pub transport_id: u64,
    pub association_id: u64,
    pub protocol: SipTransportProtocol,
    pub data: Vec<u8>,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub enum SipAuthLookupResult {
    Credential(AuthCredential),
    Bypass,
    Reject,
    NotFound,
}

#[derive(Clone, Debug)]
pub struct SipOutboundMessage {
    pub operation_id: u64,
    pub association_id: u64,
    pub protocol: SipTransportProtocol,
    pub target_uri: String,
    pub from_uri: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipInviteIdentity {
    pub call_id: String,
    pub local_tag: String,
    pub local_cseq: u32,
}

impl SipInviteIdentity {
    #[must_use]
    pub fn generate() -> Self {
        let cseq_seed = Uuid::new_v4().as_u128() as u32;
        Self {
            call_id: Uuid::new_v4().simple().to_string(),
            local_tag: Uuid::new_v4().simple().to_string(),
            local_cseq: (cseq_seed & i32::MAX as u32).max(1),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SipOutboundInvite {
    pub operation_id: u64,
    pub association_id: u64,
    pub protocol: SipTransportProtocol,
    pub identity: SipInviteIdentity,
    pub target_uri: String,
    pub from_uri: String,
    pub contact_uri: String,
    pub subject: Option<String>,
    pub sdp: String,
}

#[derive(Clone, Debug)]
pub struct SipOutboundSubscribe {
    pub operation_id: u64,
    pub association_id: u64,
    pub protocol: SipTransportProtocol,
    pub target_uri: String,
    pub from_uri: String,
    pub contact_uri: String,
    pub call_id: Option<String>,
    pub event: String,
    pub expires: u32,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipDialogMethod {
    Bye,
    Info,
}

#[derive(Clone, Debug)]
pub struct SipDialogRequest {
    pub operation_id: u64,
    pub method: SipDialogMethod,
    pub call_id: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Persistable identity and routing state for an established UAC dialog.
///
/// `local_cseq` is the CSeq reserved by the caller for the next request. The
/// caller must persist that reservation before asking the runtime to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipDialogSnapshot {
    pub call_id: String,
    pub local_uri: String,
    pub remote_uri: String,
    pub local_tag: String,
    pub remote_tag: String,
    pub local_cseq: u32,
    pub remote_target: String,
    pub route_set: Vec<String>,
    pub protocol: SipTransportProtocol,
    pub association_id: u64,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct SipRestoredDialogRequest {
    pub operation_id: u64,
    pub method: SipDialogMethod,
    pub snapshot: SipDialogSnapshot,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SipInviteResponse {
    pub call_id: String,
    pub status_code: u16,
    pub reason: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

struct EventState {
    sender: Sender<SipRuntimeEvent>,
}

struct TransmitState {
    sender: TransmitSender,
}

enum TransmitSender {
    SocketIo(tokio_mpsc::Sender<SipTransmit>),
    #[cfg(feature = "test-helpers")]
    Test(SyncSender<SipTransmit>),
}

pub struct SipRuntime {
    raw: NonNull<gmv_sip_runtime_t>,
    stopped: bool,
    event_state: Box<EventState>,
    _transmit_state: Box<TransmitState>,
    io_commands: Receiver<RuntimeIoCommand>,
    _socket_io: Option<SocketIoRuntime>,
    _runtime_guard: MutexGuard<'static, ()>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl SipRuntime {
    pub fn start(
        config: SipRuntimeConfig,
        sockets: SipRuntimeSockets,
    ) -> Result<(Self, SipRuntimeEvents)> {
        validate_sockets(&config, &sockets)?;
        let (poll_timeout_ms, auth_lookup_timeout_ms) = config.validate()?;
        let runtime_guard = match RUNTIME_LOCK.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(runtime_active()),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };

        let bind_address = config.bind_address.to_string();
        let auth_realm = config.auth_realm.as_bytes();
        let user_agent = config.user_agent.as_bytes();
        let (sender, events) = mpsc::channel();
        let mut event_state = Box::new(EventState { sender });
        let (transmit_sender, transmits) = tokio_mpsc::channel(config.io_queue_capacity);
        let (io_command_sender, io_commands) = mpsc::sync_channel(config.io_queue_capacity);
        let mut transmit_state = Box::new(TransmitState {
            sender: TransmitSender::SocketIo(transmit_sender),
        });
        let mut ffi_config = MaybeUninit::<gmv_sip_runtime_config_t>::uninit();
        // SAFETY: The C initializer writes the complete config structure.
        unsafe { gmv_sip_runtime_config_init(ffi_config.as_mut_ptr()) };
        // SAFETY: The initializer completed for a valid non-null pointer.
        let mut ffi_config = unsafe { ffi_config.assume_init() };
        ffi_config.bind_address = gmv_sip_string_view_t {
            ptr: bind_address.as_ptr().cast(),
            len: bind_address.len(),
        };
        ffi_config.port = config.port;
        ffi_config.enable_udp = u8::from(sockets.udp.is_some());
        ffi_config.enable_tcp = u8::from(sockets.tcp.is_some() || sockets.tls.is_some());
        ffi_config.async_count = config.async_count;
        ffi_config.poll_timeout_ms = poll_timeout_ms;
        ffi_config.event_callback = Some(runtime_event_callback);
        ffi_config.event_user_data = ptr::from_mut(event_state.as_mut()).cast();
        ffi_config.auth_realm = gmv_sip_string_view_t {
            ptr: auth_realm.as_ptr().cast(),
            len: auth_realm.len(),
        };
        ffi_config.auth_algorithm_type = auth_algorithm_id(config.auth_algorithm);
        ffi_config.max_pending_auth = config.max_pending_auth;
        ffi_config.auth_lookup_timeout_ms = auth_lookup_timeout_ms;
        ffi_config.user_agent = gmv_sip_string_view_t {
            ptr: user_agent.as_ptr().cast(),
            len: user_agent.len(),
        };
        ffi_config.send_callback = Some(runtime_send_callback);
        ffi_config.send_user_data = ptr::from_mut(transmit_state.as_mut()).cast();
        if base::log::log_enabled!(base::log::Level::Trace) {
            ffi_config.log_level = 5;
            ffi_config.log_callback = Some(runtime_log_callback);
            ffi_config.log_user_data = ptr::null_mut();
        }

        let mut raw = ptr::null_mut();
        // SAFETY: The config, callback state, and output pointer remain valid
        // for the duration of this call. The C runtime copies config strings.
        let status = unsafe { gmv_sip_runtime_create(&ffi_config, &mut raw) };
        if status != 0 {
            return Err(pjsip_error("runtime_create", status));
        }
        let raw = NonNull::new(raw)
            .ok_or_else(|| internal_error("PJSIP runtime create returned a null handle".into()))?;

        // SAFETY: `raw` is the uniquely owned handle returned by create.
        let status = unsafe { gmv_sip_runtime_start(raw.as_ptr()) };
        if status != 0 {
            // SAFETY: Start failure leaves the allocated runtime valid for
            // destruction and no Rust owner has been constructed yet.
            unsafe { gmv_sip_runtime_destroy(raw.as_ptr()) };
            return Err(pjsip_error("runtime_start", status));
        }
        let socket_io = match SocketIoRuntime::start(sockets, transmits, io_command_sender) {
            Ok(socket_io) => socket_io,
            Err(err) => {
                // SAFETY: Start succeeded and the runtime is still uniquely owned here.
                let _ = unsafe { gmv_sip_runtime_stop(raw.as_ptr()) };
                unsafe { gmv_sip_runtime_destroy(raw.as_ptr()) };
                return Err(err);
            }
        };

        Ok((
            Self {
                raw,
                stopped: false,
                event_state,
                _transmit_state: transmit_state,
                io_commands,
                _socket_io: Some(socket_io),
                _runtime_guard: runtime_guard,
                _not_send_or_sync: PhantomData,
            },
            events,
        ))
    }

    #[cfg(feature = "test-helpers")]
    pub fn start_for_test(
        config: SipRuntimeConfig,
    ) -> Result<(Self, SipRuntimeEvents, SipRuntimeTransmits)> {
        let (poll_timeout_ms, auth_lookup_timeout_ms) = config.validate()?;
        let runtime_guard = match RUNTIME_LOCK.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(runtime_active()),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };

        let bind_address = config.bind_address.to_string();
        let auth_realm = config.auth_realm.as_bytes();
        let user_agent = config.user_agent.as_bytes();
        let (sender, events) = mpsc::channel();
        let mut event_state = Box::new(EventState { sender });
        let (transmit_sender, transmits) = mpsc::sync_channel(config.io_queue_capacity);
        let (_io_command_sender, io_commands) = mpsc::sync_channel(config.io_queue_capacity);
        let mut transmit_state = Box::new(TransmitState {
            sender: TransmitSender::Test(transmit_sender),
        });
        let mut ffi_config = MaybeUninit::<gmv_sip_runtime_config_t>::uninit();
        // SAFETY: The C initializer writes the complete config structure.
        unsafe { gmv_sip_runtime_config_init(ffi_config.as_mut_ptr()) };
        // SAFETY: The initializer completed for a valid non-null pointer.
        let mut ffi_config = unsafe { ffi_config.assume_init() };
        ffi_config.bind_address = gmv_sip_string_view_t {
            ptr: bind_address.as_ptr().cast(),
            len: bind_address.len(),
        };
        ffi_config.port = config.port;
        ffi_config.enable_udp = u8::from(config.enable_udp);
        ffi_config.enable_tcp = u8::from(config.enable_tcp);
        ffi_config.async_count = config.async_count;
        ffi_config.poll_timeout_ms = poll_timeout_ms;
        ffi_config.event_callback = Some(runtime_event_callback);
        ffi_config.event_user_data = ptr::from_mut(event_state.as_mut()).cast();
        ffi_config.auth_realm = gmv_sip_string_view_t {
            ptr: auth_realm.as_ptr().cast(),
            len: auth_realm.len(),
        };
        ffi_config.auth_algorithm_type = auth_algorithm_id(config.auth_algorithm);
        ffi_config.max_pending_auth = config.max_pending_auth;
        ffi_config.auth_lookup_timeout_ms = auth_lookup_timeout_ms;
        ffi_config.user_agent = gmv_sip_string_view_t {
            ptr: user_agent.as_ptr().cast(),
            len: user_agent.len(),
        };
        ffi_config.send_callback = Some(runtime_send_callback);
        ffi_config.send_user_data = ptr::from_mut(transmit_state.as_mut()).cast();
        if base::log::log_enabled!(base::log::Level::Trace) {
            ffi_config.log_level = 5;
            ffi_config.log_callback = Some(runtime_log_callback);
            ffi_config.log_user_data = ptr::null_mut();
        }

        let mut raw = ptr::null_mut();
        // SAFETY: The config, callback state, and output pointer remain valid
        // for the duration of this call. The C runtime copies config strings.
        let status = unsafe { gmv_sip_runtime_create(&ffi_config, &mut raw) };
        if status != 0 {
            return Err(pjsip_error("runtime_create", status));
        }
        let raw = NonNull::new(raw)
            .ok_or_else(|| internal_error("PJSIP runtime create returned a null handle".into()))?;

        // SAFETY: `raw` is the uniquely owned handle returned by create.
        let status = unsafe { gmv_sip_runtime_start(raw.as_ptr()) };
        if status != 0 {
            // SAFETY: Start failure leaves the allocated runtime valid for
            // destruction and no Rust owner has been constructed yet.
            unsafe { gmv_sip_runtime_destroy(raw.as_ptr()) };
            return Err(pjsip_error("runtime_start", status));
        }

        Ok((
            Self {
                raw,
                stopped: false,
                event_state,
                _transmit_state: transmit_state,
                io_commands,
                _socket_io: None,
                _runtime_guard: runtime_guard,
                _not_send_or_sync: PhantomData,
            },
            events,
            transmits,
        ))
    }

    #[cfg(feature = "test-helpers")]
    pub fn inject_test_packet(
        &mut self,
        association_id: u64,
        protocol: SipTransportProtocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        self.receive_packet(association_id, protocol, local_addr, remote_addr, data)
    }

    #[cfg(feature = "test-helpers")]
    pub fn complete_test_send(
        &mut self,
        send_id: u64,
        result: std::result::Result<usize, i32>,
    ) -> Result<()> {
        self.complete_send(send_id, result)
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        // SAFETY: The runtime handle is valid and exclusively controlled by
        // this non-Send wrapper.
        let status = unsafe { gmv_sip_runtime_stop(self.raw.as_ptr()) };
        if status != 0 {
            return Err(pjsip_error("runtime_stop", status));
        }
        self.stopped = true;
        Ok(())
    }

    pub fn poll(&mut self) -> Result<()> {
        if self.stopped {
            return Err(invalid_config("cannot poll after runtime stop".into()));
        }
        self.drain_io_commands();
        // SAFETY: The runtime handle is valid and this non-Send wrapper keeps
        // all PJSIP calls on the thread that created the runtime.
        let status = unsafe { gmv_sip_runtime_poll(self.raw.as_ptr()) };
        if status != 0 {
            return Err(pjsip_error("runtime_poll", status));
        }
        Ok(())
    }

    fn drain_io_commands(&mut self) {
        while let Ok(command) = self.io_commands.try_recv() {
            match command {
                RuntimeIoCommand::Receive {
                    association_id,
                    protocol,
                    local_addr,
                    remote_addr,
                    data,
                } => {
                    if let Err(err) = self.receive_packet(
                        association_id,
                        protocol,
                        local_addr,
                        remote_addr,
                        &data,
                    ) {
                        base::log::trace!(
                            "deliver SIP socket packet failed: association_id={}, protocol={protocol:?}, err={err}",
                            association_id
                        );
                    }
                }
                RuntimeIoCommand::CompleteSend { send_id, result } => {
                    if let Err(err) = self.complete_send(send_id, result) {
                        base::log::trace!(
                            "complete SIP socket send failed: send_id={send_id}, err={err}"
                        );
                    }
                }
                RuntimeIoCommand::TransportClosed {
                    association_id,
                    protocol,
                    local_addr,
                    remote_addr,
                    status,
                } => {
                    if let Err(err) = self.close_transport(association_id, protocol, status) {
                        base::log::trace!(
                            "close SIP transport failed: association_id={association_id}, err={err}"
                        );
                    }
                    let _ = self.event_state.sender.send(SipRuntimeEvent {
                        event_id: 0,
                        kind: SipRuntimeEventKind::TransportClosed,
                        protocol: Some(protocol),
                        status_code: None,
                        pj_status: status,
                        method: None,
                        call_id: None,
                        cseq: None,
                        content_type: None,
                        body: Vec::new(),
                        local_addr: Some(local_addr),
                        remote_addr: Some(remote_addr),
                        lookup_id: None,
                        device_id: None,
                        realm: None,
                        expires_seconds: None,
                        contact: None,
                        user_agent: None,
                        gb_version: None,
                        operation_id: None,
                        association_id: Some(association_id),
                        from_header: None,
                        to_header: None,
                        subject: None,
                        event: None,
                        subscription_state: None,
                        dialog_snapshot: None,
                    });
                }
            }
        }
    }

    pub fn complete_auth_lookup(
        &mut self,
        lookup_id: u64,
        result: SipAuthLookupResult,
    ) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot complete auth lookup after runtime stop".into(),
            ));
        }
        if lookup_id == 0 {
            return Err(invalid_config("lookup_id must be non-zero".into()));
        }

        let mut completion = gmv_sip_auth_lookup_completion_t {
            size: mem::size_of::<gmv_sip_auth_lookup_completion_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            lookup_id,
            result: 0,
            credential_type: 0,
            algorithm_type: 0,
            username: empty_view(),
            realm: empty_view(),
            secret: empty_view(),
        };
        let credential = match &result {
            SipAuthLookupResult::Credential(credential) => {
                completion.result = AUTH_CREDENTIAL as i32;
                completion.credential_type = credential_type(&credential.kind);
                completion.algorithm_type = auth_algorithm_id(credential.algorithm);
                completion.username = string_view(&credential.username);
                completion.realm = string_view(&credential.realm);
                completion.secret = string_view(&credential.secret);
                Some(credential)
            }
            SipAuthLookupResult::Bypass => {
                completion.result = AUTH_BYPASS as i32;
                None
            }
            SipAuthLookupResult::Reject => {
                completion.result = AUTH_REJECT as i32;
                None
            }
            SipAuthLookupResult::NotFound => {
                completion.result = AUTH_NOT_FOUND as i32;
                None
            }
        };

        // Keep the credential strings borrowed by `completion` alive until the
        // shim has copied them into its command queue.
        let _credential = credential;
        // SAFETY: The runtime handle is valid, and every string view remains
        // valid for the duration of this synchronous call.
        let status =
            unsafe { gmv_sip_runtime_complete_auth_lookup(self.raw.as_ptr(), &completion) };
        if status != 0 {
            return Err(pjsip_error("complete_auth_lookup", status));
        }
        Ok(())
    }

    fn receive_packet(
        &mut self,
        association_id: u64,
        protocol: SipTransportProtocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot receive packet after runtime stop".into(),
            ));
        }
        if data.is_empty() {
            return Err(invalid_config(
                "received SIP packet must not be empty".into(),
            ));
        }
        if !local_addr.is_ipv4() || !remote_addr.is_ipv4() {
            return Err(invalid_config(
                "SIP runtime socket adapter supports IPv4 only".into(),
            ));
        }
        if matches!(
            protocol,
            SipTransportProtocol::Tcp | SipTransportProtocol::Tls
        ) && association_id == 0
        {
            return Err(invalid_config(
                "reliable transport association_id must be non-zero".into(),
            ));
        }

        let local_ip = local_addr.ip().to_string();
        let remote_ip = remote_addr.ip().to_string();
        let packet = gmv_sip_received_packet_t {
            size: mem::size_of::<gmv_sip_received_packet_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            association_id,
            transport: transport_id(protocol),
            data: bytes_view(data),
            local_address: string_view(&local_ip),
            local_port: local_addr.port(),
            remote_address: string_view(&remote_ip),
            remote_port: remote_addr.port(),
        };
        // SAFETY: The runtime is valid and the shim copies every borrowed view
        // before this synchronous call returns.
        let status = unsafe { gmv_sip_runtime_receive_packet(self.raw.as_ptr(), &packet) };
        if status != 0 {
            return Err(pjsip_error("receive_packet", status));
        }
        Ok(())
    }

    fn complete_send(
        &mut self,
        send_id: u64,
        result: std::result::Result<usize, i32>,
    ) -> Result<()> {
        if self.stopped || send_id == 0 {
            return Err(invalid_config(
                "cannot complete an invalid or stopped send".into(),
            ));
        }
        let sent_bytes = match result {
            Ok(bytes) => i64::try_from(bytes)
                .map_err(|_| invalid_config("sent byte count exceeds i64".into()))?,
            Err(status) => -i64::from(status.abs().max(1)),
        };
        let completion = gmv_sip_send_completion_t {
            size: mem::size_of::<gmv_sip_send_completion_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            send_id,
            sent_bytes,
        };
        // SAFETY: The runtime is valid and the shim copies the completion.
        let status = unsafe { gmv_sip_runtime_complete_send(self.raw.as_ptr(), &completion) };
        if status != 0 {
            return Err(pjsip_error("complete_send", status));
        }
        Ok(())
    }

    pub fn close_transport(
        &mut self,
        association_id: u64,
        protocol: SipTransportProtocol,
        status: i32,
    ) -> Result<()> {
        if self.stopped || association_id == 0 || protocol != SipTransportProtocol::Tcp {
            return Err(invalid_config(
                "only an active TCP association can be closed".into(),
            ));
        }
        // SAFETY: The runtime is valid and the shim copies scalar command data.
        let result = unsafe {
            gmv_sip_runtime_close_transport(
                self.raw.as_ptr(),
                association_id,
                transport_id(protocol),
                status,
            )
        };
        if result != 0 {
            return Err(pjsip_error("close_transport", result));
        }
        Ok(())
    }

    pub fn send_message(&mut self, message: &SipOutboundMessage) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot send MESSAGE after runtime stop".into(),
            ));
        }
        if message.operation_id == 0 {
            return Err(invalid_config("operation_id must be non-zero".into()));
        }
        if message.protocol == SipTransportProtocol::Tls
            || (message.protocol == SipTransportProtocol::Tcp && message.association_id == 0)
        {
            return Err(invalid_config(
                "outbound MESSAGE requires a valid UDP/TCP association".into(),
            ));
        }
        if message.target_uri.is_empty()
            || message.from_uri.is_empty()
            || !message.content_type.contains('/')
            || message.target_uri.as_bytes().contains(&0)
            || message.from_uri.as_bytes().contains(&0)
            || message.content_type.as_bytes().contains(&0)
        {
            return Err(invalid_config(
                "target_uri, from_uri, and content_type are required".into(),
            ));
        }

        let request = gmv_sip_outbound_message_t {
            size: mem::size_of::<gmv_sip_outbound_message_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            operation_id: message.operation_id,
            association_id: message.association_id,
            transport: transport_id(message.protocol),
            target_uri: string_view(&message.target_uri),
            from_uri: string_view(&message.from_uri),
            content_type: string_view(&message.content_type),
            body: bytes_view(&message.body),
        };
        // SAFETY: The runtime handle is valid and all request views remain
        // valid for this synchronous call. PJSIP copies them into txdata.
        let status = unsafe { gmv_sip_runtime_send_message(self.raw.as_ptr(), &request) };
        if status != 0 {
            return Err(pjsip_error("send_message", status));
        }
        Ok(())
    }

    pub fn send_invite(&mut self, invite: &SipOutboundInvite) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot send INVITE after runtime stop".into(),
            ));
        }
        if invite.operation_id == 0 {
            return Err(invalid_config("operation_id must be non-zero".into()));
        }
        if invite.protocol == SipTransportProtocol::Tls
            || (invite.protocol == SipTransportProtocol::Tcp && invite.association_id == 0)
        {
            return Err(invalid_config(
                "outbound INVITE requires a valid UDP/TCP association".into(),
            ));
        }
        if invite.target_uri.is_empty()
            || invite.from_uri.is_empty()
            || invite.contact_uri.is_empty()
            || invite.sdp.is_empty()
            || invite.identity.call_id.is_empty()
            || invite.identity.local_tag.is_empty()
            || invite.identity.local_cseq == 0
            || invite.identity.local_cseq > i32::MAX as u32
            || invite.target_uri.as_bytes().contains(&0)
            || invite.from_uri.as_bytes().contains(&0)
            || invite.contact_uri.as_bytes().contains(&0)
            || invite.sdp.as_bytes().contains(&0)
            || invite
                .identity
                .call_id
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
            || invite
                .identity
                .local_tag
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
            || invite
                .subject
                .as_deref()
                .is_some_and(|subject| subject.as_bytes().contains(&0))
        {
            return Err(invalid_config(
                "INVITE identity, target_uri, from_uri, contact_uri, and SDP are required".into(),
            ));
        }

        let to_uri = invite_to_uri(&invite.target_uri, invite.subject.as_deref());

        let request = gmv_sip_outbound_invite_t {
            size: mem::size_of::<gmv_sip_outbound_invite_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            operation_id: invite.operation_id,
            association_id: invite.association_id,
            transport: transport_id(invite.protocol),
            local_cseq: invite.identity.local_cseq,
            call_id: string_view(&invite.identity.call_id),
            local_tag: string_view(&invite.identity.local_tag),
            target_uri: string_view(&invite.target_uri),
            to_uri: string_view(&to_uri),
            from_uri: string_view(&invite.from_uri),
            contact_uri: string_view(&invite.contact_uri),
            subject: invite
                .subject
                .as_deref()
                .map(string_view)
                .unwrap_or_else(empty_view),
            sdp: string_view(&invite.sdp),
        };
        // SAFETY: The runtime handle is valid and the shim copies all views
        // before this synchronous call returns.
        let status = unsafe { gmv_sip_runtime_send_invite(self.raw.as_ptr(), &request) };
        if status != 0 {
            return Err(pjsip_error("send_invite", status));
        }
        Ok(())
    }

    pub fn send_dialog_request(&mut self, request: &SipDialogRequest) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot send dialog request after runtime stop".into(),
            ));
        }
        if request.operation_id == 0 || request.call_id.is_empty() {
            return Err(invalid_config(
                "operation_id and call_id are required".into(),
            ));
        }
        if request.call_id.as_bytes().contains(&0)
            || request
                .content_type
                .as_deref()
                .is_some_and(|value| value.as_bytes().contains(&0))
        {
            return Err(invalid_config(
                "dialog request strings must contain no NUL byte".into(),
            ));
        }
        if request.method == SipDialogMethod::Info
            && (request.body.is_empty()
                || !request
                    .content_type
                    .as_deref()
                    .is_some_and(|value| value.contains('/')))
        {
            return Err(invalid_config("INFO requires content_type and body".into()));
        }

        let ffi_request = gmv_sip_dialog_request_t {
            size: mem::size_of::<gmv_sip_dialog_request_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            operation_id: request.operation_id,
            method: match request.method {
                SipDialogMethod::Bye => DIALOG_BYE as i32,
                SipDialogMethod::Info => DIALOG_INFO as i32,
            },
            call_id: string_view(&request.call_id),
            content_type: request
                .content_type
                .as_deref()
                .map(string_view)
                .unwrap_or_else(empty_view),
            body: bytes_view(&request.body),
        };
        // SAFETY: The runtime handle is valid and the shim copies all views
        // before this synchronous call returns.
        let status =
            unsafe { gmv_sip_runtime_send_dialog_request(self.raw.as_ptr(), &ffi_request) };
        if status != 0 {
            return Err(pjsip_error("send_dialog_request", status));
        }
        Ok(())
    }

    pub fn send_restored_dialog_request(
        &mut self,
        request: &SipRestoredDialogRequest,
    ) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot send restored dialog request after runtime stop".into(),
            ));
        }
        let snapshot = &request.snapshot;
        if request.operation_id == 0
            || snapshot.call_id.is_empty()
            || snapshot.local_uri.is_empty()
            || snapshot.remote_uri.is_empty()
            || snapshot.local_tag.is_empty()
            || snapshot.remote_tag.is_empty()
            || snapshot.remote_target.is_empty()
            || snapshot.local_cseq == 0
            || snapshot.local_cseq > i32::MAX as u32
        {
            return Err(invalid_config(
                "restored dialog identity and reserved local_cseq are required".into(),
            ));
        }
        if snapshot.protocol == SipTransportProtocol::Tls {
            return Err(invalid_config(
                "TLS restored dialogs are not supported".into(),
            ));
        }
        if snapshot.protocol == SipTransportProtocol::Tcp && snapshot.association_id == 0 {
            return Err(invalid_config(
                "TCP restored dialog requires a current association_id".into(),
            ));
        }
        let strings = [
            snapshot.call_id.as_str(),
            snapshot.local_uri.as_str(),
            snapshot.remote_uri.as_str(),
            snapshot.local_tag.as_str(),
            snapshot.remote_tag.as_str(),
            snapshot.remote_target.as_str(),
        ];
        if strings.iter().any(|value| {
            value
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        }) || request.content_type.as_deref().is_some_and(|value| {
            value
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        }) || snapshot.route_set.iter().any(|route| {
            route.is_empty()
                || route
                    .bytes()
                    .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        }) {
            return Err(invalid_config(
                "restored dialog strings and routes must be non-empty and contain no control separator"
                    .into(),
            ));
        }
        if request.method == SipDialogMethod::Info
            && (request.body.is_empty()
                || !request
                    .content_type
                    .as_deref()
                    .is_some_and(|value| value.contains('/')))
        {
            return Err(invalid_config("INFO requires content_type and body".into()));
        }
        let route_set = snapshot.route_set.join("\n");
        let remote_address = snapshot.remote_addr.ip().to_string();
        let ffi_request = gmv_sip_restored_dialog_request_t {
            size: mem::size_of::<gmv_sip_restored_dialog_request_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            operation_id: request.operation_id,
            method: match request.method {
                SipDialogMethod::Bye => DIALOG_BYE as i32,
                SipDialogMethod::Info => DIALOG_INFO as i32,
            },
            association_id: snapshot.association_id,
            transport: transport_id(snapshot.protocol),
            local_cseq: snapshot.local_cseq,
            call_id: string_view(&snapshot.call_id),
            local_uri: string_view(&snapshot.local_uri),
            remote_uri: string_view(&snapshot.remote_uri),
            local_tag: string_view(&snapshot.local_tag),
            remote_tag: string_view(&snapshot.remote_tag),
            remote_target: string_view(&snapshot.remote_target),
            route_set: string_view(&route_set),
            remote_address: string_view(&remote_address),
            remote_port: snapshot.remote_addr.port(),
            content_type: request
                .content_type
                .as_deref()
                .map(string_view)
                .unwrap_or_else(empty_view),
            body: bytes_view(&request.body),
        };
        // SAFETY: The runtime is valid and the shim synchronously copies all views.
        let status = unsafe {
            gmv_sip_runtime_send_restored_dialog_request(self.raw.as_ptr(), &ffi_request)
        };
        if status != 0 {
            return Err(pjsip_error("send_restored_dialog_request", status));
        }
        Ok(())
    }

    pub fn respond_invite(&mut self, response: &SipInviteResponse) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot respond to INVITE after runtime stop".into(),
            ));
        }
        if response.call_id.is_empty() || !(200..=699).contains(&response.status_code) {
            return Err(invalid_config(
                "INVITE response requires call_id and status 200..699".into(),
            ));
        }
        if response.status_code < 300
            && (response.content_type.as_deref() != Some("application/sdp")
                || response.body.is_empty())
        {
            return Err(invalid_config(
                "INVITE 2xx requires application/sdp body".into(),
            ));
        }
        if response.call_id.as_bytes().contains(&0)
            || response
                .reason
                .as_deref()
                .is_some_and(|value| value.as_bytes().contains(&0))
            || response
                .content_type
                .as_deref()
                .is_some_and(|value| value.as_bytes().contains(&0))
        {
            return Err(invalid_config(
                "INVITE response strings must contain no NUL byte".into(),
            ));
        }

        let ffi_response = gmv_sip_invite_response_t {
            size: mem::size_of::<gmv_sip_invite_response_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            status_code: response.status_code,
            call_id: string_view(&response.call_id),
            reason: response
                .reason
                .as_deref()
                .map(string_view)
                .unwrap_or_else(empty_view),
            content_type: response
                .content_type
                .as_deref()
                .map(string_view)
                .unwrap_or_else(empty_view),
            body: bytes_view(&response.body),
        };
        // SAFETY: The runtime handle is valid and the shim copies all views
        // before this synchronous call returns.
        let status = unsafe { gmv_sip_runtime_respond_invite(self.raw.as_ptr(), &ffi_response) };
        if status != 0 {
            return Err(pjsip_error("respond_invite", status));
        }
        Ok(())
    }

    pub fn send_subscribe(&mut self, subscribe: &SipOutboundSubscribe) -> Result<()> {
        if self.stopped {
            return Err(invalid_config(
                "cannot send SUBSCRIBE after runtime stop".into(),
            ));
        }
        if subscribe.operation_id == 0 || subscribe.event.is_empty() {
            return Err(invalid_config("operation_id and event are required".into()));
        }
        if subscribe.protocol == SipTransportProtocol::Tls
            || (subscribe.protocol == SipTransportProtocol::Tcp && subscribe.association_id == 0)
        {
            return Err(invalid_config(
                "outbound SUBSCRIBE requires a valid UDP/TCP association".into(),
            ));
        }
        let initial = subscribe.call_id.is_none();
        if initial
            && (subscribe.target_uri.is_empty()
                || subscribe.from_uri.is_empty()
                || subscribe.contact_uri.is_empty()
                || subscribe.expires == 0)
        {
            return Err(invalid_config(
                "initial SUBSCRIBE requires target_uri, from_uri, contact_uri, and expires".into(),
            ));
        }
        if !subscribe.body.is_empty() && !subscribe.content_type.contains('/') {
            return Err(invalid_config(
                "SUBSCRIBE body requires content_type".into(),
            ));
        }
        let contains_nul = [
            subscribe.target_uri.as_str(),
            subscribe.from_uri.as_str(),
            subscribe.contact_uri.as_str(),
            subscribe.event.as_str(),
            subscribe.content_type.as_str(),
        ]
        .into_iter()
        .any(|value| value.as_bytes().contains(&0))
            || subscribe
                .call_id
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.as_bytes().contains(&0));
        if contains_nul {
            return Err(invalid_config(
                "SUBSCRIBE strings must contain no NUL byte".into(),
            ));
        }

        let request = gmv_sip_outbound_subscribe_t {
            size: mem::size_of::<gmv_sip_outbound_subscribe_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            operation_id: subscribe.operation_id,
            association_id: subscribe.association_id,
            transport: transport_id(subscribe.protocol),
            target_uri: string_view(&subscribe.target_uri),
            from_uri: string_view(&subscribe.from_uri),
            contact_uri: string_view(&subscribe.contact_uri),
            call_id: subscribe
                .call_id
                .as_deref()
                .map(string_view)
                .unwrap_or_else(empty_view),
            event: string_view(&subscribe.event),
            expires: subscribe.expires,
            content_type: string_view(&subscribe.content_type),
            body: bytes_view(&subscribe.body),
        };
        // SAFETY: The runtime handle is valid and the shim copies all views
        // before this synchronous call returns.
        let status = unsafe { gmv_sip_runtime_send_subscribe(self.raw.as_ptr(), &request) };
        if status != 0 {
            return Err(pjsip_error("send_subscribe", status));
        }
        Ok(())
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop()
    }
}

impl Drop for SipRuntime {
    fn drop(&mut self) {
        if !self.stopped {
            // SAFETY: Drop has exclusive access to the valid runtime handle.
            let _ = unsafe { gmv_sip_runtime_stop(self.raw.as_ptr()) };
            self.stopped = true;
        }
        // SAFETY: This is the unique destroy paired with runtime create.
        unsafe { gmv_sip_runtime_destroy(self.raw.as_ptr()) };
    }
}

unsafe extern "C" fn runtime_event_callback(event: *const gmv_sip_event_t, user_data: *mut c_void) {
    if event.is_null() || user_data.is_null() {
        return;
    }
    // SAFETY: The shim invokes this callback with valid pointers and keeps
    // EventState alive until the event thread has joined.
    let event = unsafe { &*event };
    if event.version != GMV_SIP_ABI_VERSION
        || (event.size as usize) < mem::size_of::<gmv_sip_event_t>()
    {
        return;
    }
    // SAFETY: `user_data` points to EventState owned by SipRuntime.
    let state = unsafe { &*(user_data.cast::<EventState>()) };
    let _ = state.sender.send(copy_event(event));
}

unsafe extern "C" fn runtime_send_callback(
    packet: *const gmv_sip_send_packet_t,
    user_data: *mut c_void,
) -> i32 {
    if packet.is_null() || user_data.is_null() {
        return -1;
    }
    // SAFETY: The shim provides a valid packet for this callback invocation.
    let packet = unsafe { &*packet };
    if packet.version != GMV_SIP_ABI_VERSION
        || (packet.size as usize) < mem::size_of::<gmv_sip_send_packet_t>()
    {
        return -1;
    }
    // SAFETY: SipRuntime keeps TransmitState alive until after runtime stop.
    let state = unsafe { &*(user_data.cast::<TransmitState>()) };
    let Some(protocol) = copy_transport(packet.transport) else {
        return -1;
    };
    let Some(local_addr) = copy_socket_addr(packet.local_address, packet.local_port) else {
        return -1;
    };
    let Some(remote_addr) = copy_socket_addr(packet.remote_address, packet.remote_port) else {
        return -1;
    };
    let transmit = SipTransmit {
        send_id: packet.send_id,
        transport_id: packet.transport_id,
        association_id: packet.association_id,
        protocol,
        data: copy_bytes_view(packet.data),
        local_addr,
        remote_addr,
    };
    match &state.sender {
        TransmitSender::SocketIo(sender) => i32::from(sender.try_send(transmit).is_ok()) - 1,
        #[cfg(feature = "test-helpers")]
        TransmitSender::Test(sender) => i32::from(sender.try_send(transmit).is_ok()) - 1,
    }
}

unsafe extern "C" fn runtime_log_callback(
    _level: i32,
    message: gmv_sip_string_view_t,
    _user_data: *mut c_void,
) {
    if message.ptr.is_null() || message.len == 0 {
        return;
    }
    // SAFETY: PJSIP supplies a readable message buffer for the callback duration.
    let bytes = unsafe { slice::from_raw_parts(message.ptr.cast::<u8>(), message.len) };
    let message = String::from_utf8_lossy(bytes);
    let message = message.trim_end_matches(['\r', '\n', '\0']);
    base::log::trace!("{message}");
}

fn copy_event(event: &gmv_sip_event_t) -> SipRuntimeEvent {
    SipRuntimeEvent {
        event_id: event.event_id,
        kind: match event.event_type {
            value if value == EVENT_REQUEST_RECEIVED as i32 => SipRuntimeEventKind::RequestReceived,
            value if value == EVENT_RESPONSE_SENT as i32 => SipRuntimeEventKind::ResponseSent,
            value if value == EVENT_RUNTIME_FAULT as i32 => SipRuntimeEventKind::RuntimeFault,
            value if value == EVENT_AUTH_LOOKUP_REQUIRED as i32 => {
                SipRuntimeEventKind::AuthLookupRequired
            }
            value if value == EVENT_REGISTERED as i32 => SipRuntimeEventKind::Registered,
            value if value == EVENT_UNREGISTERED as i32 => SipRuntimeEventKind::Unregistered,
            value if value == EVENT_AUTH_REJECTED as i32 => SipRuntimeEventKind::AuthRejected,
            value if value == EVENT_OUTBOUND_RESPONSE as i32 => {
                SipRuntimeEventKind::OutboundResponse
            }
            value if value == EVENT_INCOMING_INVITE as i32 => SipRuntimeEventKind::IncomingInvite,
            value => SipRuntimeEventKind::Unknown(value),
        },
        protocol: match event.transport {
            value if value == TRANSPORT_UDP as i32 => Some(SipTransportProtocol::Udp),
            value if value == TRANSPORT_TCP as i32 => Some(SipTransportProtocol::Tcp),
            _ => None,
        },
        status_code: u16::try_from(event.status_code)
            .ok()
            .filter(|status| *status != 0),
        pj_status: event.pj_status,
        method: copy_string_view(event.method),
        call_id: copy_string_view(event.call_id),
        cseq: (event.cseq != 0).then_some(event.cseq),
        content_type: copy_string_view(event.content_type),
        body: copy_bytes_view(event.body),
        local_addr: copy_string_view(event.local_address).and_then(|value| value.parse().ok()),
        remote_addr: copy_string_view(event.remote_address).and_then(|value| value.parse().ok()),
        lookup_id: (event.lookup_id != 0).then_some(event.lookup_id),
        device_id: copy_string_view(event.device_id),
        realm: copy_string_view(event.realm),
        expires_seconds: u32::try_from(event.expires_seconds).ok(),
        contact: copy_string_view(event.contact),
        user_agent: copy_string_view(event.user_agent),
        gb_version: copy_string_view(event.gb_version),
        operation_id: (event.operation_id != 0).then_some(event.operation_id),
        association_id: (event.association_id != 0).then_some(event.association_id),
        from_header: copy_string_view(event.from_header),
        to_header: copy_string_view(event.to_header),
        subject: copy_string_view(event.subject),
        event: copy_string_view(event.event),
        subscription_state: copy_string_view(event.subscription_state),
        dialog_snapshot: copy_dialog_snapshot(event),
    }
}

fn copy_dialog_snapshot(event: &gmv_sip_event_t) -> Option<SipDialogSnapshot> {
    let local_cseq = event.dialog_local_cseq;
    if local_cseq == 0 {
        return None;
    }
    Some(SipDialogSnapshot {
        call_id: copy_string_view(event.call_id)?,
        local_uri: copy_string_view(event.dialog_local_uri)?,
        remote_uri: copy_string_view(event.dialog_remote_uri)?,
        local_tag: copy_string_view(event.dialog_local_tag)?,
        remote_tag: copy_string_view(event.dialog_remote_tag)?,
        local_cseq,
        remote_target: copy_string_view(event.dialog_remote_target)?,
        route_set: copy_string_view(event.dialog_route_set)
            .map(|routes| routes.lines().map(str::to_owned).collect())
            .unwrap_or_default(),
        protocol: copy_transport(event.transport)?,
        association_id: event.association_id,
        local_addr: copy_string_view(event.local_address)?.parse().ok()?,
        remote_addr: copy_string_view(event.remote_address)?.parse().ok()?,
    })
}

fn copy_transport(value: i32) -> Option<SipTransportProtocol> {
    match value {
        value if value == TRANSPORT_UDP as i32 => Some(SipTransportProtocol::Udp),
        value if value == TRANSPORT_TCP as i32 => Some(SipTransportProtocol::Tcp),
        _ => None,
    }
}

fn copy_socket_addr(view: gmv_sip_string_view_t, port: u16) -> Option<SocketAddr> {
    let ip = copy_string_view(view)?.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn validate_sockets(config: &SipRuntimeConfig, sockets: &SipRuntimeSockets) -> Result<()> {
    if sockets.udp.is_none() && sockets.tcp.is_none() && sockets.tls.is_none() {
        return Err(invalid_config(
            "at least one SIP UDP, TCP, or TLS socket must be provided".into(),
        ));
    }
    if sockets.udp.is_some() && !config.enable_udp {
        return Err(invalid_config(
            "UDP socket was provided while enable_udp is false".into(),
        ));
    }
    if sockets.tcp.is_some() && !config.enable_tcp {
        return Err(invalid_config(
            "TCP listener was provided while enable_tcp is false".into(),
        ));
    }
    if sockets.tls.is_some() && config.tls.is_none() {
        return Err(invalid_config("TLS listener requires SipTlsConfig".into()));
    }
    Ok(())
}

fn duration_millis(name: &str, duration: Duration) -> Result<u32> {
    let millis = duration.as_millis();
    if millis == 0 {
        return Err(invalid_config(format!(
            "{name} must be at least one millisecond"
        )));
    }
    u32::try_from(millis).map_err(|_| invalid_config(format!("{name} exceeds the C ABI range")))
}

fn empty_view() -> gmv_sip_string_view_t {
    gmv_sip_string_view_t {
        ptr: ptr::null(),
        len: 0,
    }
}

fn string_view(value: &str) -> gmv_sip_string_view_t {
    gmv_sip_string_view_t {
        ptr: value.as_ptr().cast(),
        len: value.len(),
    }
}

fn bytes_view(value: &[u8]) -> gmv_sip_string_view_t {
    gmv_sip_string_view_t {
        ptr: value.as_ptr().cast(),
        len: value.len(),
    }
}

fn invite_to_uri(target_uri: &str, subject: Option<&str>) -> String {
    let Some((_, host)) = target_uri
        .strip_prefix("sip:")
        .and_then(|value| value.split_once('@'))
    else {
        return format!("<{target_uri}>");
    };
    let Some((channel_id, _)) = subject.and_then(|value| value.split_once(':')) else {
        return format!("<{target_uri}>");
    };
    if channel_id.is_empty() || !channel_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return format!("<{target_uri}>");
    }
    format!("<sip:{channel_id}@{host}>")
}

fn transport_id(protocol: SipTransportProtocol) -> i32 {
    match protocol {
        SipTransportProtocol::Udp => TRANSPORT_UDP as i32,
        SipTransportProtocol::Tcp => TRANSPORT_TCP as i32,
        SipTransportProtocol::Tls => 0,
    }
}

fn auth_algorithm_id(algorithm: AuthAlgorithm) -> i32 {
    // SAFETY: These shim functions return stable PJSIP enum values.
    unsafe {
        match algorithm {
            AuthAlgorithm::Md5 => gmv_pjsip_auth_alg_md5(),
            AuthAlgorithm::Sha256 => gmv_pjsip_auth_alg_sha256(),
            AuthAlgorithm::Sha512_256 => gmv_pjsip_auth_alg_sha512_256(),
        }
    }
}

fn credential_type(kind: &CredentialKind) -> i32 {
    // SAFETY: These shim functions return stable PJSIP enum values.
    unsafe {
        match kind {
            CredentialKind::PlainPassword => gmv_pjsip_auth_plain_password_type(),
            CredentialKind::DigestHa1 => gmv_pjsip_auth_digest_type(),
        }
    }
}

fn copy_string_view(view: gmv_sip_string_view_t) -> Option<String> {
    if view.ptr.is_null() || view.len == 0 {
        return None;
    }
    // SAFETY: The callback contract guarantees the view is valid during the
    // callback, and this function immediately copies the bytes.
    let bytes = unsafe { slice::from_raw_parts(view.ptr.cast::<u8>(), view.len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn copy_bytes_view(view: gmv_sip_string_view_t) -> Vec<u8> {
    if view.ptr.is_null() || view.len == 0 {
        return Vec::new();
    }
    // SAFETY: The callback contract guarantees the view is valid during the
    // callback, and this function immediately copies the bytes.
    unsafe { slice::from_raw_parts(view.ptr.cast::<u8>(), view.len) }.to_vec()
}

fn pjsip_error(operation: &'static str, status: i32) -> base::exception::GlobalError {
    let mut buffer = [0 as c_char; 256];
    // SAFETY: `buffer` is writable and its length matches the supplied size.
    let message_status =
        unsafe { gmv_sip_error_message(status, buffer.as_mut_ptr(), buffer.len()) };
    let message = if message_status == 0 {
        // SAFETY: The shim guarantees a NUL-terminated message on success.
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        "unknown PJPROJECT error".into()
    };
    system_error(format!(
        "PJSIP operation `{operation}` failed: status={status}, message={message}"
    ))
}
