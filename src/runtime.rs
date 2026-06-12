use std::ffi::{c_char, c_void, CStr};
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::slice;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use gmv_pjsip_sys::{
    gmv_pjsip_auth_alg_md5, gmv_pjsip_auth_alg_sha256, gmv_pjsip_auth_alg_sha512_256,
    gmv_pjsip_auth_digest_type, gmv_pjsip_auth_plain_password_type,
    gmv_sip_auth_lookup_completion_t,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_BYPASS as AUTH_BYPASS,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_CREDENTIAL as AUTH_CREDENTIAL,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_NOT_FOUND as AUTH_NOT_FOUND,
    gmv_sip_auth_lookup_result_GMV_SIP_AUTH_REJECT as AUTH_REJECT, gmv_sip_error_message,
    gmv_sip_event_t,
    gmv_sip_event_type_GMV_SIP_EVENT_AUTH_LOOKUP_REQUIRED as EVENT_AUTH_LOOKUP_REQUIRED,
    gmv_sip_event_type_GMV_SIP_EVENT_AUTH_REJECTED as EVENT_AUTH_REJECTED,
    gmv_sip_event_type_GMV_SIP_EVENT_OUTBOUND_RESPONSE as EVENT_OUTBOUND_RESPONSE,
    gmv_sip_event_type_GMV_SIP_EVENT_REGISTERED as EVENT_REGISTERED,
    gmv_sip_event_type_GMV_SIP_EVENT_REQUEST_RECEIVED as EVENT_REQUEST_RECEIVED,
    gmv_sip_event_type_GMV_SIP_EVENT_RESPONSE_SENT as EVENT_RESPONSE_SENT,
    gmv_sip_event_type_GMV_SIP_EVENT_RUNTIME_FAULT as EVENT_RUNTIME_FAULT,
    gmv_sip_event_type_GMV_SIP_EVENT_UNREGISTERED as EVENT_UNREGISTERED,
    gmv_sip_outbound_message_t, gmv_sip_runtime_complete_auth_lookup, gmv_sip_runtime_config_init,
    gmv_sip_runtime_config_t, gmv_sip_runtime_create, gmv_sip_runtime_destroy,
    gmv_sip_runtime_send_message, gmv_sip_runtime_start, gmv_sip_runtime_stop, gmv_sip_runtime_t,
    gmv_sip_runtime_tcp_port, gmv_sip_runtime_udp_port, gmv_sip_string_view_t,
    gmv_sip_transport_GMV_SIP_TRANSPORT_TCP as TRANSPORT_TCP,
    gmv_sip_transport_GMV_SIP_TRANSPORT_UDP as TRANSPORT_UDP, GMV_SIP_ABI_VERSION,
};

use crate::auth::{AuthAlgorithm, AuthCredential, CredentialKind};
use crate::error::{Result, SipError};
use crate::transport::SipTransportProtocol;

static RUNTIME_LOCK: Mutex<()> = Mutex::new(());

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
        }
    }
}

impl SipRuntimeConfig {
    fn validate(&self) -> Result<(u32, u32)> {
        if !self.enable_udp && !self.enable_tcp {
            return Err(SipError::InvalidConfig(
                "at least one of UDP or TCP must be enabled".into(),
            ));
        }
        if self.async_count == 0 {
            return Err(SipError::InvalidConfig(
                "async_count must be greater than zero".into(),
            ));
        }
        if self.auth_realm.is_empty() || self.auth_realm.as_bytes().contains(&0) {
            return Err(SipError::InvalidConfig(
                "auth_realm must be non-empty and contain no NUL byte".into(),
            ));
        }
        if self.max_pending_auth == 0 {
            return Err(SipError::InvalidConfig(
                "max_pending_auth must be greater than zero".into(),
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
}

pub type SipRuntimeEvents = Receiver<SipRuntimeEvent>;

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
    pub target_uri: String,
    pub from_uri: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

struct EventState {
    sender: Sender<SipRuntimeEvent>,
}

pub struct SipRuntime {
    raw: NonNull<gmv_sip_runtime_t>,
    stopped: bool,
    _event_state: Box<EventState>,
    _runtime_guard: MutexGuard<'static, ()>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl SipRuntime {
    pub fn start(config: SipRuntimeConfig) -> Result<(Self, SipRuntimeEvents)> {
        let (poll_timeout_ms, auth_lookup_timeout_ms) = config.validate()?;
        let runtime_guard = match RUNTIME_LOCK.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(SipError::RuntimeActive),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };

        let bind_address = config.bind_address.to_string();
        let auth_realm = config.auth_realm.as_bytes();
        let (sender, events) = mpsc::channel();
        let mut event_state = Box::new(EventState { sender });

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

        let mut raw = ptr::null_mut();
        // SAFETY: The config, callback state, and output pointer remain valid
        // for the duration of this call. The C runtime copies config strings.
        let status = unsafe { gmv_sip_runtime_create(&ffi_config, &mut raw) };
        if status != 0 {
            return Err(pjsip_error("runtime_create", status));
        }
        let raw = NonNull::new(raw).ok_or_else(|| {
            SipError::Internal("PJSIP runtime create returned a null handle".into())
        })?;

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
                _event_state: event_state,
                _runtime_guard: runtime_guard,
                _not_send_or_sync: PhantomData,
            },
            events,
        ))
    }

    pub fn udp_port(&self) -> Option<u16> {
        if self.stopped {
            return None;
        }
        // SAFETY: The runtime handle is valid while `self` is alive.
        let port = unsafe { gmv_sip_runtime_udp_port(self.raw.as_ptr()) };
        (port != 0).then_some(port)
    }

    pub fn tcp_port(&self) -> Option<u16> {
        if self.stopped {
            return None;
        }
        // SAFETY: The runtime handle is valid while `self` is alive.
        let port = unsafe { gmv_sip_runtime_tcp_port(self.raw.as_ptr()) };
        (port != 0).then_some(port)
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

    pub fn complete_auth_lookup(
        &mut self,
        lookup_id: u64,
        result: SipAuthLookupResult,
    ) -> Result<()> {
        if self.stopped {
            return Err(SipError::InvalidConfig(
                "cannot complete auth lookup after runtime stop".into(),
            ));
        }
        if lookup_id == 0 {
            return Err(SipError::InvalidConfig("lookup_id must be non-zero".into()));
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

    pub fn send_message(&mut self, message: &SipOutboundMessage) -> Result<()> {
        if self.stopped {
            return Err(SipError::InvalidConfig(
                "cannot send MESSAGE after runtime stop".into(),
            ));
        }
        if message.operation_id == 0 {
            return Err(SipError::InvalidConfig(
                "operation_id must be non-zero".into(),
            ));
        }
        if message.target_uri.is_empty()
            || message.from_uri.is_empty()
            || !message.content_type.contains('/')
            || message.target_uri.as_bytes().contains(&0)
            || message.from_uri.as_bytes().contains(&0)
            || message.content_type.as_bytes().contains(&0)
        {
            return Err(SipError::InvalidConfig(
                "target_uri, from_uri, and content_type are required".into(),
            ));
        }

        let request = gmv_sip_outbound_message_t {
            size: mem::size_of::<gmv_sip_outbound_message_t>() as u32,
            version: GMV_SIP_ABI_VERSION,
            operation_id: message.operation_id,
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
    }
}

fn duration_millis(name: &str, duration: Duration) -> Result<u32> {
    let millis = duration.as_millis();
    if millis == 0 {
        return Err(SipError::InvalidConfig(format!(
            "{name} must be at least one millisecond"
        )));
    }
    u32::try_from(millis)
        .map_err(|_| SipError::InvalidConfig(format!("{name} exceeds the C ABI range")))
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

fn pjsip_error(operation: &'static str, status: i32) -> SipError {
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
    SipError::Pjsip {
        operation,
        status,
        message,
    }
}
