use std::ffi::c_void;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use gmv_pjsip_sys::{
    gmv_sip_abi_version, gmv_sip_event_t, gmv_sip_received_packet_t, gmv_sip_runtime_complete_send,
    gmv_sip_runtime_config_init, gmv_sip_runtime_config_t, gmv_sip_runtime_create,
    gmv_sip_runtime_destroy, gmv_sip_runtime_poll, gmv_sip_runtime_receive_packet,
    gmv_sip_runtime_start, gmv_sip_runtime_stop, gmv_sip_runtime_t, gmv_sip_send_completion_t,
    gmv_sip_send_packet_t, gmv_sip_string_view_t,
    gmv_sip_transport_GMV_SIP_TRANSPORT_UDP as TRANSPORT_UDP, GMV_SIP_ABI_VERSION,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static BIND_ADDRESS: &[u8] = b"127.0.0.1";
static REMOTE_ADDRESS: &[u8] = b"127.0.0.1";

struct CallbackState {
    events: AtomicUsize,
    sends: AtomicUsize,
    send_id: AtomicU64,
    send_len: AtomicUsize,
}

impl CallbackState {
    fn new() -> Self {
        Self {
            events: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            send_id: AtomicU64::new(0),
            send_len: AtomicUsize::new(0),
        }
    }
}

unsafe extern "C" fn count_event(_event: *const gmv_sip_event_t, user_data: *mut c_void) {
    if !user_data.is_null() {
        // SAFETY: The test keeps CallbackState alive until runtime stop.
        let state = unsafe { &*(user_data.cast::<CallbackState>()) };
        state.events.fetch_add(1, Ordering::Release);
    }
}

unsafe extern "C" fn capture_send(
    packet: *const gmv_sip_send_packet_t,
    user_data: *mut c_void,
) -> i32 {
    if packet.is_null() || user_data.is_null() {
        return -1;
    }
    // SAFETY: The shim supplies a valid packet for this callback invocation.
    let packet = unsafe { &*packet };
    // SAFETY: The test keeps CallbackState alive until runtime stop.
    let state = unsafe { &*(user_data.cast::<CallbackState>()) };
    state.send_len.store(packet.data.len, Ordering::Relaxed);
    state.send_id.store(packet.send_id, Ordering::Relaxed);
    state.sends.fetch_add(1, Ordering::Release);
    0
}

fn view(value: &'static [u8]) -> gmv_sip_string_view_t {
    gmv_sip_string_view_t {
        ptr: value.as_ptr().cast(),
        len: value.len(),
    }
}

fn config(state: &CallbackState) -> gmv_sip_runtime_config_t {
    let mut config = MaybeUninit::<gmv_sip_runtime_config_t>::uninit();
    // SAFETY: The C initializer writes the complete config structure.
    unsafe { gmv_sip_runtime_config_init(config.as_mut_ptr()) };
    // SAFETY: The initializer completed successfully for a non-null pointer.
    let mut config = unsafe { config.assume_init() };
    config.bind_address = view(BIND_ADDRESS);
    config.port = 5060;
    config.enable_udp = 1;
    config.enable_tcp = 1;
    config.event_callback = Some(count_event);
    config.event_user_data = ptr::from_ref(state).cast_mut().cast();
    config.send_callback = Some(capture_send);
    config.send_user_data = ptr::from_ref(state).cast_mut().cast();
    config
}

fn create_started(state: &CallbackState) -> *mut gmv_sip_runtime_t {
    let config = config(state);
    let mut runtime = ptr::null_mut();
    // SAFETY: Config and output pointers are valid for the duration of the call.
    let status = unsafe { gmv_sip_runtime_create(&config, &mut runtime) };
    assert_eq!(status, 0);
    assert!(!runtime.is_null());
    // SAFETY: Runtime was created successfully and is exclusively owned here.
    assert_eq!(unsafe { gmv_sip_runtime_start(runtime) }, 0);
    runtime
}

fn stop_destroy(runtime: *mut gmv_sip_runtime_t) {
    // SAFETY: Runtime is exclusively owned by this test.
    assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
    // SAFETY: Stop is explicitly idempotent.
    assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
    // SAFETY: Runtime is no longer used after destruction.
    unsafe { gmv_sip_runtime_destroy(runtime) };
}

fn wait_for_send(runtime: *mut gmv_sip_runtime_t, state: &CallbackState) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        // SAFETY: Runtime remains valid and is polled by its creating thread.
        assert_eq!(unsafe { gmv_sip_runtime_poll(runtime) }, 0);
        if state.sends.load(Ordering::Acquire) > 0 {
            return state.send_id.load(Ordering::Relaxed);
        }
    }
    panic!("timed out waiting for send callback");
}

#[test]
fn abi_rejects_wrong_version() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    // SAFETY: This function takes no pointers and returns the static ABI version.
    assert_eq!(unsafe { gmv_sip_abi_version() }, GMV_SIP_ABI_VERSION);
    let state = CallbackState::new();
    let mut config = config(&state);
    config.version += 1;
    let mut runtime = ptr::null_mut();
    // SAFETY: Pointers are valid; the invalid version is the behavior under test.
    let status = unsafe { gmv_sip_runtime_create(&config, &mut runtime) };
    assert_ne!(status, 0);
    assert!(runtime.is_null());
}

#[test]
fn abi_rejects_invalid_log_level() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    let state = CallbackState::new();
    let mut config = config(&state);
    config.log_level = 6;
    let mut runtime = ptr::null_mut();
    // SAFETY: Pointers are valid; the invalid log level is the behavior under test.
    let status = unsafe { gmv_sip_runtime_create(&config, &mut runtime) };
    assert_ne!(status, 0);
    assert!(runtime.is_null());
}

#[test]
fn runtime_injects_udp_and_completes_async_send() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    let state = CallbackState::new();
    let runtime = create_started(&state);

    static OPTIONS: &[u8] = b"OPTIONS sip:127.0.0.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:40000;branch=z9hG4bK-sys;rport\r\n\
From: <sip:test@127.0.0.1>;tag=sys\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: sys-options\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n";
    let packet = gmv_sip_received_packet_t {
        size: mem::size_of::<gmv_sip_received_packet_t>() as u32,
        version: GMV_SIP_ABI_VERSION,
        association_id: 0,
        transport: TRANSPORT_UDP as i32,
        data: view(OPTIONS),
        local_address: view(BIND_ADDRESS),
        local_port: 5060,
        remote_address: view(REMOTE_ADDRESS),
        remote_port: 40000,
    };
    // SAFETY: Runtime and packet pointers are valid; the shim copies all views.
    assert_eq!(
        unsafe { gmv_sip_runtime_receive_packet(runtime, &packet) },
        0
    );

    let send_id = wait_for_send(runtime, &state);
    assert_ne!(send_id, 0);
    assert!(state.send_len.load(Ordering::Relaxed) > 0);
    let completion = gmv_sip_send_completion_t {
        size: mem::size_of::<gmv_sip_send_completion_t>() as u32,
        version: GMV_SIP_ABI_VERSION,
        send_id,
        sent_bytes: state.send_len.load(Ordering::Relaxed) as i64,
    };
    // SAFETY: Runtime and completion pointers are valid for this call.
    assert_eq!(
        unsafe { gmv_sip_runtime_complete_send(runtime, &completion) },
        0
    );
    // SAFETY: Runtime remains valid and consumes the queued send completion.
    assert_eq!(unsafe { gmv_sip_runtime_poll(runtime) }, 0);

    let deadline = Instant::now() + Duration::from_secs(2);
    while state.events.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        // SAFETY: Runtime remains valid and is polled by its creating thread.
        assert_eq!(unsafe { gmv_sip_runtime_poll(runtime) }, 0);
    }
    assert!(state.events.load(Ordering::Relaxed) >= 2);
    stop_destroy(runtime);
}

#[test]
fn runtime_can_be_created_and_destroyed_repeatedly() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    let state = CallbackState::new();
    let config = config(&state);
    let mut runtime = ptr::null_mut();
    // SAFETY: Config and output pointers are valid for the duration of the call.
    assert_eq!(unsafe { gmv_sip_runtime_create(&config, &mut runtime) }, 0);

    for _ in 0..3 {
        // SAFETY: Runtime was created successfully and is exclusively owned here.
        assert_eq!(unsafe { gmv_sip_runtime_start(runtime) }, 0);
        // SAFETY: Starting an already started runtime is explicitly idempotent.
        assert_eq!(unsafe { gmv_sip_runtime_start(runtime) }, 0);
        // SAFETY: Runtime is exclusively owned by this test.
        assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
    }

    // SAFETY: Runtime is no longer used after destruction.
    unsafe { gmv_sip_runtime_destroy(runtime) };
}
