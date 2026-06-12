use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::net::{TcpStream, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use gmv_pjsip_sys::{
    gmv_sip_abi_version, gmv_sip_event_t, gmv_sip_runtime_config_init, gmv_sip_runtime_config_t,
    gmv_sip_runtime_create, gmv_sip_runtime_destroy, gmv_sip_runtime_start, gmv_sip_runtime_stop,
    gmv_sip_runtime_t, gmv_sip_runtime_tcp_port, gmv_sip_runtime_udp_port, gmv_sip_string_view_t,
    GMV_SIP_ABI_VERSION,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());

unsafe extern "C" fn count_event(_event: *const gmv_sip_event_t, user_data: *mut c_void) {
    if !user_data.is_null() {
        // SAFETY: The test keeps this AtomicUsize alive until runtime stop.
        let count = unsafe { &*(user_data.cast::<AtomicUsize>()) };
        count.fetch_add(1, Ordering::Relaxed);
    }
}

fn config(events: &AtomicUsize) -> gmv_sip_runtime_config_t {
    let mut config = MaybeUninit::<gmv_sip_runtime_config_t>::uninit();
    // SAFETY: The C initializer writes the complete config structure.
    unsafe { gmv_sip_runtime_config_init(config.as_mut_ptr()) };
    // SAFETY: The initializer completed successfully for a non-null pointer.
    let mut config = unsafe { config.assume_init() };
    static BIND_ADDRESS: &[u8] = b"127.0.0.1";
    config.bind_address = gmv_sip_string_view_t {
        ptr: BIND_ADDRESS.as_ptr().cast(),
        len: BIND_ADDRESS.len(),
    };
    config.port = 0;
    config.enable_udp = 1;
    config.enable_tcp = 1;
    config.event_callback = Some(count_event);
    config.event_user_data = ptr::from_ref(events).cast_mut().cast();
    config
}

fn create_started(events: &AtomicUsize) -> (*mut gmv_sip_runtime_t, u16, u16) {
    let config = config(events);
    let mut runtime = ptr::null_mut();
    // SAFETY: Config and output pointers are valid for the duration of the call.
    let status = unsafe { gmv_sip_runtime_create(&config, &mut runtime) };
    assert_eq!(status, 0);
    assert!(!runtime.is_null());
    // SAFETY: Runtime was created successfully and is exclusively owned here.
    assert_eq!(unsafe { gmv_sip_runtime_start(runtime) }, 0);
    // SAFETY: Runtime remains valid and started.
    let udp_port = unsafe { gmv_sip_runtime_udp_port(runtime) };
    // SAFETY: Runtime remains valid and started.
    let tcp_port = unsafe { gmv_sip_runtime_tcp_port(runtime) };
    assert_ne!(udp_port, 0);
    assert_ne!(tcp_port, 0);
    (runtime, udp_port, tcp_port)
}

fn stop_destroy(runtime: *mut gmv_sip_runtime_t) {
    // SAFETY: Runtime is exclusively owned by this test.
    assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
    // SAFETY: Stop is explicitly idempotent.
    assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
    // SAFETY: Runtime is no longer used after destruction.
    unsafe { gmv_sip_runtime_destroy(runtime) };
}

#[test]
fn abi_rejects_wrong_version() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    // SAFETY: This function takes no pointers and returns the static ABI version.
    let abi_version = unsafe { gmv_sip_abi_version() };
    assert_eq!(abi_version, GMV_SIP_ABI_VERSION);
    let events = AtomicUsize::new(0);
    let mut config = config(&events);
    config.version += 1;
    let mut runtime = ptr::null_mut();
    // SAFETY: Pointers are valid; the invalid version is the behavior under test.
    let status = unsafe { gmv_sip_runtime_create(&config, &mut runtime) };
    assert_ne!(status, 0);
    assert!(runtime.is_null());
}

#[test]
fn runtime_handles_udp_options_and_tcp_message() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    let events = AtomicUsize::new(0);
    let (runtime, udp_port, tcp_port) = create_started(&events);

    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set UDP timeout");
    let udp_local = udp.local_addr().expect("UDP local address");
    let options = format!(
        "OPTIONS sip:127.0.0.1:{udp_port} SIP/2.0\r\n\
Via: SIP/2.0/UDP {udp_local};branch=z9hG4bK-gmv-options;rport\r\n\
From: <sip:test@127.0.0.1>;tag=from-options\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: gmv-options-loopback\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    udp.send_to(options.as_bytes(), ("127.0.0.1", udp_port))
        .expect("send OPTIONS");
    let mut udp_response = [0u8; 2048];
    let (len, _) = udp
        .recv_from(&mut udp_response)
        .expect("receive OPTIONS response");
    assert!(String::from_utf8_lossy(&udp_response[..len]).starts_with("SIP/2.0 200"));

    let mut tcp = TcpStream::connect(("127.0.0.1", tcp_port)).expect("connect TCP client");
    tcp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set TCP timeout");
    let body = "<?xml version=\"1.0\"?><Notify><CmdType>Keepalive</CmdType></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{tcp_port} SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-gmv-message;rport\r\n\
From: <sip:test@127.0.0.1>;tag=from-message\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: gmv-message-loopback\r\n\
CSeq: 1 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    tcp.write_all(message.as_bytes()).expect("send MESSAGE");
    let mut tcp_response = [0u8; 2048];
    let len = tcp
        .read(&mut tcp_response)
        .expect("receive MESSAGE response");
    assert!(String::from_utf8_lossy(&tcp_response[..len]).starts_with("SIP/2.0 200"));

    stop_destroy(runtime);
    assert!(events.load(Ordering::Relaxed) >= 4);
}

#[test]
fn runtime_can_be_created_and_destroyed_repeatedly() {
    let _guard = TEST_LOCK.lock().expect("lock runtime tests");
    let events = AtomicUsize::new(0);
    let config = config(&events);
    let mut runtime = ptr::null_mut();
    // SAFETY: Config and output pointers are valid for the duration of the call.
    assert_eq!(unsafe { gmv_sip_runtime_create(&config, &mut runtime) }, 0);
    assert!(!runtime.is_null());

    for _ in 0..3 {
        // SAFETY: Runtime was created successfully and is exclusively owned here.
        assert_eq!(unsafe { gmv_sip_runtime_start(runtime) }, 0);
        // SAFETY: Runtime remains valid and started.
        assert_ne!(unsafe { gmv_sip_runtime_udp_port(runtime) }, 0);
        // SAFETY: Runtime remains valid and started.
        assert_ne!(unsafe { gmv_sip_runtime_tcp_port(runtime) }, 0);
        // SAFETY: Starting an already started runtime is explicitly idempotent.
        assert_eq!(unsafe { gmv_sip_runtime_start(runtime) }, 0);
        // SAFETY: Runtime is exclusively owned by this test.
        assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
        // SAFETY: Stop is explicitly idempotent.
        assert_eq!(unsafe { gmv_sip_runtime_stop(runtime) }, 0);
    }

    // SAFETY: Runtime is no longer used after destruction.
    unsafe { gmv_sip_runtime_destroy(runtime) };
}
