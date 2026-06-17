use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

use gmv_pjsip::{
    SipAuthLookupResult, SipDialogMethod, SipDialogRequest, SipError, SipInviteResponse,
    SipOutboundInvite, SipOutboundMessage, SipOutboundSubscribe, SipRuntime, SipRuntimeConfig,
    SipRuntimeEvent, SipRuntimeEventKind, SipRuntimeSockets, SipRuntimeTransmits, SipTransmit,
    SipTransportProtocol,
};
use log::{LevelFilter, Log, Metadata, Record};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static TEST_LOG_INIT: Once = Once::new();
static TEST_LOGGER: TestLogger = TestLogger {
    messages: Mutex::new(Vec::new()),
};
const LOCAL_PORT: u16 = 5060;
const TEST_LOG_TARGET: &str = "gmv_pjsip::test";

struct TestLogger {
    messages: Mutex<Vec<String>>,
}

impl Log for TestLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == TEST_LOG_TARGET
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            self.messages
                .lock()
                .expect("lock test log messages")
                .push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn init_test_logger() {
    TEST_LOG_INIT.call_once(|| {
        log::set_logger(&TEST_LOGGER).expect("install test logger");
        log::set_max_level(LevelFilter::Debug);
    });
}

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn local_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, LOCAL_PORT))
}

fn remote_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn start_runtime(
    mut config: SipRuntimeConfig,
) -> (SipRuntime, Receiver<SipRuntimeEvent>, SipRuntimeTransmits) {
    config.port = LOCAL_PORT;
    SipRuntime::start_for_test(config).expect("start runtime")
}

fn receive_event(
    runtime: &mut SipRuntime,
    events: &Receiver<SipRuntimeEvent>,
    kind: SipRuntimeEventKind,
) -> SipRuntimeEvent {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        runtime.poll().expect("poll runtime");
        while let Ok(event) = events.try_recv() {
            if event.kind == kind {
                return event;
            }
        }
    }
    panic!("timed out waiting for {kind:?}");
}

fn receive_transmit(runtime: &mut SipRuntime, transmits: &SipRuntimeTransmits) -> SipTransmit {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        runtime.poll().expect("poll runtime");
        if let Ok(transmit) = transmits.try_recv() {
            return transmit;
        }
    }
    panic!("timed out waiting for custom transport transmit");
}

fn finish_transmit(runtime: &mut SipRuntime, transmit: &SipTransmit) -> String {
    runtime
        .complete_test_send(transmit.send_id, Ok(transmit.data.len()))
        .expect("complete custom transport send");
    String::from_utf8_lossy(&transmit.data).into_owned()
}

fn header_value<'a>(message: &'a str, name: &str) -> &'a str {
    message
        .lines()
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header.eq_ignore_ascii_case(name).then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("missing {name} header"))
}

#[test]
fn runtime_rejects_invalid_transport_config() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_udp: false,
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let error = match SipRuntime::start_for_test(config) {
        Ok(_) => panic!("runtime unexpectedly accepted invalid config"),
        Err(error) => error,
    };
    assert!(matches!(error, SipError::InvalidConfig(_)));
}

#[test]
fn runtime_rejects_empty_log_target() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        log_target: String::new(),
        ..SipRuntimeConfig::default()
    };
    let error = match SipRuntime::start_for_test(config) {
        Ok(_) => panic!("runtime unexpectedly accepted empty log target"),
        Err(error) => error,
    };
    assert!(matches!(error, SipError::InvalidConfig(_)));
}

#[test]
fn pjsip_logs_are_bridged_to_the_rust_log_facade() {
    let _guard = lock_tests();
    init_test_logger();
    TEST_LOGGER
        .messages
        .lock()
        .expect("lock test log messages")
        .clear();
    let config = SipRuntimeConfig {
        log_target: TEST_LOG_TARGET.into(),
        ..SipRuntimeConfig::default()
    };
    let (runtime, _events, _transmits) = start_runtime(config);
    runtime.shutdown().expect("shutdown runtime");
    assert!(!TEST_LOGGER
        .messages
        .lock()
        .expect("lock test log messages")
        .is_empty());
}

#[test]
fn runtime_enforces_one_active_instance() {
    let _guard = lock_tests();
    let (runtime, _events, _transmits) = start_runtime(SipRuntimeConfig::default());
    let error = match SipRuntime::start_for_test(SipRuntimeConfig::default()) {
        Ok(_) => panic!("second runtime unexpectedly started"),
        Err(error) => error,
    };
    assert!(matches!(error, SipError::RuntimeActive));
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_owns_inherited_udp_socket() {
    let _guard = lock_tests();
    let runtime_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind runtime UDP");
    let runtime_addr = runtime_socket.local_addr().expect("runtime UDP address");
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind peer UDP");
    peer.set_nonblocking(true).expect("set peer nonblocking");
    let peer_addr = peer.local_addr().expect("peer UDP address");
    let config = SipRuntimeConfig {
        bind_address: Ipv4Addr::LOCALHOST,
        port: runtime_addr.port(),
        enable_tcp: false,
        log_target: TEST_LOG_TARGET.into(),
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, _events) = SipRuntime::start(
        config,
        SipRuntimeSockets {
            udp: Some(runtime_socket),
            tcp: None,
            tls: None,
        },
    )
    .expect("start socket-owned runtime");
    let request = format!(
        "OPTIONS sip:{runtime_addr} SIP/2.0\r\n\
Via: SIP/2.0/UDP {peer_addr};branch=z9hG4bK-owned-udp;rport\r\n\
From: <sip:test@127.0.0.1>;tag=owned-udp\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: owned-udp-loopback\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    peer.send_to(request.as_bytes(), runtime_addr)
        .expect("send OPTIONS to runtime");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buffer = [0; 4096];
    while Instant::now() < deadline {
        runtime.poll().expect("poll runtime");
        match peer.recv_from(&mut buffer) {
            Ok((len, _)) => {
                let response = String::from_utf8_lossy(&buffer[..len]);
                assert!(response.starts_with("SIP/2.0 200"), "{response}");
                runtime.shutdown().expect("shutdown runtime");
                return;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("receive OPTIONS response: {err}"),
        }
    }
    panic!("timed out waiting for UDP response");
}

#[test]
fn runtime_adapter_handles_udp_and_fragmented_tcp() {
    let _guard = lock_tests();
    init_test_logger();
    TEST_LOGGER
        .messages
        .lock()
        .expect("lock test log messages")
        .clear();
    let config = SipRuntimeConfig {
        log_target: TEST_LOG_TARGET.into(),
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);

    let udp_remote = remote_addr(40000);
    let options = format!(
        "OPTIONS sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/UDP {udp_remote};branch=z9hG4bK-options;rport\r\n\
From: <sip:test@127.0.0.1>;tag=options\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: custom-options\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            udp_remote,
            options.as_bytes(),
        )
        .expect("inject UDP OPTIONS");
    let transmit = receive_transmit(&mut runtime, &transmits);
    assert_eq!(transmit.protocol, SipTransportProtocol::Udp);
    assert_eq!(transmit.association_id, 0);
    assert_eq!(transmit.local_addr, local_addr());
    assert_eq!(transmit.remote_addr, udp_remote);
    let response = finish_transmit(&mut runtime, &transmit);
    assert!(response.starts_with("SIP/2.0 200"));
    assert!(response.contains("\r\nAllow: REGISTER, MESSAGE, OPTIONS\r\n"));

    let tcp_remote = remote_addr(40001);
    let body = "<?xml version=\"1.0\"?><Notify><CmdType>Keepalive</CmdType></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/TCP {tcp_remote};branch=z9hG4bK-message;rport\r\n\
From: <sip:test@127.0.0.1>;tag=message\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: custom-message\r\n\
CSeq: 1 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let split = message.len() / 2;
    runtime
        .inject_test_packet(
            7,
            SipTransportProtocol::Tcp,
            local_addr(),
            tcp_remote,
            &message.as_bytes()[..split],
        )
        .expect("inject first TCP fragment");
    runtime.poll().expect("poll first TCP fragment");
    assert!(matches!(
        transmits.recv_timeout(Duration::from_millis(50)),
        Err(RecvTimeoutError::Timeout)
    ));
    runtime
        .inject_test_packet(
            7,
            SipTransportProtocol::Tcp,
            local_addr(),
            tcp_remote,
            &message.as_bytes()[split..],
        )
        .expect("inject second TCP fragment");
    let transmit = receive_transmit(&mut runtime, &transmits);
    assert_eq!(transmit.protocol, SipTransportProtocol::Tcp);
    assert_eq!(transmit.association_id, 7);
    assert_eq!(transmit.remote_addr, tcp_remote);
    assert!(finish_transmit(&mut runtime, &transmit).starts_with("SIP/2.0 200"));

    let options_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(options_event.method.as_deref(), Some("OPTIONS"));
    let _options_response = receive_event(&mut runtime, &events, SipRuntimeEventKind::ResponseSent);
    let message_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(message_event.method.as_deref(), Some("MESSAGE"));
    assert_eq!(message_event.body, body.as_bytes());
    let _message_response = receive_event(&mut runtime, &events, SipRuntimeEventKind::ResponseSent);

    let sticky_message = |call_id: &str, cseq: u32| {
        format!(
            "MESSAGE sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/TCP {tcp_remote};branch=z9hG4bK-{call_id};rport\r\n\
From: <sip:test@127.0.0.1>;tag={call_id}\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
        )
    };
    let sticky_first = sticky_message("tcp-sticky-1", 2);
    let sticky_second = sticky_message("tcp-sticky-2", 3);
    let sticky_third = sticky_message("tcp-sticky-3", 4);
    let third_split = sticky_third.len() - 7;
    let sticky_head = [
        sticky_first.as_bytes(),
        sticky_second.as_bytes(),
        &sticky_third.as_bytes()[..third_split],
    ]
    .concat();
    runtime
        .inject_test_packet(
            7,
            SipTransportProtocol::Tcp,
            local_addr(),
            tcp_remote,
            &sticky_head,
        )
        .expect("inject sticky TCP head");
    let first_transmit = receive_transmit(&mut runtime, &transmits);
    let first_response = finish_transmit(&mut runtime, &first_transmit);
    assert!(first_response.contains("\r\nCSeq: 2 MESSAGE\r\n"));
    let second_transmit = receive_transmit(&mut runtime, &transmits);
    let second_response = finish_transmit(&mut runtime, &second_transmit);
    assert!(second_response.contains("\r\nCSeq: 3 MESSAGE\r\n"));
    let logs = TEST_LOGGER
        .messages
        .lock()
        .expect("lock test log messages")
        .clone();
    assert!(logs
        .iter()
        .any(|message| message.contains("complete SIP packet")
            && message.contains("\\r\\nCSeq: 2 MESSAGE\\r\\n")
            && !message.contains("\\r\\nCSeq: 3 MESSAGE\\r\\n")
            && !message.contains("\r\nCSeq:")));
    assert!(logs
        .iter()
        .any(|message| message.contains("complete SIP packet")
            && message.contains("\\r\\nCSeq: 3 MESSAGE\\r\\n")
            && !message.contains("\\r\\nCSeq: 2 MESSAGE\\r\\n")
            && !message.contains("\r\nCSeq:")));
    runtime
        .inject_test_packet(
            7,
            SipTransportProtocol::Tcp,
            local_addr(),
            tcp_remote,
            &sticky_third.as_bytes()[third_split..],
        )
        .expect("inject sticky TCP tail");
    let third_transmit = receive_transmit(&mut runtime, &transmits);
    let third_response = finish_transmit(&mut runtime, &third_transmit);
    assert!(third_response.contains("\r\nCSeq: 4 MESSAGE\r\n"));

    runtime
        .close_transport(7, SipTransportProtocol::Tcp, 0)
        .expect("close TCP custom transport");
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_completes_register_auth_asynchronously() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40002);
    let username = "34020000001320000001";
    let request = format!(
        "REGISTER sip:3402000000@127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/UDP {remote};branch=z9hG4bK-register;rport\r\n\
From: <sip:{username}@3402000000>;tag=register\r\n\
To: <sip:{username}@3402000000>\r\n\
Call-ID: custom-register\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:{username}@{remote}>\r\n\
Expires: 3600\r\n\
User-Agent: GMV-Test-Device/1.0\r\n\
X-GB-Ver: 3.0\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            request.as_bytes(),
        )
        .expect("inject REGISTER");

    let lookup = receive_event(
        &mut runtime,
        &events,
        SipRuntimeEventKind::AuthLookupRequired,
    );
    assert_eq!(lookup.device_id.as_deref(), Some(username));
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("lookup id"),
            SipAuthLookupResult::Bypass,
        )
        .expect("complete auth lookup");

    let transmit = receive_transmit(&mut runtime, &transmits);
    let response = finish_transmit(&mut runtime, &transmit);
    assert!(response.starts_with("SIP/2.0 200"));
    assert_eq!(header_value(&response, "X-GB-Ver"), "3.0");

    let registered = receive_event(&mut runtime, &events, SipRuntimeEventKind::Registered);
    assert_eq!(registered.device_id.as_deref(), Some(username));
    assert_eq!(registered.expires_seconds, Some(3600));
    assert_eq!(
        registered.user_agent.as_deref(),
        Some("GMV-Test-Device/1.0")
    );
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_sends_message_and_correlates_response() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40003);
    let operation_id = 42;
    runtime
        .send_message(&SipOutboundMessage {
            operation_id,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            content_type: "Application/MANSCDP+xml".into(),
            body: b"<?xml version=\"1.0\"?><Query><CmdType>DeviceInfo</CmdType></Query>".to_vec(),
        })
        .expect("send outbound MESSAGE");

    let transmit = receive_transmit(&mut runtime, &transmits);
    assert_eq!(transmit.protocol, SipTransportProtocol::Udp);
    assert_eq!(transmit.remote_addr, remote);
    let request = finish_transmit(&mut runtime, &transmit);
    assert!(request.starts_with("MESSAGE "));
    assert!(request.contains("<CmdType>DeviceInfo</CmdType>"));

    let response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=peer\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&request, "Via"),
        header_value(&request, "From"),
        header_value(&request, "To"),
        header_value(&request, "Call-ID"),
        header_value(&request, "CSeq"),
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            response.as_bytes(),
        )
        .expect("inject outbound response");

    let event = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(event.operation_id, Some(operation_id));
    assert_eq!(event.status_code, Some(200));
    assert_eq!(event.method.as_deref(), Some("MESSAGE"));
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_owns_invite_dialog_info_and_bye() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40004);
    let invite_operation = 100;
    let local_sdp = "v=0\r\n\
o=34020000002000000001 0 0 IN IP4 127.0.0.1\r\n\
s=Play\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=video 30000 RTP/AVP 96\r\n\
a=recvonly\r\n\
a=rtpmap:96 PS/90000\r\n\
y=0100000001\r\n";
    runtime
        .send_invite(&SipOutboundInvite {
            operation_id: invite_operation,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            contact_uri: format!("<sip:platform@{}>", local_addr()),
            subject: Some("device:0100000001,platform:0100000001".into()),
            sdp: local_sdp.into(),
        })
        .expect("send outbound INVITE");

    let invite_transmit = receive_transmit(&mut runtime, &transmits);
    let invite = finish_transmit(&mut runtime, &invite_transmit);
    assert!(invite.starts_with("INVITE "));
    assert_eq!(
        header_value(&invite, "Subject"),
        "device:0100000001,platform:0100000001"
    );
    let remote_sdp = "v=0\r\n\
o=device 0 0 IN IP4 127.0.0.1\r\n\
s=Play\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=video 40000 RTP/AVP 96\r\n\
a=sendonly\r\n\
a=rtpmap:96 PS/90000\r\n\
y=0100000001\r\n";
    let invite_response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=peer-invite\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Contact: <sip:device@{remote}>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
        header_value(&invite, "Via"),
        header_value(&invite, "From"),
        header_value(&invite, "To"),
        header_value(&invite, "Call-ID"),
        header_value(&invite, "CSeq"),
        remote_sdp.len(),
        remote_sdp,
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            invite_response.as_bytes(),
        )
        .expect("inject INVITE response");

    let invite_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(invite_event.operation_id, Some(invite_operation));
    assert_eq!(invite_event.method.as_deref(), Some("INVITE"));
    assert_eq!(invite_event.status_code, Some(200));
    assert_eq!(invite_event.body, remote_sdp.as_bytes());
    let call_id = invite_event.call_id.clone().expect("INVITE call id");
    let ack = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &ack).starts_with("ACK "));

    let info_operation = 101;
    runtime
        .send_dialog_request(&SipDialogRequest {
            operation_id: info_operation,
            method: SipDialogMethod::Info,
            call_id: call_id.clone(),
            content_type: Some("Application/MANSRTSP".into()),
            body: b"PLAY RTSP/1.0\r\nCSeq: 1\r\nScale: 2.0\r\n".to_vec(),
        })
        .expect("send INFO");
    let info_transmit = receive_transmit(&mut runtime, &transmits);
    let info = finish_transmit(&mut runtime, &info_transmit);
    assert!(info.starts_with("INFO "));
    let info_response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&info, "Via"),
        header_value(&info, "From"),
        header_value(&info, "To"),
        header_value(&info, "Call-ID"),
        header_value(&info, "CSeq"),
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            info_response.as_bytes(),
        )
        .expect("inject INFO response");
    let info_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(info_event.operation_id, Some(info_operation));
    assert_eq!(info_event.method.as_deref(), Some("INFO"));
    assert_eq!(info_event.status_code, Some(200));

    let bye_operation = 102;
    runtime
        .send_dialog_request(&SipDialogRequest {
            operation_id: bye_operation,
            method: SipDialogMethod::Bye,
            call_id,
            content_type: None,
            body: Vec::new(),
        })
        .expect("send BYE");
    let bye_transmit = receive_transmit(&mut runtime, &transmits);
    let bye = finish_transmit(&mut runtime, &bye_transmit);
    assert!(bye.starts_with("BYE "));
    let bye_response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&bye, "Via"),
        header_value(&bye, "From"),
        header_value(&bye, "To"),
        header_value(&bye, "Call-ID"),
        header_value(&bye, "CSeq"),
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            bye_response.as_bytes(),
        )
        .expect("inject BYE response");
    let bye_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(bye_event.operation_id, Some(bye_operation));
    assert_eq!(bye_event.method.as_deref(), Some("BYE"));
    assert_eq!(bye_event.status_code, Some(200));

    let remote_bye_invite_operation = 103;
    runtime
        .send_invite(&SipOutboundInvite {
            operation_id: remote_bye_invite_operation,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            contact_uri: format!("<sip:platform@{}>", local_addr()),
            subject: Some("device:0100000002,platform:0100000002".into()),
            sdp: local_sdp.into(),
        })
        .expect("send second outbound INVITE");
    let second_invite_transmit = receive_transmit(&mut runtime, &transmits);
    let second_invite = finish_transmit(&mut runtime, &second_invite_transmit);
    let second_invite_response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=peer-remote-bye\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Contact: <sip:device@{remote}>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
        header_value(&second_invite, "Via"),
        header_value(&second_invite, "From"),
        header_value(&second_invite, "To"),
        header_value(&second_invite, "Call-ID"),
        header_value(&second_invite, "CSeq"),
        remote_sdp.len(),
        remote_sdp,
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            second_invite_response.as_bytes(),
        )
        .expect("inject second INVITE response");
    let second_invite_event =
        receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(
        second_invite_event.operation_id,
        Some(remote_bye_invite_operation)
    );
    let second_call_id = second_invite_event.call_id.expect("second INVITE call id");
    let second_ack = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &second_ack).starts_with("ACK "));

    let remote_bye = format!(
        "BYE sip:platform@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-remote-bye;rport\r\n\
From: {};tag=peer-remote-bye\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: 2 BYE\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n",
        local_addr(),
        remote,
        header_value(&second_invite, "To"),
        header_value(&second_invite, "From"),
        second_call_id,
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            remote_bye.as_bytes(),
        )
        .expect("inject remote BYE");
    let remote_bye_event =
        receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(remote_bye_event.method.as_deref(), Some("BYE"));
    assert_eq!(
        remote_bye_event.call_id.as_deref(),
        Some(second_call_id.as_str())
    );
    let remote_bye_response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &remote_bye_response).starts_with("SIP/2.0 200"));
    runtime.poll().expect("complete remote BYE response");

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_owns_incoming_invite_and_cancel() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40006);
    let sdp = "v=0\r\n\
o=device 0 0 IN IP4 127.0.0.1\r\n\
s=Play\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=video 6000 RTP/AVP 96\r\n\
a=rtpmap:96 PS/90000\r\n";
    let invite = format!(
        "INVITE sip:platform@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-incoming;rport\r\n\
From: <sip:device@{}>;tag=device-invite\r\n\
To: <sip:platform@{}>\r\n\
Call-ID: incoming-invite\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:device@{}>\r\n\
Subject: channel:0100000001,platform:0100000001\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
        local_addr(),
        remote,
        remote,
        local_addr(),
        remote,
        sdp.len(),
        sdp
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            invite.as_bytes(),
        )
        .expect("inject incoming INVITE");
    let trying = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &trying).starts_with("SIP/2.0 100"));
    let incoming = receive_event(&mut runtime, &events, SipRuntimeEventKind::IncomingInvite);
    assert_eq!(incoming.call_id.as_deref(), Some("incoming-invite"));
    assert_eq!(incoming.body, sdp.as_bytes());
    assert_eq!(
        incoming.subject.as_deref(),
        Some("channel:0100000001,platform:0100000001")
    );

    let cancel = format!(
        "CANCEL sip:platform@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-incoming;rport\r\n\
From: <sip:device@{}>;tag=device-invite\r\n\
To: <sip:platform@{}>\r\n\
Call-ID: incoming-invite\r\n\
CSeq: 1 CANCEL\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n",
        local_addr(),
        remote,
        remote,
        local_addr()
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            cancel.as_bytes(),
        )
        .expect("inject CANCEL");
    let cancel_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(cancel_event.method.as_deref(), Some("CANCEL"));

    let first = receive_transmit(&mut runtime, &transmits);
    let second = receive_transmit(&mut runtime, &transmits);
    let responses = [
        finish_transmit(&mut runtime, &first),
        finish_transmit(&mut runtime, &second),
    ];
    assert!(responses
        .iter()
        .any(|value| value.starts_with("SIP/2.0 200")));
    assert!(responses
        .iter()
        .any(|value| value.starts_with("SIP/2.0 487")));
    runtime.poll().expect("complete CANCEL responses");

    let unsupported_invite = invite
        .replace("incoming-invite", "unsupported-invite")
        .replace("device-invite", "unsupported-device")
        .replace("z9hG4bK-incoming", "z9hG4bK-unsupported");
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            unsupported_invite.as_bytes(),
        )
        .expect("inject unsupported incoming INVITE");
    let unsupported_trying = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &unsupported_trying).starts_with("SIP/2.0 100"));
    let unsupported = receive_event(&mut runtime, &events, SipRuntimeEventKind::IncomingInvite);
    assert_eq!(unsupported.call_id.as_deref(), Some("unsupported-invite"));
    runtime
        .respond_invite(&SipInviteResponse {
            call_id: "unsupported-invite".into(),
            status_code: 501,
            reason: Some("Inbound session is not supported".into()),
        })
        .expect("reject unsupported incoming INVITE");
    let unsupported_response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &unsupported_response)
        .starts_with("SIP/2.0 501 Inbound session is not supported"));
    runtime
        .poll()
        .expect("complete unsupported INVITE response");

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_owns_subscribe_refresh_notify_and_unsubscribe() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40005);
    let body = b"<?xml version=\"1.0\"?><Query><CmdType>Catalog</CmdType></Query>".to_vec();
    runtime
        .send_subscribe(&SipOutboundSubscribe {
            operation_id: 70,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            contact_uri: format!("<sip:platform@{}>", local_addr()),
            call_id: None,
            event: "Catalog".into(),
            expires: 300,
            content_type: "Application/MANSCDP+xml".into(),
            body: body.clone(),
        })
        .expect("send initial SUBSCRIBE");

    let transmit = receive_transmit(&mut runtime, &transmits);
    let request = finish_transmit(&mut runtime, &transmit);
    assert!(request.starts_with("SUBSCRIBE "));
    assert_eq!(header_value(&request, "Event"), "Catalog");
    assert_eq!(header_value(&request, "Expires"), "300");
    let call_id = header_value(&request, "Call-ID").to_string();
    let response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=device-sub\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Contact: <sip:device@{}>\r\n\
Expires: 300\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&request, "Via"),
        header_value(&request, "From"),
        header_value(&request, "To"),
        call_id,
        header_value(&request, "CSeq"),
        remote
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            response.as_bytes(),
        )
        .expect("inject SUBSCRIBE response");
    let accepted = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(accepted.operation_id, Some(70));
    assert_eq!(accepted.status_code, Some(200));
    assert_eq!(accepted.call_id.as_deref(), Some(call_id.as_str()));
    assert_eq!(accepted.expires_seconds, Some(300));

    let notify_body = "<?xml version=\"1.0\"?><Response><CmdType>Catalog</CmdType></Response>";
    let notify = format!(
        "NOTIFY sip:platform@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-notify;rport\r\n\
From: <sip:device@{}>;tag=device-sub\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: 1 NOTIFY\r\n\
Event: Catalog\r\n\
Subscription-State: active;expires=299\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        local_addr(),
        remote,
        remote,
        header_value(&request, "From"),
        call_id,
        notify_body.len(),
        notify_body
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            notify.as_bytes(),
        )
        .expect("inject NOTIFY");
    let notify_response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &notify_response).starts_with("SIP/2.0 200"));
    let notify_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(notify_event.method.as_deref(), Some("NOTIFY"));
    assert_eq!(notify_event.call_id.as_deref(), Some(call_id.as_str()));
    assert_eq!(notify_event.event.as_deref(), Some("Catalog"));
    assert_eq!(
        notify_event.subscription_state.as_deref(),
        Some("active;expires=299")
    );
    assert_eq!(notify_event.body, notify_body.as_bytes());

    runtime
        .send_subscribe(&SipOutboundSubscribe {
            operation_id: 71,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: String::new(),
            from_uri: String::new(),
            contact_uri: String::new(),
            call_id: Some(call_id.clone()),
            event: "Catalog".into(),
            expires: 180,
            content_type: "Application/MANSCDP+xml".into(),
            body: body.clone(),
        })
        .expect("refresh SUBSCRIBE");
    let refresh_transmit = receive_transmit(&mut runtime, &transmits);
    let refresh = finish_transmit(&mut runtime, &refresh_transmit);
    assert!(refresh.starts_with("SUBSCRIBE "));
    assert_eq!(header_value(&refresh, "Expires"), "180");
    let refresh_response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Contact: <sip:device@{}>\r\n\
Expires: 180\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&refresh, "Via"),
        header_value(&refresh, "From"),
        header_value(&refresh, "To"),
        call_id,
        header_value(&refresh, "CSeq"),
        remote
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            refresh_response.as_bytes(),
        )
        .expect("inject refresh response");
    let refreshed = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(refreshed.operation_id, Some(71));
    assert_eq!(refreshed.expires_seconds, Some(180));

    runtime
        .send_subscribe(&SipOutboundSubscribe {
            operation_id: 72,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: String::new(),
            from_uri: String::new(),
            contact_uri: String::new(),
            call_id: Some(call_id),
            event: "Catalog".into(),
            expires: 0,
            content_type: String::new(),
            body: Vec::new(),
        })
        .expect("unsubscribe");
    let unsubscribe_transmit = receive_transmit(&mut runtime, &transmits);
    let unsubscribe = finish_transmit(&mut runtime, &unsubscribe_transmit);
    assert!(unsubscribe.starts_with("SUBSCRIBE "));
    assert_eq!(header_value(&unsubscribe, "Expires"), "0");
    let unsubscribe_response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Expires: 0\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&unsubscribe, "Via"),
        header_value(&unsubscribe, "From"),
        header_value(&unsubscribe, "To"),
        header_value(&unsubscribe, "Call-ID"),
        header_value(&unsubscribe, "CSeq"),
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            unsubscribe_response.as_bytes(),
        )
        .expect("inject unsubscribe response");
    let unsubscribed = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(unsubscribed.operation_id, Some(72));
    assert_eq!(unsubscribed.status_code, Some(200));

    runtime.shutdown().expect("shutdown runtime");
}
