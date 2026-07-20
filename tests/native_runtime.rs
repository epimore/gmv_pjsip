use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

use base::log::{LevelFilter, Log, Metadata, Record};
use gmv_pjsip::auth::{create_digest_response, parse_digest_authorization};
use gmv_pjsip::{
    AuthAlgorithm, AuthCredential, CredentialKind, SipAuthLookupResult, SipDialogMethod,
    SipDialogRequest, SipIncomingInviteAllow, SipInviteResponse, SipOutboundInvite,
    SipOutboundMessage, SipOutboundSubscribe, SipRecoverySource, SipRegisteredSource,
    SipRestoredDialogRequest, SipRuntime, SipRuntimeConfig, SipRuntimeEvent, SipRuntimeEventKind,
    SipRuntimeSockets, SipRuntimeTransmits, SipTransmit, SipTransportProtocol,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static TEST_LOG_INIT: Once = Once::new();
static TEST_LOGGER: TestLogger = TestLogger {
    messages: Mutex::new(Vec::new()),
};
const LOCAL_PORT: u16 = 5060;
const TEST_USER_AGENT: &str = "Gmv test-version";

struct TestLogger {
    messages: Mutex<Vec<String>>,
}

impl Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
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
        base::log::set_logger(&TEST_LOGGER).expect("install test logger");
        base::log::set_max_level(LevelFilter::Trace);
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
    config.user_agent = TEST_USER_AGENT.into();
    SipRuntime::start_for_test(config).expect("start runtime")
}

fn allow_registered_source(
    runtime: &mut SipRuntime,
    device_id: &str,
    remote: SocketAddr,
    protocol: SipTransportProtocol,
) {
    runtime
        .allow_registered_source(&SipRegisteredSource {
            device_id: device_id.into(),
            remote_address: remote.ip().to_string(),
            protocol,
            registration_call_id: None,
            registration_cseq: None,
        })
        .expect("allow registered source");
}

fn allow_recovery_source(
    runtime: &mut SipRuntime,
    device_id: &str,
    remote: SocketAddr,
    protocol: SipTransportProtocol,
    ttl: Duration,
) {
    runtime
        .allow_recovery_source(&SipRecoverySource {
            device_id: device_id.into(),
            remote_address: remote.ip().to_string(),
            protocol,
            registration_call_id: None,
            registration_cseq: None,
            ttl,
        })
        .expect("allow recovery source");
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
    panic!("timed out waiting for runtime adapter transmit");
}

fn finish_transmit(runtime: &mut SipRuntime, transmit: &SipTransmit) -> String {
    runtime
        .complete_test_send(transmit.send_id, Ok(transmit.data.len()))
        .expect("complete runtime adapter send");
    let message = String::from_utf8_lossy(&transmit.data).into_owned();
    let user_agents = message
        .lines()
        .filter_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .eq_ignore_ascii_case("User-Agent")
                .then_some(value.trim())
        })
        .collect::<Vec<_>>();
    assert_eq!(user_agents, [TEST_USER_AGENT]);
    message
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

fn register_request(
    request_uri: &str,
    username: &str,
    remote: SocketAddr,
    call_id: &str,
    cseq: u32,
    authorization: Option<&str>,
) -> String {
    let authorization = authorization
        .map(|value| format!("Authorization: {value}\r\n"))
        .unwrap_or_default();
    format!(
        "REGISTER {request_uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {remote};branch=z9hG4bK-register-{cseq};rport\r\n\
From: <sip:{username}@3402000000>;tag=register\r\n\
To: <sip:{username}@3402000000>\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} REGISTER\r\n\
Contact: <sip:{username}@{remote}>\r\n\
Expires: 3600\r\n\
{authorization}\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    )
}

struct BypassRegisterCase<'a> {
    request_uri: &'a str,
    username: &'a str,
    remote: SocketAddr,
    call_id: &'a str,
    cseq: u32,
}

fn complete_bypass_register(
    runtime: &mut SipRuntime,
    events: &Receiver<SipRuntimeEvent>,
    transmits: &SipRuntimeTransmits,
    case: BypassRegisterCase<'_>,
) -> String {
    let request = register_request(
        case.request_uri,
        case.username,
        case.remote,
        case.call_id,
        case.cseq,
        None,
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            case.remote,
            request.as_bytes(),
        )
        .expect("inject bypass REGISTER");
    let lookup = receive_event(runtime, events, SipRuntimeEventKind::AuthLookupRequired);
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("auth lookup id"),
            SipAuthLookupResult::Bypass,
        )
        .expect("complete bypass auth lookup");
    let transmit = receive_transmit(runtime, transmits);
    finish_transmit(runtime, &transmit)
}

fn test_credential(username: &str, realm: &str) -> AuthCredential {
    AuthCredential {
        username: username.into(),
        realm: realm.into(),
        secret: "native-runtime-test-secret".into(),
        kind: CredentialKind::PlainPassword,
        algorithm: AuthAlgorithm::Md5,
    }
}

fn issue_register_challenge(
    runtime: &mut SipRuntime,
    events: &Receiver<SipRuntimeEvent>,
    transmits: &SipRuntimeTransmits,
    request_uri: &str,
    username: &str,
    remote: SocketAddr,
    credential: &AuthCredential,
) -> String {
    let request = register_request(request_uri, username, remote, "digest-register", 1, None);
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            request.as_bytes(),
        )
        .expect("inject initial REGISTER");
    let lookup = receive_event(runtime, events, SipRuntimeEventKind::AuthLookupRequired);
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("auth lookup id"),
            SipAuthLookupResult::Credential(credential.clone()),
        )
        .expect("complete initial auth lookup");
    let challenge_transmit = receive_transmit(runtime, transmits);
    let challenge = finish_transmit(runtime, &challenge_transmit);
    assert!(challenge.starts_with("SIP/2.0 401"));
    header_value(&challenge, "WWW-Authenticate").to_owned()
}

fn digest_authorization(
    challenge: &str,
    credential: &AuthCredential,
    authorization_uri: &str,
) -> String {
    let parts = parse_digest_authorization(challenge);
    let nonce = parts.get("nonce").expect("challenge nonce");
    let nc = "00000001";
    let cnonce = "native-test-cnonce";
    let qop = "auth";
    let response = create_digest_response(
        credential,
        "REGISTER",
        authorization_uri,
        nonce,
        Some(nc),
        Some(cnonce),
        Some(qop),
        AuthAlgorithm::Md5,
    )
    .expect("create REGISTER digest");
    format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", \
         response=\"{}\", algorithm=MD5, cnonce=\"{}\", qop={}, nc={}",
        credential.username, credential.realm, nonce, authorization_uri, response, cnonce, qop, nc
    )
}

struct DigestRegisterCase<'a> {
    request_uri: &'a str,
    authorization_uri: &'a str,
    username: &'a str,
    remote: SocketAddr,
    credential: &'a AuthCredential,
    tamper_digest: bool,
}

fn complete_digest_register(
    runtime: &mut SipRuntime,
    events: &Receiver<SipRuntimeEvent>,
    transmits: &SipRuntimeTransmits,
    case: DigestRegisterCase<'_>,
) -> (String, Option<SipRuntimeEvent>) {
    let challenge = issue_register_challenge(
        runtime,
        events,
        transmits,
        case.request_uri,
        case.username,
        case.remote,
        case.credential,
    );
    let mut authorization =
        digest_authorization(&challenge, case.credential, case.authorization_uri);
    if case.tamper_digest {
        let response_start =
            authorization.find("response=\"").expect("digest response") + "response=\"".len();
        let replacement = if &authorization[response_start..response_start + 1] == "0" {
            "1"
        } else {
            "0"
        };
        authorization.replace_range(response_start..response_start + 1, replacement);
    }
    let request = register_request(
        case.request_uri,
        case.username,
        case.remote,
        "digest-register",
        2,
        Some(&authorization),
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            case.remote,
            request.as_bytes(),
        )
        .expect("inject authenticated REGISTER");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut registered = None;
    while Instant::now() < deadline {
        runtime.poll().expect("poll runtime");
        while let Ok(event) = events.try_recv() {
            if event.kind == SipRuntimeEventKind::AuthLookupRequired {
                runtime
                    .complete_auth_lookup(
                        event.lookup_id.expect("auth lookup id"),
                        SipAuthLookupResult::Credential(case.credential.clone()),
                    )
                    .expect("complete authenticated lookup");
            } else if event.kind == SipRuntimeEventKind::Registered {
                registered = Some(event);
            }
        }
        if let Ok(transmit) = transmits.try_recv() {
            return (finish_transmit(runtime, &transmit), registered);
        }
    }
    panic!("timed out waiting for authenticated REGISTER response");
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
    assert!(error
        .to_string()
        .contains("invalid SIP runtime configuration"));
}

#[test]
fn runtime_rejects_invalid_user_agent() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        user_agent: "Gmv test\r\nInjected: value".into(),
        ..SipRuntimeConfig::default()
    };
    let error = match SipRuntime::start_for_test(config) {
        Ok(_) => panic!("runtime unexpectedly accepted invalid User-Agent"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("invalid SIP runtime configuration"));
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
    let (runtime, _events, _transmits) = start_runtime(SipRuntimeConfig::default());
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
    assert!(error
        .to_string()
        .contains("PJSIP runtime is already active"));
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
        advertised_address: Ipv4Addr::LOCALHOST,
        port: runtime_addr.port(),
        enable_tcp: false,
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
    allow_registered_source(&mut runtime, "test", peer_addr, SipTransportProtocol::Udp);
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
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());

    let udp_remote = remote_addr(40000);
    allow_registered_source(&mut runtime, "test", udp_remote, SipTransportProtocol::Udp);
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
    allow_registered_source(&mut runtime, "test", tcp_remote, SipTransportProtocol::Tcp);
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
        .expect("close TCP runtime adapter");
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn recovery_source_only_allows_message_and_promotes_to_live() {
    let _guard = lock_tests();
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());
    let remote = remote_addr(40100);
    allow_recovery_source(
        &mut runtime,
        "recovering-device",
        remote,
        SipTransportProtocol::Udp,
        Duration::from_millis(200),
    );

    let options = format!(
        "OPTIONS sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/UDP {remote};branch=z9hG4bK-recovery-options;rport\r\n\
From: <sip:recovering-device@127.0.0.1>;tag=recovery-options\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: recovery-options\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            options.as_bytes(),
        )
        .expect("inject recovery OPTIONS");
    runtime.poll().expect("poll recovery OPTIONS");
    assert!(matches!(
        transmits.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(events.try_recv().is_err());

    let body = "<?xml version=\"1.0\"?><Notify><CmdType>Keepalive</CmdType><DeviceID>recovering-device</DeviceID></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/UDP {remote};branch=z9hG4bK-recovery-message;rport\r\n\
From: <sip:recovering-device@127.0.0.1>;tag=recovery-message\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: recovery-message\r\n\
CSeq: 2 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let wrong_identity = message
        .replace("recovering-device@", "unknown-device@")
        .replace("recovery-message", "wrong-recovery-message");
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            wrong_identity.as_bytes(),
        )
        .expect("inject wrong recovery identity");
    runtime.poll().expect("poll wrong recovery identity");
    assert!(matches!(
        transmits.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(events.try_recv().is_err());

    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            message.as_bytes(),
        )
        .expect("inject recovery MESSAGE");
    let response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &response).starts_with("SIP/2.0 200"));
    let request = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(request.method.as_deref(), Some("MESSAGE"));

    allow_registered_source(
        &mut runtime,
        "recovering-device",
        remote,
        SipTransportProtocol::Udp,
    );
    std::thread::sleep(Duration::from_millis(220));
    runtime.poll().expect("poll promoted source");
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            options.as_bytes(),
        )
        .expect("inject promoted OPTIONS");
    let response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &response).starts_with("SIP/2.0 200"));
}

#[test]
fn expired_recovery_source_is_removed_without_reconnect() {
    let _guard = lock_tests();
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());
    let remote = remote_addr(40101);
    allow_recovery_source(
        &mut runtime,
        "expired-device",
        remote,
        SipTransportProtocol::Udp,
        Duration::from_millis(20),
    );
    std::thread::sleep(Duration::from_millis(30));
    runtime.poll().expect("poll expired recovery source");

    let body = "<Notify><CmdType>Keepalive</CmdType><DeviceID>expired-device</DeviceID></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/UDP {remote};branch=z9hG4bK-expired-message;rport\r\n\
From: <sip:expired-device@127.0.0.1>;tag=expired-message\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: expired-message\r\n\
CSeq: 1 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            message.as_bytes(),
        )
        .expect("inject expired recovery MESSAGE");
    runtime.poll().expect("poll expired recovery MESSAGE");
    assert!(matches!(
        transmits.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(events.try_recv().is_err());
}

#[test]
fn tcp_recovery_source_allows_current_connection_message() {
    let _guard = lock_tests();
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());
    let remote = remote_addr(40102);
    allow_recovery_source(
        &mut runtime,
        "tcp-recovering-device",
        remote,
        SipTransportProtocol::Tcp,
        Duration::from_secs(1),
    );
    let body =
        "<Notify><CmdType>Keepalive</CmdType><DeviceID>tcp-recovering-device</DeviceID></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/TCP {remote};branch=z9hG4bK-tcp-recovery;rport\r\n\
From: <sip:tcp-recovering-device@127.0.0.1>;tag=tcp-recovery\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: tcp-recovery\r\n\
CSeq: 1 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    runtime
        .inject_test_packet(
            44,
            SipTransportProtocol::Tcp,
            local_addr(),
            remote,
            message.as_bytes(),
        )
        .expect("inject TCP recovery MESSAGE");
    let response = receive_transmit(&mut runtime, &transmits);
    assert_eq!(response.association_id, 44);
    assert!(finish_transmit(&mut runtime, &response).starts_with("SIP/2.0 200"));
    let request = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
    assert_eq!(request.method.as_deref(), Some("MESSAGE"));
}

#[test]
#[ignore = "capacity baseline; run explicitly for restart recovery changes"]
fn recovery_source_capacity_baseline_10000() {
    let _guard = lock_tests();
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());
    let remote = remote_addr(40103);
    let started = Instant::now();
    for index in 0..10_000 {
        runtime
            .allow_recovery_source(&SipRecoverySource {
                device_id: format!("capacity-device-{index:05}"),
                remote_address: remote.ip().to_string(),
                protocol: SipTransportProtocol::Udp,
                registration_call_id: Some(format!("capacity-register-{index:05}")),
                registration_cseq: Some(10),
                ttl: Duration::from_secs(60),
            })
            .expect("allow capacity recovery source");
    }
    let install_elapsed = started.elapsed();
    assert!(
        install_elapsed < Duration::from_secs(30),
        "10k recovery source install exceeded baseline: {install_elapsed:?}"
    );

    let lookup_started = Instant::now();
    for (cseq, index) in [0, 5_000, 9_999].into_iter().enumerate() {
        let device_id = format!("capacity-device-{index:05}");
        let body = format!(
            "<Notify><CmdType>Keepalive</CmdType><DeviceID>{device_id}</DeviceID></Notify>"
        );
        let message = format!(
            "MESSAGE sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/UDP {remote};branch=z9hG4bK-capacity-{index};rport\r\n\
From: <sip:{device_id}@127.0.0.1>;tag=capacity-{index}\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: capacity-{index}\r\n\
CSeq: {} MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
            cseq + 1,
            body.len(),
            body
        );
        runtime
            .inject_test_packet(
                0,
                SipTransportProtocol::Udp,
                local_addr(),
                remote,
                message.as_bytes(),
            )
            .expect("inject capacity lookup");
        let response = receive_transmit(&mut runtime, &transmits);
        assert!(finish_transmit(&mut runtime, &response).starts_with("SIP/2.0 200"));
        let request = receive_event(&mut runtime, &events, SipRuntimeEventKind::RequestReceived);
        assert_eq!(request.method.as_deref(), Some("MESSAGE"));
        assert!(request
            .from_header
            .as_deref()
            .is_some_and(|from| from.contains(&device_id)));
    }
    let lookup_elapsed = lookup_started.elapsed();
    assert!(
        lookup_elapsed < Duration::from_secs(2),
        "first/middle/last recovery source lookup exceeded baseline: {lookup_elapsed:?}"
    );
    println!(
        "10k recovery source baseline: install={install_elapsed:?}, lookups={lookup_elapsed:?}"
    );
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
fn runtime_rejects_register_cseq_rollback_before_success_response() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40022);
    let username = "34020000001320000001";
    let request_uri = format!("sip:3402000000@127.0.0.1:{LOCAL_PORT}");

    let accepted = complete_bypass_register(
        &mut runtime,
        &events,
        &transmits,
        BypassRegisterCase {
            request_uri: &request_uri,
            username,
            remote,
            call_id: "stable-register",
            cseq: 10,
        },
    );
    assert!(accepted.starts_with("SIP/2.0 200"));
    receive_event(&mut runtime, &events, SipRuntimeEventKind::Registered);

    let stale = complete_bypass_register(
        &mut runtime,
        &events,
        &transmits,
        BypassRegisterCase {
            request_uri: &request_uri,
            username,
            remote,
            call_id: "stable-register",
            cseq: 9,
        },
    );
    assert!(stale.starts_with("SIP/2.0 500"));
    assert_eq!(header_value(&stale, "Retry-After"), "1");
    for _ in 0..3 {
        runtime.poll().expect("poll stale REGISTER result");
    }
    assert!(events.try_iter().all(|event| {
        event.kind != SipRuntimeEventKind::Registered
            && event.kind != SipRuntimeEventKind::Unregistered
    }));

    let replacement = complete_bypass_register(
        &mut runtime,
        &events,
        &transmits,
        BypassRegisterCase {
            request_uri: &request_uri,
            username,
            remote,
            call_id: "replacement-register",
            cseq: 1,
        },
    );
    assert!(replacement.starts_with("SIP/2.0 200"));
    receive_event(&mut runtime, &events, SipRuntimeEventKind::Registered);
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn recovery_source_restores_register_ordering_before_first_register() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40023);
    let username = "34020000001320000001";
    runtime
        .allow_recovery_source(&SipRecoverySource {
            device_id: username.into(),
            remote_address: remote.ip().to_string(),
            protocol: SipTransportProtocol::Udp,
            registration_call_id: Some("stable-register".into()),
            registration_cseq: Some(10),
            ttl: Duration::from_secs(30),
        })
        .expect("install recovery source with REGISTER ordering");
    let request_uri = format!("sip:3402000000@127.0.0.1:{LOCAL_PORT}");

    let stale = complete_bypass_register(
        &mut runtime,
        &events,
        &transmits,
        BypassRegisterCase {
            request_uri: &request_uri,
            username,
            remote,
            call_id: "stable-register",
            cseq: 9,
        },
    );
    assert!(stale.starts_with("SIP/2.0 500"));
    assert_eq!(header_value(&stale, "Retry-After"), "1");
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_register_digest_nat_uri_compat() {
    let _guard = lock_tests();
    let advertised_address = Ipv4Addr::new(192, 0, 2, 10);
    let config = SipRuntimeConfig {
        advertised_address,
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let remote = remote_addr(40012);
    let username = "34020000001320000001";
    let request_uri = format!("sip:34020000002000000001@{}", local_addr());
    let authorization_uri = format!("sip:34020000002000000001@{advertised_address}:{LOCAL_PORT}");
    let credential = test_credential(username, "3402000000");

    let (response, registered) = complete_digest_register(
        &mut runtime,
        &events,
        &transmits,
        DigestRegisterCase {
            request_uri: &request_uri,
            authorization_uri: &authorization_uri,
            username,
            remote,
            credential: &credential,
            tamper_digest: false,
        },
    );

    assert!(response.starts_with("SIP/2.0 200"));
    let registered = registered
        .unwrap_or_else(|| receive_event(&mut runtime, &events, SipRuntimeEventKind::Registered));
    assert_eq!(registered.device_id.as_deref(), Some(username));
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_register_digest_exact_uri_still_succeeds() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let username = "34020000001320000001";
    let request_uri = format!("sip:34020000002000000001@{}", local_addr());
    let credential = test_credential(username, "3402000000");

    let (response, registered) = complete_digest_register(
        &mut runtime,
        &events,
        &transmits,
        DigestRegisterCase {
            request_uri: &request_uri,
            authorization_uri: &request_uri,
            username,
            remote: remote_addr(40013),
            credential: &credential,
            tamper_digest: false,
        },
    );

    assert!(response.starts_with("SIP/2.0 200"));
    let registered = registered
        .unwrap_or_else(|| receive_event(&mut runtime, &events, SipRuntimeEventKind::Registered));
    assert_eq!(registered.device_id.as_deref(), Some(username));
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_rejects_unrelated_digest_uri() {
    let _guard = lock_tests();
    let advertised_address = Ipv4Addr::new(192, 0, 2, 10);
    let request_uri = format!("sip:34020000002000000001@{}", local_addr());
    let username = "34020000001320000001";
    let credential = test_credential(username, "3402000000");
    let rejected_uris = [
        format!("sip:34020000002000000001@192.0.2.99:{LOCAL_PORT}"),
        format!("sip:44010000002000000001@{advertised_address}:{LOCAL_PORT}"),
        format!(
            "sip:34020000002000000001@{advertised_address}:{}",
            LOCAL_PORT + 1
        ),
    ];

    for (index, authorization_uri) in rejected_uris.iter().enumerate() {
        let config = SipRuntimeConfig {
            advertised_address,
            enable_tcp: false,
            ..SipRuntimeConfig::default()
        };
        let (mut runtime, events, transmits) = start_runtime(config);
        let (response, registered) = complete_digest_register(
            &mut runtime,
            &events,
            &transmits,
            DigestRegisterCase {
                request_uri: &request_uri,
                authorization_uri,
                username,
                remote: remote_addr(40020 + index as u16),
                credential: &credential,
                tamper_digest: false,
            },
        );
        assert!(response.starts_with("SIP/2.0 403"));
        assert!(registered.is_none());
        runtime.shutdown().expect("shutdown runtime");
    }
}

#[test]
fn runtime_adapter_rejects_invalid_register_digest() {
    let _guard = lock_tests();
    let advertised_address = Ipv4Addr::new(192, 0, 2, 10);
    let config = SipRuntimeConfig {
        advertised_address,
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config);
    let username = "34020000001320000001";
    let request_uri = format!("sip:34020000002000000001@{}", local_addr());
    let authorization_uri = format!("sip:34020000002000000001@{advertised_address}:{LOCAL_PORT}");
    let credential = test_credential(username, "3402000000");

    let (response, registered) = complete_digest_register(
        &mut runtime,
        &events,
        &transmits,
        DigestRegisterCase {
            request_uri: &request_uri,
            authorization_uri: &authorization_uri,
            username,
            remote: remote_addr(40030),
            credential: &credential,
            tamper_digest: true,
        },
    );

    assert!(response.starts_with("SIP/2.0 403"));
    assert!(registered.is_none());
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
    let message_cseq = header_value(&request, "CSeq")
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .expect("MESSAGE CSeq");
    assert!((1..=i32::MAX as u32).contains(&message_cseq));

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

    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            response.as_bytes(),
        )
        .expect("inject duplicate outbound response");
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut duplicate_response = false;
    while Instant::now() < deadline {
        runtime.poll().expect("poll duplicate response");
        while let Ok(event) = events.try_recv() {
            duplicate_response |= event.kind == SipRuntimeEventKind::OutboundResponse
                && event.operation_id == Some(operation_id);
        }
    }
    assert!(
        !duplicate_response,
        "final MESSAGE response was emitted more than once"
    );
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn tcp_via_uses_configured_advertised_address() {
    let _guard = lock_tests();
    let advertised_address = Ipv4Addr::new(203, 0, 113, 10);
    let config = SipRuntimeConfig {
        advertised_address,
        enable_udp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, _events, transmits) = start_runtime(config);
    let remote = remote_addr(40013);
    let association_id = 13;
    allow_registered_source(&mut runtime, "device", remote, SipTransportProtocol::Tcp);
    let bootstrap = format!(
        "OPTIONS sip:platform@{} SIP/2.0\r\nVia: SIP/2.0/TCP {remote};branch=z9hG4bK-bootstrap;rport\r\nFrom: <sip:device@{remote}>;tag=bootstrap\r\nTo: <sip:platform@{}>\r\nCall-ID: bootstrap-advertised-via\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        local_addr(),
        local_addr(),
    );
    runtime
        .inject_test_packet(
            association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            remote,
            bootstrap.as_bytes(),
        )
        .expect("create TCP transport");
    let response = receive_transmit(&mut runtime, &transmits);
    finish_transmit(&mut runtime, &response);

    runtime
        .send_message(&SipOutboundMessage {
            operation_id: 43,
            association_id,
            protocol: SipTransportProtocol::Tcp,
            target_uri: format!("sip:device@{remote};transport=tcp"),
            from_uri: format!("<sip:platform@{advertised_address}>"),
            content_type: "Application/MANSCDP+xml".into(),
            body: b"<Query><CmdType>DeviceInfo</CmdType></Query>".to_vec(),
        })
        .expect("send TCP MESSAGE");
    let transmit = receive_transmit(&mut runtime, &transmits);
    let request = finish_transmit(&mut runtime, &transmit);
    assert!(header_value(&request, "Via")
        .starts_with(&format!("SIP/2.0/TCP {advertised_address}:{LOCAL_PORT};")));

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
            identity: gmv_pjsip::SipInviteIdentity::generate(),
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
            identity: gmv_pjsip::SipInviteIdentity::generate(),
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
fn fresh_runtime_sends_restored_info_info_and_bye() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: true,
        ..SipRuntimeConfig::default()
    };
    let remote = remote_addr(15070);
    let (mut original_runtime, original_events, original_transmits) = start_runtime(config.clone());
    let invite_identity = gmv_pjsip::SipInviteIdentity::generate();
    original_runtime
        .send_invite(&SipOutboundInvite {
            operation_id: 200,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            identity: invite_identity.clone(),
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            contact_uri: format!("<sip:platform@{}>", local_addr()),
            subject: Some("device:0100000001,platform:0100000001".into()),
            sdp: "v=0\r\no=platform 0 0 IN IP4 127.0.0.1\r\ns=Play\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=video 30000 RTP/AVP 96\r\na=recvonly\r\na=rtpmap:96 PS/90000\r\ny=0100000001\r\n".into(),
        })
        .expect("send original INVITE");
    let invite_transmit = receive_transmit(&mut original_runtime, &original_transmits);
    let invite = finish_transmit(&mut original_runtime, &invite_transmit);
    assert_eq!(header_value(&invite, "Call-ID"), invite_identity.call_id);
    assert!(header_value(&invite, "From").contains(&invite_identity.local_tag));
    assert_eq!(
        header_value(&invite, "CSeq"),
        format!("{} INVITE", invite_identity.local_cseq)
    );
    let remote_sdp = "v=0\r\no=device 0 0 IN IP4 127.0.0.1\r\ns=Play\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=video 40000 RTP/AVP 96\r\na=sendonly\r\na=rtpmap:96 PS/90000\r\ny=0100000001\r\n";
    let response = format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=persisted-remote-tag\r\nCall-ID: {}\r\nCSeq: {}\r\nContact: <sip:device@{remote}>\r\nRecord-Route: <sip:proxy@127.0.0.1:15071;lr>\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}",
        header_value(&invite, "Via"),
        header_value(&invite, "From"),
        header_value(&invite, "To"),
        header_value(&invite, "Call-ID"),
        header_value(&invite, "CSeq"),
        remote_sdp.len(),
        remote_sdp,
    );
    original_runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            response.as_bytes(),
        )
        .expect("inject original INVITE response");
    let invite_event = receive_event(
        &mut original_runtime,
        &original_events,
        SipRuntimeEventKind::OutboundResponse,
    );
    let base_snapshot = invite_event
        .dialog_snapshot
        .expect("INVITE 2xx exports dialog snapshot");
    assert_eq!(base_snapshot.call_id, invite_identity.call_id);
    assert_eq!(base_snapshot.local_tag, invite_identity.local_tag);
    assert_eq!(base_snapshot.local_cseq, invite_identity.local_cseq);
    assert_eq!(base_snapshot.remote_tag, "persisted-remote-tag");
    assert_eq!(base_snapshot.remote_addr, remote);
    assert_eq!(base_snapshot.route_set.len(), 1);
    let ack = receive_transmit(&mut original_runtime, &original_transmits);
    assert!(finish_transmit(&mut original_runtime, &ack).starts_with("ACK "));
    original_runtime
        .shutdown()
        .expect("destroy original runtime");

    let (mut runtime, events, transmits) = start_runtime(config);
    let first_cseq = base_snapshot.local_cseq + 1;
    for (operation_id, method, cseq, response_code) in [
        (201, SipDialogMethod::Info, first_cseq, 200),
        (202, SipDialogMethod::Info, first_cseq + 1, 408),
        (203, SipDialogMethod::Bye, first_cseq + 2, 481),
    ] {
        let mut snapshot = base_snapshot.clone();
        snapshot.local_cseq = cseq;
        runtime
            .send_restored_dialog_request(&SipRestoredDialogRequest {
                operation_id,
                method,
                snapshot,
                content_type: (method == SipDialogMethod::Info)
                    .then(|| "Application/MANSRTSP".into()),
                body: if method == SipDialogMethod::Info {
                    b"PLAY RTSP/1.0\r\nCSeq: 1\r\nScale: 2.0\r\n".to_vec()
                } else {
                    Vec::new()
                },
            })
            .expect("queue restored dialog request");

        let transmit = receive_transmit(&mut runtime, &transmits);
        assert_eq!(transmit.remote_addr, remote);
        let message = finish_transmit(&mut runtime, &transmit);
        let method_name = if method == SipDialogMethod::Info {
            "INFO"
        } else {
            "BYE"
        };
        assert!(message.starts_with(&format!("{method_name} sip:device@{remote} ")));
        assert_eq!(header_value(&message, "Call-ID"), base_snapshot.call_id);
        assert!(header_value(&message, "From").contains(&base_snapshot.local_tag));
        assert!(header_value(&message, "To").contains("tag=persisted-remote-tag"));
        assert!(header_value(&message, "Route").contains("127.0.0.1:15071"));
        assert_eq!(
            header_value(&message, "CSeq"),
            format!("{cseq} {method_name}")
        );

        let response_status = match response_code {
            200 => "200 OK",
            408 => "408 Request Timeout",
            481 => "481 Call/Transaction Does Not Exist",
            _ => unreachable!(),
        };
        let response = format!(
            "SIP/2.0 {response_status}\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
            header_value(&message, "Via"),
            header_value(&message, "From"),
            header_value(&message, "To"),
            header_value(&message, "Call-ID"),
            header_value(&message, "CSeq"),
        );
        runtime
            .inject_test_packet(
                0,
                SipTransportProtocol::Udp,
                local_addr(),
                remote,
                response.as_bytes(),
            )
            .expect("inject restored dialog response");
        let event = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
        assert_eq!(event.operation_id, Some(operation_id));
        assert_eq!(event.status_code, Some(response_code));
    }

    let tcp_remote = remote_addr(15072);
    let tcp_association_id = 77;
    allow_registered_source(
        &mut runtime,
        "device",
        tcp_remote,
        SipTransportProtocol::Tcp,
    );
    let bootstrap = format!(
        "OPTIONS sip:platform@{} SIP/2.0\r\nVia: SIP/2.0/TCP {tcp_remote};branch=z9hG4bK-bootstrap\r\nFrom: <sip:device@{tcp_remote}>;tag=bootstrap\r\nTo: <sip:platform@{}>\r\nCall-ID: bootstrap-tcp\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        local_addr(),
        local_addr(),
    );
    runtime
        .inject_test_packet(
            tcp_association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            tcp_remote,
            bootstrap.as_bytes(),
        )
        .expect("establish current TCP association");
    let bootstrap_response = receive_transmit(&mut runtime, &transmits);
    assert_eq!(bootstrap_response.association_id, tcp_association_id);
    finish_transmit(&mut runtime, &bootstrap_response);

    let mut tcp_snapshot = base_snapshot.clone();
    tcp_snapshot.protocol = SipTransportProtocol::Tcp;
    tcp_snapshot.association_id = tcp_association_id;
    tcp_snapshot.remote_addr = tcp_remote;
    tcp_snapshot.local_cseq = first_cseq + 3;
    runtime
        .send_restored_dialog_request(&SipRestoredDialogRequest {
            operation_id: 204,
            method: SipDialogMethod::Info,
            snapshot: tcp_snapshot,
            content_type: Some("Application/MANSRTSP".into()),
            body: b"PLAY RTSP/1.0\r\nCSeq: 2\r\nScale: 1.0\r\n".to_vec(),
        })
        .expect("send restored INFO on current TCP association");
    let tcp_transmit = receive_transmit(&mut runtime, &transmits);
    assert_eq!(tcp_transmit.protocol, SipTransportProtocol::Tcp);
    assert_eq!(tcp_transmit.association_id, tcp_association_id);
    assert_eq!(tcp_transmit.remote_addr, tcp_remote);
    let tcp_info = finish_transmit(&mut runtime, &tcp_transmit);
    let tcp_response = format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
        header_value(&tcp_info, "Via"),
        header_value(&tcp_info, "From"),
        header_value(&tcp_info, "To"),
        header_value(&tcp_info, "Call-ID"),
        header_value(&tcp_info, "CSeq"),
    );
    runtime
        .inject_test_packet(
            tcp_association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            tcp_remote,
            tcp_response.as_bytes(),
        )
        .expect("inject restored TCP INFO response");
    let tcp_event = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(tcp_event.operation_id, Some(204));
    assert_eq!(tcp_event.status_code, Some(200));

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
    runtime
        .allow_incoming_invite(&SipIncomingInviteAllow {
            target_id: "device".into(),
            source_id: "platform".into(),
            remote_address: remote.ip().to_string(),
            protocol: SipTransportProtocol::Udp,
            ttl: Duration::from_secs(5),
        })
        .expect("allow incoming INVITE");
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
    runtime.poll().expect("process unsupported INVITE drop");
    assert!(matches!(
        transmits.recv_timeout(Duration::from_millis(50)),
        Err(RecvTimeoutError::Timeout)
    ));

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_adapter_accepts_incoming_audio_invite_and_sends_bye() {
    let _guard = lock_tests();
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events, transmits) = start_runtime(config.clone());
    let remote = remote_addr(40007);
    runtime
        .allow_incoming_invite(&SipIncomingInviteAllow {
            target_id: "receiver".into(),
            source_id: "platform".into(),
            remote_address: remote.ip().to_string(),
            protocol: SipTransportProtocol::Udp,
            ttl: Duration::from_secs(5),
        })
        .expect("allow broadcast INVITE");
    let remote_sdp = "v=0\r\n\
o=receiver 0 0 IN IP4 127.0.0.1\r\n\
s=Play\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=audio 30008 RTP/AVP 8\r\n\
a=recvonly\r\n\
a=rtpmap:8 PCMA/8000\r\n\
y=0400000004\r\n";
    let invite = format!(
        "INVITE sip:platform@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-broadcast;rport\r\n\
From: <sip:receiver@{}>;tag=receiver-broadcast\r\n\
To: <sip:platform@{}>\r\n\
Call-ID: incoming-broadcast\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:receiver@{}>\r\n\
Subject: source:0400000004,receiver:0400000004\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
        local_addr(),
        remote,
        remote,
        local_addr(),
        remote,
        remote_sdp.len(),
        remote_sdp
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            invite.as_bytes(),
        )
        .expect("inject broadcast INVITE");
    let trying = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &trying).starts_with("SIP/2.0 100"));
    let incoming = receive_event(&mut runtime, &events, SipRuntimeEventKind::IncomingInvite);
    assert_eq!(incoming.call_id.as_deref(), Some("incoming-broadcast"));
    let mut snapshot = incoming.dialog_snapshot.expect("UAS dialog snapshot");
    assert_eq!(snapshot.call_id, "incoming-broadcast");
    assert_eq!(snapshot.remote_tag, "receiver-broadcast");

    let local_sdp = "v=0\r\n\
o=platform 0 0 IN IP4 127.0.0.1\r\n\
s=Play\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=audio 16060 RTP/AVP 8\r\n\
a=sendonly\r\n\
a=rtpmap:8 PCMA/8000\r\n\
y=0400000004\r\n";
    runtime
        .respond_invite(&SipInviteResponse {
            call_id: "incoming-broadcast".into(),
            status_code: 200,
            reason: None,
            content_type: Some("application/sdp".into()),
            body: local_sdp.as_bytes().to_vec(),
        })
        .expect("accept broadcast INVITE");
    let ok = receive_transmit(&mut runtime, &transmits);
    let ok = finish_transmit(&mut runtime, &ok);
    assert!(ok.starts_with("SIP/2.0 200"));
    assert_eq!(header_value(&ok, "Content-Type"), "application/sdp");
    assert!(ok.contains("m=audio 16060 RTP/AVP 8"));
    assert!(ok.contains("a=sendonly"));
    assert!(ok.contains("a=rtpmap:8 PCMA/8000"));

    let ack = format!(
        "ACK sip:platform@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-broadcast-ack;rport\r\n\
From: <sip:receiver@{}>;tag=receiver-broadcast\r\n\
To: {}\r\n\
Call-ID: incoming-broadcast\r\n\
CSeq: 1 ACK\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n",
        local_addr(),
        remote,
        remote,
        header_value(&ok, "To")
    );
    runtime
        .inject_test_packet(
            0,
            SipTransportProtocol::Udp,
            local_addr(),
            remote,
            ack.as_bytes(),
        )
        .expect("inject broadcast ACK");
    runtime.poll().expect("process broadcast ACK");

    runtime.shutdown().expect("shutdown original runtime");

    snapshot.local_cseq = snapshot.local_cseq.saturating_add(1);
    let (mut runtime, _events, transmits) = start_runtime(config);
    runtime
        .send_restored_dialog_request(&SipRestoredDialogRequest {
            operation_id: 301,
            method: SipDialogMethod::Bye,
            snapshot: snapshot.clone(),
            content_type: None,
            body: Vec::new(),
        })
        .expect("send restored broadcast BYE");
    let bye = receive_transmit(&mut runtime, &transmits);
    let bye = finish_transmit(&mut runtime, &bye);
    assert!(bye.starts_with("BYE "));
    assert_eq!(header_value(&bye, "Call-ID"), snapshot.call_id);
    assert!(header_value(&bye, "From").contains(&snapshot.local_tag));
    assert!(header_value(&bye, "To").contains(&snapshot.remote_tag));

    runtime.shutdown().expect("shutdown restored runtime");
}

#[test]
fn receive_is_processed_before_close_in_same_poll() {
    let _guard = lock_tests();
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());
    let association_id = 78;
    let remote = remote_addr(40007);
    allow_registered_source(&mut runtime, "device", remote, SipTransportProtocol::Tcp);
    let options = |branch: &str, cseq: u32| {
        format!(
            "OPTIONS sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/TCP {remote};branch={branch};rport\r\n\
From: <sip:device@127.0.0.1>;tag=receive-close\r\n\
To: <sip:platform@127.0.0.1>\r\n\
Call-ID: receive-close-options\r\n\
CSeq: {cseq} OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
        )
    };

    runtime
        .inject_test_packet(
            association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            remote,
            options("z9hG4bK-receive-close-first", 1).as_bytes(),
        )
        .expect("create TCP transport");
    let first_response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &first_response).starts_with("SIP/2.0 200"));

    runtime
        .inject_test_packet(
            association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            remote,
            options("z9hG4bK-receive-close-last", 2).as_bytes(),
        )
        .expect("queue final TCP packet");
    runtime
        .close_transport(association_id, SipTransportProtocol::Tcp, 0)
        .expect("queue TCP transport close");
    runtime.poll().expect("process final packet and close");
    while transmits.try_recv().is_ok() {}

    runtime
        .send_message(&SipOutboundMessage {
            operation_id: 81,
            association_id,
            protocol: SipTransportProtocol::Tcp,
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            content_type: "Application/MANSCDP+xml".into(),
            body: b"<Query><CmdType>DeviceInfo</CmdType></Query>".to_vec(),
        })
        .expect("queue MESSAGE after close");
    let fault = receive_event(&mut runtime, &events, SipRuntimeEventKind::RuntimeFault);
    assert_eq!(fault.operation_id, Some(81));
    assert!(
        transmits.try_recv().is_err(),
        "closed TCP association was recreated by its final packet"
    );

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn closing_tcp_transport_cleans_subscription_before_refresh_timer() {
    let _guard = lock_tests();
    let (mut runtime, events, transmits) = start_runtime(SipRuntimeConfig::default());
    let association_id = 77;
    let remote = remote_addr(40006);
    allow_registered_source(&mut runtime, "device", remote, SipTransportProtocol::Tcp);
    let options = format!(
        "OPTIONS sip:127.0.0.1:{LOCAL_PORT} SIP/2.0\r\n\
Via: SIP/2.0/TCP {remote};branch=z9hG4bK-subscribe-close;rport\r\n\
From: <sip:device@127.0.0.1>;tag=subscribe-close\r\n\
To: <sip:platform@127.0.0.1>\r\n\
Call-ID: subscribe-close-options\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    runtime
        .inject_test_packet(
            association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            remote,
            options.as_bytes(),
        )
        .expect("create TCP transport");
    let options_response = receive_transmit(&mut runtime, &transmits);
    assert!(finish_transmit(&mut runtime, &options_response).starts_with("SIP/2.0 200"));

    runtime
        .send_subscribe(&SipOutboundSubscribe {
            operation_id: 80,
            association_id,
            protocol: SipTransportProtocol::Tcp,
            target_uri: format!("sip:device@{remote}"),
            from_uri: format!("<sip:platform@{}>", local_addr()),
            contact_uri: format!("<sip:platform@{}>", local_addr()),
            call_id: None,
            event: "Catalog".into(),
            expires: 1,
            content_type: "Application/MANSCDP+xml".into(),
            body: b"<Query><CmdType>Catalog</CmdType></Query>".to_vec(),
        })
        .expect("send TCP SUBSCRIBE");
    let subscribe_transmit = receive_transmit(&mut runtime, &transmits);
    let subscribe = finish_transmit(&mut runtime, &subscribe_transmit);
    let response = format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=device-sub-close\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Contact: <sip:device@{}>\r\n\
Expires: 1\r\n\
Content-Length: 0\r\n\r\n",
        header_value(&subscribe, "Via"),
        header_value(&subscribe, "From"),
        header_value(&subscribe, "To"),
        header_value(&subscribe, "Call-ID"),
        header_value(&subscribe, "CSeq"),
        remote,
    );
    runtime
        .inject_test_packet(
            association_id,
            SipTransportProtocol::Tcp,
            local_addr(),
            remote,
            response.as_bytes(),
        )
        .expect("inject TCP SUBSCRIBE response");
    let accepted = receive_event(&mut runtime, &events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(accepted.operation_id, Some(80));

    runtime
        .close_transport(association_id, SipTransportProtocol::Tcp, 0)
        .expect("close subscribed TCP transport");
    runtime.poll().expect("process TCP transport close");
    while transmits.try_recv().is_ok() {}

    std::thread::sleep(Duration::from_millis(1200));
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        runtime.poll().expect("poll after subscription expiry");
    }
    assert!(
        transmits.try_recv().is_err(),
        "closed subscription unexpectedly refreshed"
    );
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
