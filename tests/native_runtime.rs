#![cfg(feature = "pjsip-sys")]

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use gmv_pjsip::auth::create_digest_response;
use gmv_pjsip::{
    AuthAlgorithm, AuthCredential, CredentialKind, SipAuthLookupResult, SipError,
    SipOutboundMessage, SipRuntime, SipRuntimeConfig, SipRuntimeEvent, SipRuntimeEventKind,
    SipTransportProtocol,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn receive_udp(socket: &UdpSocket) -> String {
    let mut response = [0u8; 4096];
    let (len, _) = socket
        .recv_from(&mut response)
        .expect("receive SIP response");
    String::from_utf8_lossy(&response[..len]).into_owned()
}

fn receive_event(
    events: &std::sync::mpsc::Receiver<SipRuntimeEvent>,
    kind: SipRuntimeEventKind,
) -> SipRuntimeEvent {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(event) = events.recv_timeout(Duration::from_millis(100)) {
            if event.kind == kind {
                return event;
            }
        }
    }
    panic!("timed out waiting for {kind:?}");
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
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let config = SipRuntimeConfig {
        enable_udp: false,
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let error = match SipRuntime::start(config) {
        Ok(_) => panic!("runtime unexpectedly accepted invalid config"),
        Err(error) => error,
    };
    assert!(matches!(error, SipError::InvalidConfig(_)));
}

#[test]
fn runtime_enforces_one_active_instance() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let (runtime, _events) = SipRuntime::start(SipRuntimeConfig::default()).expect("start runtime");
    let error = match SipRuntime::start(SipRuntimeConfig::default()) {
        Ok(_) => panic!("second runtime unexpectedly started"),
        Err(error) => error,
    };
    assert!(matches!(error, SipError::RuntimeActive));
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_copies_udp_and_tcp_events() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let (runtime, events) = SipRuntime::start(SipRuntimeConfig::default()).expect("start runtime");
    let udp_port = runtime.udp_port().expect("UDP port");
    let tcp_port = runtime.tcp_port().expect("TCP port");

    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set UDP timeout");
    let udp_local = udp.local_addr().expect("UDP local address");
    let options = format!(
        "OPTIONS sip:127.0.0.1:{udp_port} SIP/2.0\r\n\
Via: SIP/2.0/UDP {udp_local};branch=z9hG4bK-safe-options;rport\r\n\
From: <sip:test@127.0.0.1>;tag=safe-options\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: safe-options-loopback\r\n\
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
    let udp_response = String::from_utf8_lossy(&udp_response[..len]);
    assert!(udp_response.starts_with("SIP/2.0 200"));
    assert!(udp_response.contains("\r\nAllow: REGISTER, MESSAGE, OPTIONS\r\n"));
    assert!(udp_response.contains("\r\nSupported: gb28181\r\n"));
    assert!(udp_response.contains("\r\nUser-Agent: GMV-PJSIP/0.1\r\n"));
    assert!(udp_response.contains("\r\nX-GB-Ver: 3.0\r\n"));

    let mut tcp = TcpStream::connect(("127.0.0.1", tcp_port)).expect("connect TCP client");
    tcp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set TCP timeout");
    let body = "<?xml version=\"1.0\"?><Notify><CmdType>Keepalive</CmdType></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{tcp_port} SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-safe-message;rport\r\n\
From: <sip:test@127.0.0.1>;tag=safe-message\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: safe-message-loopback\r\n\
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

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut copied = Vec::new();
    while copied.len() < 4 && Instant::now() < deadline {
        if let Ok(event) = events.recv_timeout(Duration::from_millis(100)) {
            copied.push(event);
        }
    }

    let options_event = copied
        .iter()
        .find(|event| {
            event.kind == SipRuntimeEventKind::RequestReceived
                && event.protocol == Some(SipTransportProtocol::Udp)
                && event.method.as_deref() == Some("OPTIONS")
        })
        .expect("copied OPTIONS event");
    assert_eq!(
        options_event.call_id.as_deref(),
        Some("safe-options-loopback")
    );
    assert_eq!(options_event.cseq, Some(1));
    assert_eq!(
        options_event.local_addr.map(|addr| addr.port()),
        Some(udp_port)
    );
    assert_eq!(options_event.remote_addr, Some(udp_local));
    assert!(options_event.body.is_empty());
    assert_ne!(options_event.event_id, 0);

    assert!(copied.iter().any(|event| {
        event.kind == SipRuntimeEventKind::ResponseSent
            && event.protocol == Some(SipTransportProtocol::Udp)
            && event.status_code == Some(200)
    }));
    let message_event = copied
        .iter()
        .find(|event| {
            event.kind == SipRuntimeEventKind::RequestReceived
                && event.protocol == Some(SipTransportProtocol::Tcp)
                && event.method.as_deref() == Some("MESSAGE")
        })
        .expect("copied MESSAGE event");
    assert_eq!(
        message_event.call_id.as_deref(),
        Some("safe-message-loopback")
    );
    assert_eq!(message_event.cseq, Some(1));
    assert_eq!(
        message_event.content_type.as_deref(),
        Some("Application/MANSCDP+xml")
    );
    assert_eq!(message_event.body, body.as_bytes());
    assert!(copied.iter().any(|event| {
        event.kind == SipRuntimeEventKind::ResponseSent
            && event.protocol == Some(SipTransportProtocol::Tcp)
            && event.status_code == Some(200)
    }));

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_absorbs_duplicate_udp_message_transaction() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (runtime, events) = SipRuntime::start(config).expect("start runtime");
    let port = runtime.udp_port().expect("UDP port");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind MESSAGE client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set MESSAGE timeout");
    let local = socket.local_addr().expect("MESSAGE client address");
    let body = "<?xml version=\"1.0\"?><Notify><CmdType>Keepalive</CmdType></Notify>";
    let message = format!(
        "MESSAGE sip:127.0.0.1:{port} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-safe-duplicate;rport\r\n\
From: <sip:test@127.0.0.1>;tag=safe-duplicate\r\n\
To: <sip:gmv@127.0.0.1>\r\n\
Call-ID: safe-duplicate-message\r\n\
CSeq: 1 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    for _ in 0..2 {
        socket
            .send_to(message.as_bytes(), ("127.0.0.1", port))
            .expect("send duplicate MESSAGE");
        let mut response = [0u8; 2048];
        let (len, _) = socket
            .recv_from(&mut response)
            .expect("receive duplicate MESSAGE response");
        assert!(String::from_utf8_lossy(&response[..len]).starts_with("SIP/2.0 200"));
    }

    let deadline = Instant::now() + Duration::from_millis(300);
    let mut request_count = 0;
    while Instant::now() < deadline {
        match events.recv_timeout(Duration::from_millis(20)) {
            Ok(event)
                if event.kind == SipRuntimeEventKind::RequestReceived
                    && event.method.as_deref() == Some("MESSAGE") =>
            {
                request_count += 1;
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    assert_eq!(request_count, 1);

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_sends_outbound_message_and_correlates_final_response() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events) = SipRuntime::start(config).expect("start runtime");
    let runtime_port = runtime.udp_port().expect("UDP port");
    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind outbound peer");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set outbound peer timeout");
    let peer_port = peer.local_addr().expect("outbound peer address").port();

    let responder = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        let (len, source) = peer
            .recv_from(&mut packet)
            .expect("receive outbound MESSAGE");
        let request = String::from_utf8_lossy(&packet[..len]).into_owned();
        assert!(request.starts_with("MESSAGE "));
        assert!(request.contains("<CmdType>DeviceInfo</CmdType>"));
        let via = header_value(&request, "Via").to_owned();
        let from = header_value(&request, "From").to_owned();
        let to = header_value(&request, "To").to_owned();
        let call_id = header_value(&request, "Call-ID").to_owned();
        let cseq = header_value(&request, "CSeq").to_owned();
        let response = format!(
            "SIP/2.0 200 OK\r\n\
Via: {via}\r\n\
From: {from}\r\n\
To: {to};tag=outbound-peer\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq}\r\n\
Content-Length: 0\r\n\r\n"
        );
        peer.send_to(response.as_bytes(), source)
            .expect("send outbound MESSAGE response");
    });

    let operation_id = 42;
    runtime
        .send_message(&SipOutboundMessage {
            operation_id,
            target_uri: format!("sip:device@127.0.0.1:{peer_port}"),
            from_uri: format!("<sip:platform@127.0.0.1:{runtime_port}>"),
            content_type: "Application/MANSCDP+xml".into(),
            body: b"<?xml version=\"1.0\"?><Query><CmdType>DeviceInfo</CmdType></Query>".to_vec(),
        })
        .expect("send outbound MESSAGE");

    let response = receive_event(&events, SipRuntimeEventKind::OutboundResponse);
    assert_eq!(response.operation_id, Some(operation_id));
    assert_eq!(response.status_code, Some(200));
    assert_eq!(response.method.as_deref(), Some("MESSAGE"));
    assert!(response.call_id.is_some());
    assert!(response.cseq.is_some());

    responder.join().expect("join outbound peer");
    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_completes_register_auth_asynchronously() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let mut config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    config.auth_realm = "3402000000".into();
    let (mut runtime, events) = SipRuntime::start(config).expect("start runtime");
    let port = runtime.udp_port().expect("UDP port");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind REGISTER client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set REGISTER timeout");
    let local = socket.local_addr().expect("REGISTER client address");
    let username = "34020000001320000001";
    let realm = "3402000000";
    let password = "safe-register-password";
    let uri = format!("sip:{realm}@127.0.0.1:{port}");
    let credential = AuthCredential {
        username: username.into(),
        realm: realm.into(),
        secret: password.into(),
        kind: CredentialKind::PlainPassword,
        algorithm: AuthAlgorithm::Md5,
    };

    let first = format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-register-1;rport\r\n\
From: <sip:{username}@{realm}>;tag=register-auth\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: safe-register-loopback\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:{username}@{local}>\r\n\
Expires: 3600\r\n\
User-Agent: GMV-Test-Device/1.0\r\n\
X-GB-Ver: 3.0\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(first.as_bytes(), ("127.0.0.1", port))
        .expect("send initial REGISTER");

    let lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    assert_eq!(lookup.device_id.as_deref(), Some(username));
    assert_eq!(lookup.realm.as_deref(), Some(realm));
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("initial lookup id"),
            SipAuthLookupResult::Credential(credential.clone()),
        )
        .expect("complete initial auth lookup");

    let challenge = receive_udp(&socket);
    assert!(challenge.starts_with("SIP/2.0 401"));
    assert_eq!(header_value(&challenge, "X-GB-Ver"), "3.0");
    let challenge_parts =
        gmv_pjsip::auth::parse_digest_authorization(header_value(&challenge, "WWW-Authenticate"));
    let nonce = challenge_parts.get("nonce").expect("challenge nonce");
    let nc = "00000001";
    let cnonce = "register-client-nonce";
    let response = create_digest_response(
        &credential,
        "REGISTER",
        &uri,
        nonce,
        Some(nc),
        Some(cnonce),
        Some("auth"),
        AuthAlgorithm::Md5,
    )
    .expect("create REGISTER digest");
    let authorized = format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-register-2;rport\r\n\
From: <sip:{username}@{realm}>;tag=register-auth\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: safe-register-loopback\r\n\
CSeq: 2 REGISTER\r\n\
Contact: <sip:{username}@{local}>\r\n\
Expires: 3600\r\n\
User-Agent: GMV-Test-Device/1.0\r\n\
X-GB-Ver: 3.0\r\n\
Max-Forwards: 70\r\n\
Authorization: Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm=MD5, cnonce=\"{cnonce}\", qop=auth, nc={nc}\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(authorized.as_bytes(), ("127.0.0.1", port))
        .expect("send authorized REGISTER");
    let lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("authorized lookup id"),
            SipAuthLookupResult::Credential(credential.clone()),
        )
        .expect("complete authorized lookup");
    let ok = receive_udp(&socket);
    assert!(ok.starts_with("SIP/2.0 200"));
    assert_eq!(header_value(&ok, "X-GB-Ver"), "3.0");
    assert!(header_value(&ok, "Contact").contains(username));

    let registered = receive_event(&events, SipRuntimeEventKind::Registered);
    assert_eq!(registered.device_id.as_deref(), Some(username));
    assert_eq!(registered.status_code, Some(200));
    assert_eq!(registered.expires_seconds, Some(3600));
    assert_eq!(
        registered.user_agent.as_deref(),
        Some("GMV-Test-Device/1.0")
    );
    assert_eq!(registered.gb_version.as_deref(), Some("3.0"));
    assert!(registered
        .contact
        .as_deref()
        .is_some_and(|contact| contact.contains(username)));

    let wrong_credential = AuthCredential {
        secret: "wrong-password".into(),
        ..credential.clone()
    };
    let wrong_response = create_digest_response(
        &wrong_credential,
        "REGISTER",
        &uri,
        nonce,
        Some("00000002"),
        Some(cnonce),
        Some("auth"),
        AuthAlgorithm::Md5,
    )
    .expect("create wrong REGISTER digest");
    let rejected = format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-register-3;rport\r\n\
From: <sip:{username}@{realm}>;tag=register-auth\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: safe-register-loopback\r\n\
CSeq: 3 REGISTER\r\n\
Contact: <sip:{username}@{local}>\r\n\
Expires: 3600\r\n\
User-Agent: GMV-Test-Device/1.0\r\n\
X-GB-Ver: 3.0\r\n\
Max-Forwards: 70\r\n\
Authorization: Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{wrong_response}\", algorithm=MD5, cnonce=\"{cnonce}\", qop=auth, nc=00000002\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(rejected.as_bytes(), ("127.0.0.1", port))
        .expect("send rejected REGISTER");
    let lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("rejected lookup id"),
            SipAuthLookupResult::Credential(credential.clone()),
        )
        .expect("complete rejected lookup");
    let forbidden = receive_udp(&socket);
    assert!(forbidden.starts_with("SIP/2.0 403"));
    assert_eq!(header_value(&forbidden, "X-GB-Ver"), "3.0");
    let rejected = receive_event(&events, SipRuntimeEventKind::AuthRejected);
    assert_eq!(rejected.status_code, Some(403));

    let unregister_response = create_digest_response(
        &credential,
        "REGISTER",
        &uri,
        nonce,
        Some("00000003"),
        Some(cnonce),
        Some("auth"),
        AuthAlgorithm::Md5,
    )
    .expect("create unregister digest");
    let unregister = format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-register-4;rport\r\n\
From: <sip:{username}@{realm}>;tag=register-auth\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: safe-register-loopback\r\n\
CSeq: 4 REGISTER\r\n\
Contact: <sip:{username}@{local}>;expires=0\r\n\
User-Agent: GMV-Test-Device/1.0\r\n\
X-GB-Ver: 3.0\r\n\
Max-Forwards: 70\r\n\
Authorization: Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{unregister_response}\", algorithm=MD5, cnonce=\"{cnonce}\", qop=auth, nc=00000003\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(unregister.as_bytes(), ("127.0.0.1", port))
        .expect("send unregister");
    let lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("unregister lookup id"),
            SipAuthLookupResult::Credential(credential.clone()),
        )
        .expect("complete unregister lookup");
    assert!(receive_udp(&socket).starts_with("SIP/2.0 200"));
    let unregistered = receive_event(&events, SipRuntimeEventKind::Unregistered);
    assert_eq!(unregistered.expires_seconds, Some(0));

    let wrong_uri = format!("sip:wrong@127.0.0.1:{port}");
    let wrong_uri_response = create_digest_response(
        &credential,
        "REGISTER",
        &wrong_uri,
        nonce,
        Some("00000004"),
        Some(cnonce),
        Some("auth"),
        AuthAlgorithm::Md5,
    )
    .expect("create wrong URI digest");
    let wrong_uri_register = format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-register-5;rport\r\n\
From: <sip:{username}@{realm}>;tag=register-auth\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: safe-register-loopback\r\n\
CSeq: 5 REGISTER\r\n\
Contact: <sip:{username}@{local}>\r\n\
Max-Forwards: 70\r\n\
Authorization: Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{wrong_uri}\", response=\"{wrong_uri_response}\", algorithm=MD5, cnonce=\"{cnonce}\", qop=auth, nc=00000004\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(wrong_uri_register.as_bytes(), ("127.0.0.1", port))
        .expect("send wrong URI REGISTER");
    assert!(receive_udp(&socket).starts_with("SIP/2.0 403"));

    let replay = format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-register-6;rport\r\n\
From: <sip:{username}@{realm}>;tag=register-auth\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: safe-register-loopback\r\n\
CSeq: 6 REGISTER\r\n\
Contact: <sip:{username}@{local}>;expires=0\r\n\
Max-Forwards: 70\r\n\
Authorization: Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{unregister_response}\", algorithm=MD5, cnonce=\"{cnonce}\", qop=auth, nc=00000003\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(replay.as_bytes(), ("127.0.0.1", port))
        .expect("send replayed REGISTER");
    let lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("replay lookup id"),
            SipAuthLookupResult::Credential(credential),
        )
        .expect("complete replay lookup");
    assert!(receive_udp(&socket).starts_with("SIP/2.0 403"));
    let replay_rejected = receive_event(&events, SipRuntimeEventKind::AuthRejected);
    assert_eq!(replay_rejected.status_code, Some(403));

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_singleflights_same_device_register_lookups() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let config = SipRuntimeConfig {
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    let (mut runtime, events) = SipRuntime::start(config).expect("start runtime");
    let port = runtime.udp_port().expect("UDP port");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind REGISTER client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set REGISTER timeout");
    let local = socket.local_addr().expect("REGISTER local address");
    let username = "34020000001320000002";
    let realm = "3402000000";
    let uri = format!("sip:{realm}@127.0.0.1:{port}");

    for sequence in 1..=2 {
        let request = format!(
            "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-singleflight-{sequence};rport\r\n\
From: <sip:{username}@{realm}>;tag=singleflight\r\n\
To: <sip:{username}@{realm}>\r\n\
Call-ID: singleflight-{sequence}\r\n\
CSeq: {sequence} REGISTER\r\n\
Contact: <sip:{username}@{local}>\r\n\
Expires: 3600\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
        );
        socket
            .send_to(request.as_bytes(), ("127.0.0.1", port))
            .expect("send concurrent REGISTER");
    }

    let lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        if let Ok(event) = events.recv_timeout(Duration::from_millis(10)) {
            assert_ne!(
                event.kind,
                SipRuntimeEventKind::AuthLookupRequired,
                "same device emitted a duplicate lookup"
            );
        }
    }
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("singleflight lookup id"),
            SipAuthLookupResult::Bypass,
        )
        .expect("complete singleflight lookup");
    assert!(receive_udp(&socket).starts_with("SIP/2.0 200"));
    assert!(receive_udp(&socket).starts_with("SIP/2.0 200"));
    let first = receive_event(&events, SipRuntimeEventKind::Registered);
    let second = receive_event(&events, SipRuntimeEventKind::Registered);
    assert_eq!(first.lookup_id, lookup.lookup_id);
    assert_eq!(second.lookup_id, lookup.lookup_id);

    runtime.shutdown().expect("shutdown runtime");
}

#[test]
fn runtime_times_out_pending_auth_lookup() {
    let _guard = TEST_LOCK.lock().expect("lock native runtime tests");
    let config = SipRuntimeConfig {
        enable_tcp: false,
        auth_lookup_timeout: Duration::from_millis(50),
        ..SipRuntimeConfig::default()
    };
    let (runtime, events) = SipRuntime::start(config).expect("start runtime");
    let port = runtime.udp_port().expect("UDP port");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind REGISTER client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set REGISTER timeout");
    let local = socket.local_addr().expect("REGISTER local address");
    let request = format!(
        "REGISTER sip:3402000000@127.0.0.1:{port} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-auth-timeout;rport\r\n\
From: <sip:34020000001320000003@3402000000>;tag=auth-timeout\r\n\
To: <sip:34020000001320000003@3402000000>\r\n\
Call-ID: auth-timeout\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:34020000001320000003@{local}>\r\n\
Expires: 3600\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n"
    );
    socket
        .send_to(request.as_bytes(), ("127.0.0.1", port))
        .expect("send timeout REGISTER");
    let _lookup = receive_event(&events, SipRuntimeEventKind::AuthLookupRequired);
    assert!(receive_udp(&socket).starts_with("SIP/2.0 504"));
    let rejected = receive_event(&events, SipRuntimeEventKind::AuthRejected);
    assert_eq!(rejected.status_code, Some(504));

    runtime.shutdown().expect("shutdown runtime");
}
