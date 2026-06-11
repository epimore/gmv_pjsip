use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use gmv_pjsip::auth::{AuthAlgorithm, AuthConfig, StaticPasswordProvider};
use gmv_pjsip::message::HeaderMapExt;
use gmv_pjsip::parser::parse_sip_message;
use gmv_pjsip::{
    CreateBye, CreateInvite, SipContext, SipEvent, SipLocalConfig, SipPacketMeta,
    SipTransportProtocol,
};

fn local_config() -> SipLocalConfig {
    SipLocalConfig {
        platform_id: "34020000002000000001".into(),
        realm: "3402000000".into(),
        domain: "3402000000".into(),
        user_agent: "GMV-PJSIP-Test/0.1".into(),
        public_host: "192.168.1.10".into(),
        listen_port: 5060,
        default_expires: 3600,
        transaction_ttl: Duration::from_secs(32),
        auth: AuthConfig::disabled("3402000000"),
    }
}

fn meta(protocol: SipTransportProtocol) -> SipPacketMeta {
    SipPacketMeta {
        local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 5060),
        remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 5060),
        protocol,
        received_at: Instant::now(),
    }
}

fn header(bytes: &Bytes, name: &str) -> String {
    parse_sip_message(bytes.clone())
        .unwrap()
        .header(name)
        .unwrap_or_default()
        .to_string()
}

fn call_id(bytes: &Bytes) -> String {
    header(bytes, "Call-ID")
}

#[test]
fn register_without_authorization_gets_digest_challenge() {
    let mut cfg = local_config();
    cfg.auth = AuthConfig::digest(
        "3402000000",
        Arc::new(StaticPasswordProvider {
            username: "34020000001320000001".into(),
            password: "123456".into(),
        }),
        AuthAlgorithm::Md5,
    );
    let ctx = SipContext::new(cfg);
    let request = Bytes::from_static(
        b"REGISTER sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-reg-auth-1;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000001320000001@3402000000>\r\n\
Call-ID: reg-auth-call-1\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:34020000001320000001@192.168.1.20:5060>\r\n\
Expires: 3600\r\n\
Content-Length: 0\r\n\r\n",
    );

    let out = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    assert!(out.event.is_none());
    let response = parse_sip_message(out.sends[0].1.clone()).unwrap();
    assert_eq!(response.status_code(), Some(401));
    let www = response.header("WWW-Authenticate").unwrap();
    assert!(www.contains("Digest"));
    assert!(www.contains(r#"realm="3402000000""#));
    assert!(www.contains(r#"qop="auth""#));
}

#[test]
fn register_ok_and_udp_retransmit_reuses_response_without_event() {
    let ctx = SipContext::new(local_config());
    let request = Bytes::from_static(
        b"REGISTER sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-reg-1;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000001320000001@3402000000>\r\n\
Call-ID: reg-call-1\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:34020000001320000001@192.168.1.20:5060>\r\n\
Expires: 3600\r\n\
User-Agent: Device-Test\r\n\
Content-Length: 0\r\n\r\n",
    );

    let first = ctx
        .handle_rx_packet(request.clone(), meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(first.sends.len(), 1);
    assert!(matches!(first.event, Some(SipEvent::Register(_))));
    assert!(String::from_utf8_lossy(&first.sends[0].1).starts_with("SIP/2.0 200 OK"));

    let second = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(second.sends.len(), 1);
    assert!(second.event.is_none());
    assert_eq!(first.sends[0].1, second.sends[0].1);
}

#[test]
fn message_keepalive_generates_event_and_200_ok() {
    let ctx = SipContext::new(local_config());
    let body = r#"<?xml version="1.0"?><Notify><CmdType>Keepalive</CmdType><DeviceID>34020000001320000001</DeviceID></Notify>"#;
    let request = Bytes::from(format!(
        "MESSAGE sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-msg-1;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000002000000001@3402000000>\r\n\
Call-ID: msg-call-1\r\n\
CSeq: 20 MESSAGE\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    ));

    let out = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    assert!(String::from_utf8_lossy(&out.sends[0].1).starts_with("SIP/2.0 200 OK"));
    match out.event.unwrap() {
        SipEvent::Message(event) => assert_eq!(format!("{:?}", event.kind), "Keepalive"),
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn invite_2xx_generates_tcp_ack_with_original_dialog_headers() {
    let ctx = SipContext::new(local_config());
    let invite = ctx
        .create_invite(CreateInvite {
            device_id: "34020000001320000001".into(),
            channel_id: "34020000001320000002".into(),
            stream_id: "stream-1".into(),
            target_uri: "sip:34020000001320000001@192.168.1.20:5060;transport=tcp".into(),
            sdp: "v=0\r\ns=Play\r\n".into(),
            ssrc: Some(12345678),
            protocol: SipTransportProtocol::Tcp,
            call_id: Some("invite-call-1".into()),
            cseq: Some(7),
            subject: None,
        })
        .unwrap();

    let from = header(&invite, "From");
    let to = header(&invite, "To");
    let call_id = call_id(&invite);
    let sdp = "v=0\r\ns=Play\r\ny=12345678\r\n";
    let response = Bytes::from(format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=device-to-tag\r\n\
Call-ID: {}\r\n\
CSeq: 7 INVITE\r\n\
Contact: <sip:34020000001320000001@192.168.1.20:5060;transport=tcp>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
        header(&invite, "Via"),
        from,
        to,
        call_id,
        sdp.len(),
        sdp
    ));

    let out = ctx
        .handle_rx_packet(response, meta(SipTransportProtocol::Tcp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    match out.event.unwrap() {
        SipEvent::InviteAccepted(event) => assert_eq!(event.call_id, "invite-call-1"),
        other => panic!("unexpected event: {other:?}"),
    }

    let ack = &out.sends[0].1;
    assert!(String::from_utf8_lossy(ack).starts_with("ACK "));
    assert!(header(ack, "Via").starts_with("SIP/2.0/TCP"));
    assert_eq!(header(ack, "CSeq"), "7 ACK");
    assert_eq!(header(ack, "From"), from);
    assert!(header(ack, "To").contains("device-to-tag"));
}

#[test]
fn bye_uses_dialog_protocol_and_cleanup_removes_terminated_state() {
    let ctx = SipContext::new(local_config());
    let invite = ctx
        .create_invite(CreateInvite {
            device_id: "34020000001320000001".into(),
            channel_id: "34020000001320000002".into(),
            stream_id: "stream-2".into(),
            target_uri: "sip:34020000001320000001@192.168.1.20:5060;transport=tcp".into(),
            sdp: "v=0\r\ns=Play\r\n".into(),
            ssrc: Some(22334455),
            protocol: SipTransportProtocol::Tcp,
            call_id: Some("invite-call-2".into()),
            cseq: Some(1),
            subject: None,
        })
        .unwrap();

    let response = Bytes::from(format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=device-to-tag\r\n\
Call-ID: invite-call-2\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:34020000001320000001@192.168.1.20:5060;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n",
        header(&invite, "Via"),
        header(&invite, "From"),
        header(&invite, "To")
    ));
    let _ = ctx
        .handle_rx_packet(response, meta(SipTransportProtocol::Tcp))
        .unwrap();

    let bye = ctx
        .create_bye(CreateBye {
            call_id: Some("invite-call-2".into()),
            stream_id: None,
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&bye).starts_with("BYE "));
    assert!(header(&bye, "Via").starts_with("SIP/2.0/TCP"));
    assert_eq!(header(&bye, "CSeq"), "2 BYE");

    let remote_bye = Bytes::from(format!(
        "BYE sip:34020000002000000001@192.168.1.10:5060;transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.168.1.20:5060;branch=z9hG4bK-bye-remote;rport\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: invite-call-2\r\n\
CSeq: 2 BYE\r\n\
Content-Length: 0\r\n\r\n",
        header(&bye, "To"),
        header(&bye, "From")
    ));
    let out = ctx
        .handle_rx_packet(remote_bye, meta(SipTransportProtocol::Tcp))
        .unwrap();
    assert!(matches!(out.event, Some(SipEvent::Bye(_))));

    let report = ctx.cleanup_expired_with(Duration::from_secs(0));
    assert!(report.expired_calls >= 1);
    assert!(ctx.calls.get("invite-call-2").is_none());
}

#[test]
fn parser_truncates_body_by_content_length_and_ignores_extra_bytes() {
    let raw = Bytes::from_static(
        b"MESSAGE sip:a@b SIP/2.0\r\n\
Via: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bK-extra\r\n\
From: <sip:a@b>;tag=1\r\n\
To: <sip:b@b>\r\n\
Call-ID: parser-call\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 4\r\n\r\n1234NEXT-PACKET",
    );
    let msg = parse_sip_message(raw).unwrap();
    assert_eq!(&msg.body[..], b"1234");
    assert!(!String::from_utf8_lossy(&msg.raw).contains("NEXT-PACKET"));
}

#[test]
fn talk_invite_builds_audio_sdp() {
    use gmv_pjsip::{CreateTalkInvite, TalkAudioCodec, TalkSdpMode};

    let ctx = SipContext::new(local_config());
    let invite = ctx
        .create_talk_invite(CreateTalkInvite {
            device_id: "34020000001320000001".into(),
            channel_id: "34020000001320000002".into(),
            talk_id: "talk-1".into(),
            target_uri: "sip:34020000001320000001@192.168.1.20:5060".into(),
            media_ip: "192.168.1.10".into(),
            media_port: 30000,
            ssrc: Some(99887766),
            payload_type: 8,
            codec: TalkAudioCodec::G711A,
            mode: TalkSdpMode::SendRecv,
            protocol: SipTransportProtocol::Udp,
            call_id: Some("talk-call-1".into()),
            cseq: Some(1),
            subject: None,
        })
        .unwrap();

    let text = String::from_utf8_lossy(&invite);
    assert!(text.starts_with("INVITE "));
    assert!(text.contains("m=audio 30000 RTP/AVP 8"));
    assert!(text.contains("a=sendrecv"));
    assert!(text.contains("a=rtpmap:8 PCMA/8000"));
}

#[test]
fn playback_seek_and_speed_are_in_dialog_info() {
    use gmv_pjsip::{CreatePlaybackSeekInfo, CreatePlaybackSpeedInfo};

    let ctx = SipContext::new(local_config());
    let invite = ctx
        .create_invite(CreateInvite {
            device_id: "34020000001320000001".into(),
            channel_id: "34020000001320000002".into(),
            stream_id: "stream-info".into(),
            target_uri: "sip:34020000001320000001@192.168.1.20:5060;transport=tcp".into(),
            sdp: "v=0\r\ns=Playback\r\n".into(),
            ssrc: Some(77889900),
            protocol: SipTransportProtocol::Tcp,
            call_id: Some("info-call-1".into()),
            cseq: Some(11),
            subject: None,
        })
        .unwrap();
    let response = Bytes::from(format!(
        "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=device-to-tag\r\n\
Call-ID: info-call-1\r\n\
CSeq: 11 INVITE\r\n\
Contact: <sip:34020000001320000001@192.168.1.20:5060;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n",
        header(&invite, "Via"),
        header(&invite, "From"),
        header(&invite, "To")
    ));
    let _ = ctx.handle_rx_packet(response, meta(SipTransportProtocol::Tcp)).unwrap();

    let seek = ctx
        .create_playback_seek_info(CreatePlaybackSeekInfo {
            call_id: Some("info-call-1".into()),
            stream_id: None,
            seek_second: 12.5,
            rtsp_cseq: Some(3),
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&seek).starts_with("INFO "));
    assert!(header(&seek, "Via").starts_with("SIP/2.0/TCP"));
    assert!(String::from_utf8_lossy(&seek).contains("Range: npt=12.500-"));

    let speed = ctx
        .create_playback_speed_info(CreatePlaybackSpeedInfo {
            call_id: None,
            stream_id: Some("stream-info".into()),
            scale: 4.0,
            range_start_second: Some(20.0),
            rtsp_cseq: Some(4),
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&speed).contains("Scale: 4.000"));
    assert!(String::from_utf8_lossy(&speed).contains("Range: npt=20.000-"));
}

#[test]
fn snapshot_message_helpers_and_upload_finished_event() {
    use gmv_pjsip::{CreatePresetQueryMessage, CreateSnapshotControlMessage};

    let ctx = SipContext::new(local_config());
    let preset = ctx
        .create_preset_query_message(CreatePresetQueryMessage {
            target_uri: "sip:34020000001320000001@192.168.1.20:5060".into(),
            device_id: "34020000001320000001".into(),
            protocol: SipTransportProtocol::Udp,
            call_id: Some("preset-call-1".into()),
            cseq: Some(21),
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&preset).contains("<CmdType>PresetQuery</CmdType>"));

    let snapshot = ctx
        .create_snapshot_control_message(CreateSnapshotControlMessage {
            target_uri: "sip:34020000001320000001@192.168.1.20:5060".into(),
            channel_id: "34020000001320000002".into(),
            snap_num: 1,
            interval: 1,
            upload_url: "http://example/upload".into(),
            session_id: "snapshot-session-1".into(),
            protocol: SipTransportProtocol::Udp,
            call_id: Some("snapshot-call-1".into()),
            cseq: Some(22),
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&snapshot).contains("<SnapShotConfig>"));
    assert!(String::from_utf8_lossy(&snapshot).contains("<SessionID>snapshot-session-1</SessionID>"));

    let body = r#"<?xml version="1.0"?><Notify><CmdType>UploadSnapShotFinished</CmdType><DeviceID>34020000001320000002</DeviceID><SessionID>snapshot-session-1</SessionID></Notify>"#;
    let request = Bytes::from(format!(
        "MESSAGE sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-snapshot;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000002000000001@3402000000>\r\n\
Call-ID: snapshot-notify-call\r\n\
CSeq: 20 MESSAGE\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    ));
    let out = ctx.handle_rx_packet(request, meta(SipTransportProtocol::Udp)).unwrap();
    match out.event.unwrap() {
        SipEvent::Message(event) => {
            assert_eq!(format!("{:?}", event.kind), "UploadSnapshotFinished");
            assert_eq!(event.snapshot_session_id.as_deref(), Some("snapshot-session-1"));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn parses_all_standard_sip_methods_and_preserves_unknown_extension() {
    use gmv_pjsip::SipMethod;

    let cases = [
        ("ACK", SipMethod::Ack),
        ("BYE", SipMethod::Bye),
        ("CANCEL", SipMethod::Cancel),
        ("INFO", SipMethod::Info),
        ("INVITE", SipMethod::Invite),
        ("MESSAGE", SipMethod::Message),
        ("NOTIFY", SipMethod::Notify),
        ("OPTIONS", SipMethod::Options),
        ("PRACK", SipMethod::Prack),
        ("PUBLISH", SipMethod::Publish),
        ("REFER", SipMethod::Refer),
        ("REGISTER", SipMethod::Register),
        ("SUBSCRIBE", SipMethod::Subscribe),
        ("UPDATE", SipMethod::Update),
    ];

    for (token, expected) in cases {
        let parsed = SipMethod::parse(token);
        assert_eq!(parsed, expected);
        assert_eq!(parsed.as_str(), token);
        assert!(parsed.is_standard());
    }

    let other = SipMethod::parse("X-GB-CUSTOM");
    assert_eq!(other.as_str(), "X-GB-CUSTOM");
    assert!(!other.is_standard());
    assert!(SipMethod::allow_header_value().contains("PRACK"));
    assert!(SipMethod::allow_header_value().contains("SUBSCRIBE"));
}

#[test]
fn options_returns_allow_and_capability_headers() {
    let ctx = SipContext::new(local_config());
    let request = Bytes::from_static(
        b"OPTIONS sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.168.1.20:5060;branch=z9hG4bK-options-1;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000002000000001@3402000000>\r\n\
Call-ID: options-call-1\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
    );

    let out = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Tcp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    assert!(out.event.is_none());
    let response = parse_sip_message(out.sends[0].1.clone()).unwrap();
    assert_eq!(response.status_code(), Some(200));
    let allow = response.header("Allow").unwrap();
    assert!(allow.contains("REGISTER"));
    assert!(allow.contains("PRACK"));
    assert!(allow.contains("UPDATE"));
    assert!(response.header("Accept").unwrap().contains("Application/MANSCDP+xml"));
    assert!(response.header("Contact").unwrap().contains("transport=tcp"));
}

#[test]
fn notify_is_accepted_and_exposed_as_standard_request_event() {
    let ctx = SipContext::new(local_config());
    let body = r#"<?xml version="1.0"?><Notify><CmdType>Catalog</CmdType></Notify>"#;
    let request = Bytes::from(format!(
        "NOTIFY sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-notify-1;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000002000000001@3402000000>;tag=to1\r\n\
Call-ID: notify-call-1\r\n\
CSeq: 3 NOTIFY\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    ));

    let out = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    assert!(String::from_utf8_lossy(&out.sends[0].1).starts_with("SIP/2.0 200 OK"));
    match out.event.unwrap() {
        SipEvent::StandardRequest(event) => {
            assert_eq!(event.method, gmv_pjsip::SipMethod::Notify);
            assert_eq!(event.call_id.as_deref(), Some("notify-call-1"));
            assert_eq!(event.cseq, Some(3));
            assert_eq!(event.content_type.as_deref(), Some("Application/MANSCDP+xml"));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn unsupported_standard_method_returns_501_with_allow_instead_of_error() {
    let ctx = SipContext::new(local_config());
    let request = Bytes::from_static(
        b"SUBSCRIBE sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-subscribe-1;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000002000000001@3402000000>\r\n\
Call-ID: subscribe-call-1\r\n\
CSeq: 1 SUBSCRIBE\r\n\
Content-Length: 0\r\n\r\n",
    );

    let out = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    assert!(out.event.is_none());
    let response = parse_sip_message(out.sends[0].1.clone()).unwrap();
    assert_eq!(response.status_code(), Some(501));
    assert!(response.header("Allow").unwrap().contains("SUBSCRIBE"));
    assert_eq!(response.header("Unsupported-Method"), Some("SUBSCRIBE"));
}

#[test]
fn cseq_method_mismatch_gets_400_response() {
    let ctx = SipContext::new(local_config());
    let request = Bytes::from_static(
        b"MESSAGE sip:34020000002000000001@3402000000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK-cseq-mismatch;rport\r\n\
From: <sip:34020000001320000001@3402000000>;tag=from1\r\n\
To: <sip:34020000002000000001@3402000000>\r\n\
Call-ID: cseq-mismatch-call-1\r\n\
CSeq: 8 INVITE\r\n\
Content-Length: 0\r\n\r\n",
    );

    let out = ctx
        .handle_rx_packet(request, meta(SipTransportProtocol::Udp))
        .unwrap();
    assert_eq!(out.sends.len(), 1);
    assert!(out.event.is_none());
    let response = parse_sip_message(out.sends[0].1.clone()).unwrap();
    assert_eq!(response.status_code(), Some(400));
    assert_eq!(response.header("CSeq"), Some("8 INVITE"));
}
