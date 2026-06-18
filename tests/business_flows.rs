mod support;

use std::sync::Mutex;

use gmv_pjsip::gb28181::sdp::{
    build_play_sdp, build_talk_sdp, PlaySdpOptions, TalkAudioCodec, TalkSdpMode, TalkSdpOptions,
};
use gmv_pjsip::gb28181::xml::{
    build_mansrtsp_seek_body, build_mansrtsp_speed_body, build_preset_query_xml,
    build_snapshot_control_xml,
};
use gmv_pjsip::{
    SipAuthLookupResult, SipDialogMethod, SipDialogRequest, SipOutboundInvite, SipOutboundMessage,
    SipOutboundSubscribe, SipRuntimeEventKind, SipTransportProtocol,
};
use support::device_simulator::{device_addr, platform_addr, CHANNEL_ID, DEVICE_ID, PLATFORM_ID};
use support::{
    finish_transmit, header_value, receive_event_matching, receive_transmit, receive_transmit_for,
    start_runtime, DeviceSimulator,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn xml(cmd_type: &str, sn: u32, body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<Query>\r\n\
<CmdType>{cmd_type}</CmdType>\r\n\
<SN>{sn}</SN>\r\n\
<DeviceID>{DEVICE_ID}</DeviceID>\r\n\
{body}</Query>\r\n"
    )
}

fn send_message_round_trip(
    runtime: &mut gmv_pjsip::SipRuntime,
    events: &gmv_pjsip::SipRuntimeEvents,
    transmits: &gmv_pjsip::SipRuntimeTransmits,
    device: &DeviceSimulator,
    operation_id: u64,
    body: String,
    expected: &str,
) {
    runtime
        .send_message(&SipOutboundMessage {
            operation_id,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: format!("sip:{DEVICE_ID}@{}", device_addr()),
            from_uri: format!("<sip:{PLATFORM_ID}@{}>", platform_addr()),
            content_type: "Application/MANSCDP+xml".into(),
            body: body.into_bytes(),
        })
        .expect("send MESSAGE");
    let transmit = receive_transmit(runtime, transmits);
    let request = finish_transmit(runtime, &transmit);
    assert!(request.starts_with("MESSAGE "));
    assert!(request.contains(expected));
    device.respond_ok(runtime, &request);
    let response = receive_event_matching(runtime, events, |event| {
        event.kind == SipRuntimeEventKind::OutboundResponse
            && event.operation_id == Some(operation_id)
            && event.status_code == Some(200)
    });
    assert_eq!(response.method.as_deref(), Some("MESSAGE"));
}

#[allow(clippy::too_many_arguments)]
fn invite_round_trip(
    runtime: &mut gmv_pjsip::SipRuntime,
    events: &gmv_pjsip::SipRuntimeEvents,
    transmits: &gmv_pjsip::SipRuntimeTransmits,
    device: &DeviceSimulator,
    operation_id: u64,
    subject: &str,
    local_sdp: String,
    expected_sdp_line: &str,
    remote_sdp: &str,
) -> String {
    runtime
        .send_invite(&SipOutboundInvite {
            operation_id,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            identity: gmv_pjsip::SipInviteIdentity::generate(),
            target_uri: format!("sip:{DEVICE_ID}@{}", device_addr()),
            from_uri: format!("<sip:{PLATFORM_ID}@3402000000>"),
            contact_uri: format!("<sip:{PLATFORM_ID}@{}>", platform_addr()),
            subject: Some(subject.into()),
            sdp: local_sdp,
        })
        .expect("send INVITE");
    let transmit = receive_transmit(runtime, transmits);
    let request = finish_transmit(runtime, &transmit);
    assert!(request.starts_with(&format!("INVITE sip:{DEVICE_ID}@")));
    assert_eq!(
        header_value(&request, "To"),
        format!("<sip:{CHANNEL_ID}@{}>", device_addr().ip())
    );
    assert_eq!(header_value(&request, "Subject"), subject);
    assert!(request.contains(expected_sdp_line));
    device.accept_invite(runtime, &request, remote_sdp);
    let response = receive_event_matching(runtime, events, |event| {
        event.kind == SipRuntimeEventKind::OutboundResponse
            && event.operation_id == Some(operation_id)
            && event.status_code == Some(200)
    });
    let call_id = response.call_id.expect("INVITE call id");
    let ack = receive_transmit(runtime, transmits);
    assert_eq!(ack.remote_addr, device_addr());
    assert!(finish_transmit(runtime, &ack).starts_with("ACK "));
    call_id
}

#[allow(clippy::too_many_arguments)]
fn dialog_round_trip(
    runtime: &mut gmv_pjsip::SipRuntime,
    events: &gmv_pjsip::SipRuntimeEvents,
    transmits: &gmv_pjsip::SipRuntimeTransmits,
    device: &DeviceSimulator,
    operation_id: u64,
    method: SipDialogMethod,
    call_id: String,
    content_type: Option<&str>,
    body: String,
    expected_start: &str,
) {
    runtime
        .send_dialog_request(&SipDialogRequest {
            operation_id,
            method,
            call_id,
            content_type: content_type.map(ToOwned::to_owned),
            body: body.into_bytes(),
        })
        .expect("send dialog request");
    let transmit = receive_transmit(runtime, transmits);
    assert_eq!(transmit.remote_addr, device_addr());
    let request = finish_transmit(runtime, &transmit);
    assert!(request.starts_with(expected_start));
    device.respond_ok(runtime, &request);
    let response = receive_event_matching(runtime, events, |event| {
        event.kind == SipRuntimeEventKind::OutboundResponse
            && event.operation_id == Some(operation_id)
            && event.status_code == Some(200)
    });
    assert!(matches!(response.method.as_deref(), Some("INFO" | "BYE")));
}

#[test]
fn normal_gb28181_business_dialogues_use_runtime_adapter() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (mut runtime, events, transmits) = start_runtime();
    let mut device = DeviceSimulator::default();

    device.inject_register(&mut runtime);
    let lookup = receive_event_matching(&mut runtime, &events, |event| {
        event.kind == SipRuntimeEventKind::AuthLookupRequired
    });
    runtime
        .complete_auth_lookup(
            lookup.lookup_id.expect("auth lookup id"),
            SipAuthLookupResult::Bypass,
        )
        .expect("complete auth");
    let register_response = receive_transmit_for(&mut runtime, &transmits, "REGISTER response");
    assert!(finish_transmit(&mut runtime, &register_response).starts_with("SIP/2.0 200"));
    let registered = receive_event_matching(&mut runtime, &events, |event| {
        event.kind == SipRuntimeEventKind::Registered
    });
    assert_eq!(registered.device_id.as_deref(), Some(DEVICE_ID));

    device.inject_request(&mut runtime, "OPTIONS", "normal-options", None, "", &[]);
    let options_response = receive_transmit_for(&mut runtime, &transmits, "OPTIONS response");
    assert!(finish_transmit(&mut runtime, &options_response).starts_with("SIP/2.0 200"));

    let keepalive = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<Notify>\r\n<CmdType>Keepalive</CmdType>\r\n<SN>1</SN>\r\n\
<DeviceID>{DEVICE_ID}</DeviceID>\r\n<Status>OK</Status>\r\n</Notify>\r\n"
    );
    device.inject_request(
        &mut runtime,
        "MESSAGE",
        "normal-keepalive",
        Some("Application/MANSCDP+xml"),
        &keepalive,
        &[],
    );
    let keepalive_response = receive_transmit_for(&mut runtime, &transmits, "Keepalive response");
    assert!(finish_transmit(&mut runtime, &keepalive_response).starts_with("SIP/2.0 200"));
    let keepalive_event = receive_event_matching(&mut runtime, &events, |event| {
        event.kind == SipRuntimeEventKind::RequestReceived
            && event.method.as_deref() == Some("MESSAGE")
            && event
                .body
                .windows(b"Keepalive".len())
                .any(|part| part == b"Keepalive")
    });
    assert_eq!(keepalive_event.call_id.as_deref(), Some("normal-keepalive"));

    let messages = [
        (
            10,
            xml("DeviceInfo", 10, ""),
            "<CmdType>DeviceInfo</CmdType>",
        ),
        (11, xml("Catalog", 11, ""), "<CmdType>Catalog</CmdType>"),
        (
            12,
            xml(
                "RecordInfo",
                12,
                "<StartTime>2026-06-13T00:00:00</StartTime>\r\n\
<EndTime>2026-06-13T01:00:00</EndTime>\r\n",
            ),
            "<CmdType>RecordInfo</CmdType>",
        ),
        (
            13,
            build_preset_query_xml(CHANNEL_ID),
            "<CmdType>PresetQuery</CmdType>",
        ),
        (
            14,
            format!(
                "<?xml version=\"1.0\"?>\r\n<Control>\r\n\
<CmdType>DeviceControl</CmdType>\r\n<SN>14</SN>\r\n\
<DeviceID>{CHANNEL_ID}</DeviceID>\r\n\
<PTZCmd>A50F0102201000E7</PTZCmd>\r\n</Control>\r\n"
            ),
            "<PTZCmd>",
        ),
        (
            15,
            build_snapshot_control_xml(
                CHANNEL_ID,
                1,
                1,
                "http://192.0.2.10:8080/edge/upload/picture/token",
                "snapshot-session",
            ),
            "<CmdType>DeviceConfig</CmdType>",
        ),
        (
            16,
            xml("DeviceStatus", 16, ""),
            "<CmdType>DeviceStatus</CmdType>",
        ),
    ];
    for (operation_id, body, expected) in messages {
        send_message_round_trip(
            &mut runtime,
            &events,
            &transmits,
            &device,
            operation_id,
            body,
            expected,
        );
    }

    let remote_video_sdp = format!(
        "v=0\r\n\
o={DEVICE_ID} 0 0 IN IP4 198.51.100.20\r\n\
s=Play\r\n\
c=IN IP4 198.51.100.20\r\n\
t=0 0\r\n\
m=video 30000 RTP/AVP 96\r\n\
a=sendonly\r\n\
a=rtpmap:96 PS/90000\r\n\
y=0100008199\r\n"
    );
    let live_call_id = invite_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        20,
        &format!("{CHANNEL_ID}:0100008199,{PLATFORM_ID}:0100008199"),
        build_play_sdp(PlaySdpOptions {
            ip: "192.0.2.10".into(),
            port: 18_568,
            ssrc: 100_008_199,
            payload_type: 96,
        }),
        "s=Play",
        &remote_video_sdp,
    );
    dialog_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        21,
        SipDialogMethod::Bye,
        live_call_id,
        None,
        String::new(),
        "BYE ",
    );

    let playback_sdp = format!(
        "v=0\r\n\
o={CHANNEL_ID} 0 0 IN IP4 192.0.2.10\r\n\
s=Playback\r\n\
u={CHANNEL_ID}:0\r\n\
c=IN IP4 192.0.2.10\r\n\
t=1781308800 1781312400\r\n\
m=video 18568 RTP/AVP 96\r\n\
a=recvonly\r\n\
a=rtpmap:96 PS/90000\r\n\
y=0100008200\r\n"
    );
    let playback_call_id = invite_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        22,
        &format!("{CHANNEL_ID}:0100008200,{PLATFORM_ID}:0100008200"),
        playback_sdp,
        "s=Playback",
        &remote_video_sdp,
    );
    dialog_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        23,
        SipDialogMethod::Info,
        playback_call_id.clone(),
        Some("Application/MANSRTSP"),
        build_mansrtsp_seek_body(30.0, 1),
        "INFO ",
    );
    dialog_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        24,
        SipDialogMethod::Info,
        playback_call_id.clone(),
        Some("Application/MANSRTSP"),
        build_mansrtsp_speed_body(2.0, None, 2),
        "INFO ",
    );
    dialog_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        25,
        SipDialogMethod::Bye,
        playback_call_id,
        None,
        String::new(),
        "BYE ",
    );

    let download_sdp = format!(
        "v=0\r\n\
o={CHANNEL_ID} 0 0 IN IP4 192.0.2.10\r\n\
s=Download\r\n\
u={CHANNEL_ID}:0\r\n\
c=IN IP4 192.0.2.10\r\n\
t=1781308800 1781312400\r\n\
m=video 18568 RTP/AVP 96\r\n\
a=recvonly\r\n\
a=rtpmap:96 PS/90000\r\n\
a=downloadspeed:1\r\n\
y=0100008201\r\n"
    );
    let download_call_id = invite_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        26,
        &format!("{CHANNEL_ID}:0100008201,{PLATFORM_ID}:0100008201"),
        download_sdp,
        "s=Download",
        &remote_video_sdp,
    );
    dialog_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        27,
        SipDialogMethod::Bye,
        download_call_id,
        None,
        String::new(),
        "BYE ",
    );

    let remote_talk_sdp = format!(
        "v=0\r\n\
o={DEVICE_ID} 0 0 IN IP4 198.51.100.20\r\n\
s=Talk\r\n\
c=IN IP4 198.51.100.20\r\n\
t=0 0\r\n\
m=audio 30002 RTP/AVP 8\r\n\
a=sendrecv\r\n\
a=rtpmap:8 PCMA/8000\r\n\
y=0200008202\r\n"
    );
    let talk_call_id = invite_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        28,
        &format!("{CHANNEL_ID}:0200008202,{PLATFORM_ID}:0200008202"),
        build_talk_sdp(TalkSdpOptions {
            ip: "192.0.2.10".into(),
            port: 18_570,
            ssrc: 200_008_202,
            payload_type: 8,
            codec: TalkAudioCodec::G711A,
            mode: TalkSdpMode::SendRecv,
        }),
        "s=Talk",
        &remote_talk_sdp,
    );
    dialog_round_trip(
        &mut runtime,
        &events,
        &transmits,
        &device,
        29,
        SipDialogMethod::Bye,
        talk_call_id,
        None,
        String::new(),
        "BYE ",
    );

    runtime
        .send_subscribe(&SipOutboundSubscribe {
            operation_id: 30,
            association_id: 0,
            protocol: SipTransportProtocol::Udp,
            target_uri: format!("sip:{DEVICE_ID}@{}", device_addr()),
            from_uri: format!("<sip:{PLATFORM_ID}@{}>", platform_addr()),
            contact_uri: format!("<sip:{PLATFORM_ID}@{}>", platform_addr()),
            call_id: None,
            event: "Catalog".into(),
            expires: 300,
            content_type: "Application/MANSCDP+xml".into(),
            body: xml("Catalog", 30, "").into_bytes(),
        })
        .expect("send SUBSCRIBE");
    let subscribe_transmit = receive_transmit(&mut runtime, &transmits);
    let subscribe = finish_transmit(&mut runtime, &subscribe_transmit);
    assert!(subscribe.starts_with("SUBSCRIBE "));
    device.respond_subscribe(&mut runtime, &subscribe, 300);
    let accepted = receive_event_matching(&mut runtime, &events, |event| {
        event.kind == SipRuntimeEventKind::OutboundResponse
            && event.operation_id == Some(30)
            && event.status_code == Some(200)
    });
    assert_eq!(
        accepted.call_id.as_deref(),
        Some(header_value(&subscribe, "Call-ID"))
    );
    let notify_body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<Notify>\r\n<CmdType>Catalog</CmdType>\r\n<SN>31</SN>\r\n\
<DeviceID>{DEVICE_ID}</DeviceID>\r\n<SumNum>0</SumNum>\r\n</Notify>\r\n"
    );
    device.inject_notify(&mut runtime, &subscribe, &notify_body);
    let notify_response = receive_transmit_for(&mut runtime, &transmits, "NOTIFY response");
    assert!(finish_transmit(&mut runtime, &notify_response).starts_with("SIP/2.0 200"));
    let notify = receive_event_matching(&mut runtime, &events, |event| {
        event.kind == SipRuntimeEventKind::RequestReceived
            && event.method.as_deref() == Some("NOTIFY")
    });
    assert_eq!(notify.event.as_deref(), Some("Catalog"));

    runtime.shutdown().expect("shutdown PJSIP runtime");
}
