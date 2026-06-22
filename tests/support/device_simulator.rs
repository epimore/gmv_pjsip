use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use gmv_pjsip::{
    SipRuntime, SipRuntimeConfig, SipRuntimeEvent, SipRuntimeEvents, SipRuntimeTransmits,
    SipTransmit, SipTransportProtocol,
};

pub const PLATFORM_PORT: u16 = 25_600;
pub const DEVICE_PORT: u16 = 5_060;
pub const PLATFORM_ID: &str = "34020000002000000001";
pub const DEVICE_ID: &str = "34020000001110000009";
pub const CHANNEL_ID: &str = "34020000001320000102";

pub fn platform_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(192, 0, 2, 10),
        PLATFORM_PORT,
    ))
}

pub fn device_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(198, 51, 100, 20),
        DEVICE_PORT,
    ))
}

pub fn device_contact_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(192, 168, 110, 254),
        DEVICE_PORT,
    ))
}

pub fn start_runtime() -> (SipRuntime, SipRuntimeEvents, SipRuntimeTransmits) {
    let config = SipRuntimeConfig {
        advertised_address: Ipv4Addr::new(192, 0, 2, 10),
        port: PLATFORM_PORT,
        enable_tcp: false,
        ..SipRuntimeConfig::default()
    };
    SipRuntime::start_for_test(config).expect("start PJSIP runtime")
}

pub fn receive_transmit(runtime: &mut SipRuntime, transmits: &SipRuntimeTransmits) -> SipTransmit {
    receive_transmit_for(runtime, transmits, "runtime adapter transmit")
}

pub fn receive_transmit_for(
    runtime: &mut SipRuntime,
    transmits: &SipRuntimeTransmits,
    scenario: &str,
) -> SipTransmit {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        runtime.poll().expect("poll runtime");
        if let Ok(transmit) = transmits.try_recv() {
            return transmit;
        }
    }
    panic!("timed out waiting for {scenario}");
}

pub fn finish_transmit(runtime: &mut SipRuntime, transmit: &SipTransmit) -> String {
    runtime
        .complete_test_send(transmit.send_id, Ok(transmit.data.len()))
        .expect("complete runtime adapter send");
    String::from_utf8_lossy(&transmit.data).into_owned()
}

pub fn receive_event_matching(
    runtime: &mut SipRuntime,
    events: &Receiver<SipRuntimeEvent>,
    predicate: impl Fn(&SipRuntimeEvent) -> bool,
) -> SipRuntimeEvent {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        runtime.poll().expect("poll runtime");
        while let Ok(event) = events.try_recv() {
            if predicate(&event) {
                return event;
            }
        }
    }
    panic!("timed out waiting for matching runtime event");
}

pub fn header_value<'a>(message: &'a str, name: &str) -> &'a str {
    message
        .lines()
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header.eq_ignore_ascii_case(name).then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("missing {name} header"))
}

pub struct DeviceSimulator {
    request_cseq: u32,
}

impl Default for DeviceSimulator {
    fn default() -> Self {
        Self { request_cseq: 1 }
    }
}

impl DeviceSimulator {
    pub fn inject_request(
        &mut self,
        runtime: &mut SipRuntime,
        method: &str,
        call_id: &str,
        content_type: Option<&str>,
        body: &str,
        extra_headers: &[(&str, &str)],
    ) {
        let branch = format!("z9hG4bK-gmv-{call_id}");
        let mut message = format!(
            "{method} sip:{PLATFORM_ID}@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch={branch};rport\r\n\
From: <sip:{DEVICE_ID}@3402000000>;tag=device-normal\r\n\
To: <sip:{PLATFORM_ID}@3402000000>\r\n\
Call-ID: {call_id}\r\n\
CSeq: {} {method}\r\n\
Contact: <sip:{DEVICE_ID}@{}>\r\n\
Max-Forwards: 70\r\n",
            platform_addr(),
            device_addr(),
            self.request_cseq,
            device_addr()
        );
        self.request_cseq += 1;
        for (name, value) in extra_headers {
            message.push_str(name);
            message.push_str(": ");
            message.push_str(value);
            message.push_str("\r\n");
        }
        if let Some(content_type) = content_type {
            message.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        message.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        self.inject(runtime, message.as_bytes());
    }

    pub fn inject_register(&mut self, runtime: &mut SipRuntime) {
        let message = format!(
            "REGISTER sip:3402000000@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-gmv-register;rport\r\n\
From: <sip:{DEVICE_ID}@3402000000>;tag=device-register\r\n\
To: <sip:{DEVICE_ID}@3402000000>\r\n\
Call-ID: normal-register\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:{DEVICE_ID}@{}>\r\n\
Expires: 3600\r\n\
User-Agent: GMV-Synthetic-Device/1.0\r\n\
X-GB-Ver: 3.0\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\r\n",
            platform_addr(),
            device_addr(),
            device_addr()
        );
        self.inject(runtime, message.as_bytes());
    }

    pub fn respond_ok(&self, runtime: &mut SipRuntime, request: &str) {
        let response = self.response(request, 200, "OK", &[], None, "");
        self.inject(runtime, response.as_bytes());
    }

    pub fn accept_invite(&self, runtime: &mut SipRuntime, request: &str, sdp: &str) {
        let trying = self.response(request, 100, "Trying", &[], None, "");
        self.inject(runtime, trying.as_bytes());
        let contact = format!("<sip:{DEVICE_ID}@{}>", device_contact_addr());
        let ok = self.response(
            request,
            200,
            "OK",
            &[("Contact", contact.as_str())],
            Some("application/sdp"),
            sdp,
        );
        self.inject(runtime, ok.as_bytes());
    }

    pub fn respond_subscribe(&self, runtime: &mut SipRuntime, request: &str, expires: u32) {
        let expires = expires.to_string();
        let contact = format!("<sip:{DEVICE_ID}@{}>", device_addr());
        let response = self.response(
            request,
            200,
            "OK",
            &[("Contact", contact.as_str()), ("Expires", expires.as_str())],
            None,
            "",
        );
        self.inject(runtime, response.as_bytes());
    }

    pub fn inject_notify(&mut self, runtime: &mut SipRuntime, subscribe: &str, body: &str) {
        let message = format!(
            "NOTIFY sip:{PLATFORM_ID}@{} SIP/2.0\r\n\
Via: SIP/2.0/UDP {};branch=z9hG4bK-gmv-notify;rport\r\n\
From: {};tag=device-normal\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {} NOTIFY\r\n\
Contact: <sip:{DEVICE_ID}@{}>\r\n\
Event: Catalog\r\n\
Subscription-State: active;expires=299\r\n\
Max-Forwards: 70\r\n\
Content-Type: Application/MANSCDP+xml\r\n\
Content-Length: {}\r\n\r\n{}",
            platform_addr(),
            device_addr(),
            header_value(subscribe, "To"),
            header_value(subscribe, "From"),
            header_value(subscribe, "Call-ID"),
            self.request_cseq,
            device_addr(),
            body.len(),
            body
        );
        self.request_cseq += 1;
        self.inject(runtime, message.as_bytes());
    }

    fn response(
        &self,
        request: &str,
        status: u16,
        reason: &str,
        extra_headers: &[(&str, &str)],
        content_type: Option<&str>,
        body: &str,
    ) -> String {
        let mut response = format!(
            "SIP/2.0 {status} {reason}\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=device-normal\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n",
            header_value(request, "Via"),
            header_value(request, "From"),
            header_value(request, "To"),
            header_value(request, "Call-ID"),
            header_value(request, "CSeq")
        );
        for (name, value) in extra_headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        if let Some(content_type) = content_type {
            response.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        response.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        response
    }

    fn inject(&self, runtime: &mut SipRuntime, bytes: &[u8]) {
        runtime
            .inject_test_packet(
                0,
                SipTransportProtocol::Udp,
                platform_addr(),
                device_addr(),
                bytes,
            )
            .expect("inject synthetic device packet");
    }
}
