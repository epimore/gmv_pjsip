use bytes::Bytes;
use rand::{distributions::Alphanumeric, Rng};

use crate::message::{ensure_tag, reason_phrase, HeaderMapExt, SipMessage};
use crate::transport::SipTransportProtocol;

#[derive(Clone, Debug, Default)]
pub struct ResponseOptions {
    pub status_code: u16,
    pub reason: Option<String>,
    pub server: Option<String>,
    pub to_tag: Option<String>,
    pub contact: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: Option<Bytes>,
}

pub fn new_token(prefix: &str) -> String {
    let random: String = rand::thread_rng().sample_iter(&Alphanumeric).take(20).map(char::from).collect();
    format!("{}{}", prefix, random)
}

pub fn new_branch() -> String { new_token("z9hG4bKgmv") }
pub fn new_tag() -> String { new_token("gmv") }
pub fn new_call_id(host: &str) -> String { format!("{}@{}", new_token("call"), host) }

pub fn build_response(req: &SipMessage, opts: ResponseOptions) -> Bytes {
    let reason = opts.reason.unwrap_or_else(|| reason_phrase(opts.status_code).to_string());
    let mut out = String::new();
    out.push_str(&format!("SIP/2.0 {} {}\r\n", opts.status_code, reason));

    for via in req.headers("Via") {
        out.push_str("Via: ");
        out.push_str(via);
        out.push_str("\r\n");
    }
    if let Some(from) = req.header("From").or_else(|| req.header("f")) {
        out.push_str("From: "); out.push_str(from); out.push_str("\r\n");
    }
    if let Some(to) = req.header("To").or_else(|| req.header("t")) {
        out.push_str("To: ");
        if let Some(tag) = opts.to_tag.as_deref() { out.push_str(&ensure_tag(to, tag)); } else { out.push_str(to); }
        out.push_str("\r\n");
    }
    if let Some(call_id) = req.header("Call-ID") { out.push_str("Call-ID: "); out.push_str(call_id); out.push_str("\r\n"); }
    if let Some(cseq) = req.header("CSeq") { out.push_str("CSeq: "); out.push_str(cseq); out.push_str("\r\n"); }
    if let Some(server) = opts.server.as_deref() { out.push_str("Server: "); out.push_str(server); out.push_str("\r\n"); }
    if let Some(contact) = opts.contact.as_deref() { out.push_str("Contact: "); out.push_str(contact); out.push_str("\r\n"); }
    for (k, v) in opts.extra_headers { out.push_str(&k); out.push_str(": "); out.push_str(&v); out.push_str("\r\n"); }

    let body = opts.body.unwrap_or_default();
    if !body.is_empty() {
        if let Some(ct) = opts.content_type.as_deref() { out.push_str("Content-Type: "); out.push_str(ct); out.push_str("\r\n"); }
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    Bytes::from(bytes)
}

pub fn build_request(start_line: &str, headers: &[(String, String)], body: Option<Bytes>, content_type: Option<&str>) -> Bytes {
    let body = body.unwrap_or_default();
    let mut out = String::new();
    out.push_str(start_line);
    out.push_str("\r\n");
    for (k, v) in headers { out.push_str(k); out.push_str(": "); out.push_str(v); out.push_str("\r\n"); }
    if !body.is_empty() {
        if let Some(ct) = content_type { out.push_str("Content-Type: "); out.push_str(ct); out.push_str("\r\n"); }
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    Bytes::from(bytes)
}

pub fn contact(platform_id: &str, host: &str, port: u16, proto: SipTransportProtocol) -> String {
    match proto {
        SipTransportProtocol::Udp => format!("<sip:{}@{}:{}>", platform_id, host, port),
        SipTransportProtocol::Tcp => format!("<sip:{}@{}:{};transport=tcp>", platform_id, host, port),
        SipTransportProtocol::Tls => format!("<sips:{}@{}:{};transport=tls>", platform_id, host, port),
    }
}

pub fn via(host: &str, port: u16, proto: SipTransportProtocol, branch: &str) -> String {
    format!("SIP/2.0/{} {}:{};branch={};rport", proto.as_sip_token(), host, port, branch)
}
