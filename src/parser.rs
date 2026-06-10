use bytes::Bytes;

use crate::error::{Result, SipError};
use crate::message::{SipHeader, SipMessage, SipMethod, SipPacketKind, SipResponseStatus};

pub fn parse_sip_message(bytes: Bytes) -> Result<SipMessage> {
    let text = std::str::from_utf8(&bytes).map_err(|e| SipError::InvalidPacket(format!("not utf8 SIP text: {e}")))?;
    let (head, body) = split_head_body(text);
    let mut lines = head.lines().map(|l| l.trim_end_matches('\r'));
    let start_line = lines.next().ok_or_else(|| SipError::InvalidPacket("empty packet".into()))?.trim();

    let kind = if start_line.starts_with("SIP/2.0") {
        let mut p = start_line.splitn(3, ' ');
        let version = p.next().unwrap_or("SIP/2.0").to_string();
        let code = p.next().ok_or_else(|| SipError::InvalidPacket("response without status code".into()))?.parse::<u16>()
            .map_err(|e| SipError::InvalidPacket(format!("invalid status code: {e}")))?;
        let reason = p.next().unwrap_or("").to_string();
        SipPacketKind::Response { version, status: SipResponseStatus { code, reason } }
    } else {
        let mut p = start_line.split_whitespace();
        let method = p.next().ok_or_else(|| SipError::InvalidPacket("request without method".into()))?;
        let uri = p.next().ok_or_else(|| SipError::InvalidPacket("request without uri".into()))?.to_string();
        let version = p.next().unwrap_or("SIP/2.0").to_string();
        SipPacketKind::Request { method: SipMethod::parse(method), uri, version }
    };

    let mut headers: Vec<SipHeader> = Vec::new();
    for line in lines {
        if line.trim().is_empty() { continue; }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.value.push(' ');
                last.value.push_str(line.trim());
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(SipError::InvalidPacket(format!("bad header line: {line}")));
        };
        headers.push(SipHeader { name: canonical_header_name(name.trim()).to_string(), value: value.trim().to_string() });
    }

    Ok(SipMessage { kind, headers, body: Bytes::copy_from_slice(body.as_bytes()), raw: bytes })
}

fn split_head_body(text: &str) -> (&str, &str) {
    if let Some(idx) = text.find("\r\n\r\n") { (&text[..idx], &text[idx + 4..]) }
    else if let Some(idx) = text.find("\n\n") { (&text[..idx], &text[idx + 2..]) }
    else { (text, "") }
}

pub fn canonical_header_name(name: &str) -> &str {
    match name.to_ascii_lowercase().as_str() {
        "v" | "via" => "Via",
        "f" | "from" => "From",
        "t" | "to" => "To",
        "i" | "call-id" => "Call-ID",
        "m" | "contact" => "Contact",
        "l" | "content-length" => "Content-Length",
        "c" | "content-type" => "Content-Type",
        "cseq" => "CSeq",
        "max-forwards" => "Max-Forwards",
        "user-agent" => "User-Agent",
        "server" => "Server",
        "expires" => "Expires",
        "authorization" => "Authorization",
        "www-authenticate" => "WWW-Authenticate",
        "subject" => "Subject",
        _ => name,
    }
}
