use bytes::Bytes;

use crate::error::{Result, SipError};
use crate::message::{SipHeader, SipMessage, SipMethod, SipPacketKind, SipResponseStatus};

pub fn parse_sip_message(bytes: Bytes) -> Result<SipMessage> {
    let (head_end, body_start) = find_header_boundary(&bytes)
        .ok_or_else(|| SipError::InvalidPacket("missing SIP header/body delimiter".into()))?;

    let head = std::str::from_utf8(&bytes[..head_end])
        .map_err(|e| SipError::InvalidPacket(format!("SIP headers are not valid UTF-8/ASCII text: {e}")))?;

    let mut lines = head.lines().map(|l| l.trim_end_matches('\r'));
    let start_line = lines
        .next()
        .ok_or_else(|| SipError::InvalidPacket("empty packet".into()))?
        .trim();

    let kind = if start_line.starts_with("SIP/2.0") {
        let mut p = start_line.splitn(3, ' ');
        let version = p.next().unwrap_or("SIP/2.0").to_string();
        let code = p
            .next()
            .ok_or_else(|| SipError::InvalidPacket("response without status code".into()))?
            .parse::<u16>()
            .map_err(|e| SipError::InvalidPacket(format!("invalid status code: {e}")))?;
        let reason = p.next().unwrap_or("").to_string();
        SipPacketKind::Response {
            version,
            status: SipResponseStatus { code, reason },
        }
    } else {
        let mut p = start_line.split_whitespace();
        let method = p
            .next()
            .ok_or_else(|| SipError::InvalidPacket("request without method".into()))?;
        let uri = p
            .next()
            .ok_or_else(|| SipError::InvalidPacket("request without uri".into()))?
            .to_string();
        let version = p.next().unwrap_or("SIP/2.0").to_string();
        SipPacketKind::Request {
            method: SipMethod::parse(method),
            uri,
            version,
        }
    };

    let mut headers: Vec<SipHeader> = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
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
        headers.push(SipHeader {
            name: canonical_header_name(name.trim()).to_string(),
            value: value.trim().to_string(),
        });
    }

    let content_length = content_length_from_headers(&headers)?;
    let available_body = bytes.len().saturating_sub(body_start);
    if available_body < content_length {
        return Err(SipError::InvalidPacket(format!(
            "Content-Length is {content_length}, but only {available_body} body bytes are available"
        )));
    }

    let packet_len = body_start + content_length;
    let body = bytes.slice(body_start..packet_len);
    let raw = bytes.slice(..packet_len);

    Ok(SipMessage {
        kind,
        headers,
        body,
        raw,
    })
}

fn find_header_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((idx, idx + 4));
    }
    if let Some(idx) = bytes.windows(2).position(|w| w == b"\n\n") {
        return Some((idx, idx + 2));
    }
    None
}

fn content_length_from_headers(headers: &[SipHeader]) -> Result<usize> {
    let Some(value) = headers
        .iter()
        .rev()
        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
        .map(|h| h.value.trim())
    else {
        return Ok(0);
    };

    value.parse::<usize>().map_err(|e| SipError::InvalidHeader {
        name: "Content-Length",
        reason: e.to_string(),
    })
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
