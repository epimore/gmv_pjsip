//! Rust-owned SIP message view.
//!
//! `SipMessageView::parse()` first validates raw bytes through PJSIP, then
//! keeps a Rust-owned normalized view for GB28181 business routing. This avoids
//! leaking PJSIP pool-bound raw pointers into `session`.

use crate::error::{PjError, Result};
use crate::runtime::PjRuntime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipPacketKind {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct SipMessageView {
    pub raw: Vec<u8>,
    pub kind: SipPacketKind,
    pub start_line: String,

    pub method: Option<String>,
    pub request_uri: Option<String>,

    pub status_code: Option<u16>,
    pub reason: Option<String>,

    /// Header order is preserved. This matters for repeated Via/Route headers.
    pub headers: Vec<SipHeader>,
    pub body: Vec<u8>,
}

impl SipMessageView {
    pub fn parse(runtime: &PjRuntime, raw: &[u8]) -> Result<Self> {
        runtime.validate_sip_packet(raw)?;
        Self::parse_after_pjsip_validation(raw)
    }

    /// Useful for unit tests where pjproject is not linked.
    pub fn parse_without_pjsip_validation(raw: &[u8]) -> Result<Self> {
        Self::parse_after_pjsip_validation(raw)
    }

    fn parse_after_pjsip_validation(raw: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(raw)?;
        let (head, body) = split_head_body(text);

        let mut lines = head.lines();
        let start_line = lines
            .next()
            .ok_or_else(|| PjError::Parse("missing SIP start line".to_string()))?
            .trim_end_matches('\r')
            .trim()
            .to_string();

        if start_line.is_empty() {
            return Err(PjError::Parse("empty SIP start line".to_string()));
        }

        let mut headers = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_value = String::new();

        for raw_line in lines {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            // Header continuation line.
            if line.starts_with(' ') || line.starts_with('\t') {
                if current_name.is_some() {
                    current_value.push(' ');
                    current_value.push_str(line.trim());
                }
                continue;
            }

            if let Some(name) = current_name.take() {
                headers.push(SipHeader {
                    name,
                    value: current_value.trim().to_string(),
                });
                current_value.clear();
            }

            let Some((name, value)) = line.split_once(':') else {
                return Err(PjError::Parse(format!("invalid SIP header line: {line}")));
            };

            current_name = Some(canonical_header_name(name.trim()));
            current_value.push_str(value.trim());
        }

        if let Some(name) = current_name.take() {
            headers.push(SipHeader {
                name,
                value: current_value.trim().to_string(),
            });
        }

        if start_line.starts_with("SIP/2.0") {
            let mut parts = start_line.splitn(3, ' ');
            let _version = parts.next();
            let status_code = parts
                .next()
                .ok_or_else(|| PjError::Parse("missing SIP status code".to_string()))?
                .parse::<u16>()
                .map_err(|_| PjError::Parse("invalid SIP status code".to_string()))?;
            let reason = parts.next().unwrap_or("").to_string();

            Ok(Self {
                raw: raw.to_vec(),
                kind: SipPacketKind::Response,
                start_line,
                method: None,
                request_uri: None,
                status_code: Some(status_code),
                reason: Some(reason),
                headers,
                body: body.as_bytes().to_vec(),
            })
        } else {
            let mut parts = start_line.split_whitespace();
            let method = parts
                .next()
                .ok_or_else(|| PjError::Parse("missing request method".to_string()))?
                .to_ascii_uppercase();
            let request_uri = parts
                .next()
                .ok_or_else(|| PjError::Parse("missing request uri".to_string()))?
                .to_string();
            let version = parts
                .next()
                .ok_or_else(|| PjError::Parse("missing SIP version".to_string()))?;

            if version != "SIP/2.0" {
                return Err(PjError::Parse(format!("unsupported SIP version: {version}")));
            }

            Ok(Self {
                raw: raw.to_vec(),
                kind: SipPacketKind::Request,
                start_line,
                method: Some(method),
                request_uri: Some(request_uri),
                status_code: None,
                reason: None,
                headers,
                body: body.as_bytes().to_vec(),
            })
        }
    }

    pub fn is_request(&self) -> bool {
        self.kind == SipPacketKind::Request
    }

    pub fn is_response(&self) -> bool {
        self.kind == SipPacketKind::Response
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let name = canonical_header_name(name);
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(&name))
            .map(|h| h.value.as_str())
    }

    pub fn headers_all<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> + 'a {
        let name = canonical_header_name(name);
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(&name))
            .map(|h| h.value.as_str())
    }

    pub fn via_headers(&self) -> Vec<&str> {
        self.headers_all("Via").collect()
    }

    pub fn call_id(&self) -> Option<&str> {
        self.header("Call-ID")
    }

    pub fn cseq(&self) -> Option<&str> {
        self.header("CSeq")
    }

    pub fn from(&self) -> Option<&str> {
        self.header("From")
    }

    pub fn to(&self) -> Option<&str> {
        self.header("To")
    }

    pub fn contact(&self) -> Option<&str> {
        self.header("Contact")
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("Content-Type")
    }

    pub fn cseq_parts(&self) -> Option<(u32, String)> {
        let cseq = self.cseq()?;
        let mut parts = cseq.split_whitespace();
        let num = parts.next()?.parse::<u32>().ok()?;
        let method = parts.next()?.to_ascii_uppercase();
        Some((num, method))
    }

    pub fn from_tag(&self) -> Option<String> {
        self.from().and_then(extract_tag).map(ToOwned::to_owned)
    }

    pub fn to_tag(&self) -> Option<String> {
        self.to().and_then(extract_tag).map(ToOwned::to_owned)
    }

    pub fn branch(&self) -> Option<String> {
        self.header("Via")
            .and_then(extract_branch)
            .map(ToOwned::to_owned)
    }

    pub fn remote_contact_uri(&self) -> Option<String> {
        self.contact().and_then(extract_uri).map(ToOwned::to_owned)
    }
}

pub fn split_head_body(text: &str) -> (&str, &str) {
    if let Some(pos) = text.find("\r\n\r\n") {
        (&text[..pos], &text[pos + 4..])
    } else if let Some(pos) = text.find("\n\n") {
        (&text[..pos], &text[pos + 2..])
    } else {
        (text, "")
    }
}

pub fn canonical_header_name(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "v" => "Via".to_string(),
        "f" => "From".to_string(),
        "t" => "To".to_string(),
        "i" => "Call-ID".to_string(),
        "m" => "Contact".to_string(),
        "l" => "Content-Length".to_string(),
        "c" => "Content-Type".to_string(),
        other => other
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join("-"),
    }
}

pub fn extract_tag(header_value: &str) -> Option<&str> {
    header_value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("tag="))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
}

pub fn extract_branch(via_value: &str) -> Option<&str> {
    via_value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("branch="))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
}

pub fn extract_uri(value: &str) -> Option<&str> {
    let value = value.trim();

    if let Some(start) = value.find('<') {
        let end = value[start + 1..].find('>')?;
        Some(&value[start + 1..start + 1 + end])
    } else if value.starts_with("sip:") || value.starts_with("sips:") {
        Some(value.split(';').next().unwrap_or(value).trim())
    } else {
        None
    }
}

pub fn ensure_name_addr(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('<') {
        value.to_string()
    } else {
        format!("<{value}>")
    }
}
