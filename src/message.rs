use std::collections::HashMap;
use std::ptr;

use gmv_pjsip_sys as sys;

use crate::error::{PjError, Result};
use crate::runtime::PjRuntime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipKind {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

#[derive(Debug, Clone)]
pub struct SipMessage {
    pub raw: Vec<u8>,
    pub start_line: String,
    pub kind: SipKind,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
}

impl SipMessage {
    /// Parse and validate SIP bytes through PJSIP, then copy the data into a safe owned Rust view.
    ///
    /// The PJSIP `pjsip_msg*` is pool-backed and released before returning. Business code should use
    /// this owned view instead of keeping raw C pointers.
    pub fn parse(runtime: &PjRuntime, raw: &[u8]) -> Result<Self> {
        let pool = runtime.create_pool("gmv_sip_parse", 8192, 8192)?;

        // PJSIP parser mutates the buffer and expects writable NUL-terminated memory.
        let mut buf = Vec::with_capacity(raw.len() + 1);
        buf.extend_from_slice(raw);
        buf.push(0);

        let msg = unsafe {
            sys::pjsip_parse_msg(
                pool.as_ptr(),
                buf.as_mut_ptr() as *mut i8,
                raw.len() as sys::pj_size_t,
                ptr::null_mut(),
            )
        };

        if msg.is_null() {
            return Err(PjError::InvalidSip("pjsip_parse_msg failed".into()));
        }

        parse_owned(raw)
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn header_values(&self, name: &str) -> &[String] {
        static EMPTY: Vec<String> = Vec::new();
        self.headers
            .get(&normalize_header_name(name))
            .unwrap_or(&EMPTY)
            .as_slice()
    }

    pub fn header_first(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&normalize_header_name(name))
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    pub fn method(&self) -> Option<&str> {
        match &self.kind {
            SipKind::Request { method, .. } => Some(method.as_str()),
            _ => None,
        }
    }

    pub fn request_uri(&self) -> Option<&str> {
        match &self.kind {
            SipKind::Request { uri, .. } => Some(uri.as_str()),
            _ => None,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match self.kind {
            SipKind::Response { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match &self.kind {
            SipKind::Response { reason, .. } => Some(reason.as_str()),
            _ => None,
        }
    }

    pub fn via(&self) -> Option<&str> {
        self.header_first("Via")
    }

    pub fn from(&self) -> Option<&str> {
        self.header_first("From")
    }

    pub fn to(&self) -> Option<&str> {
        self.header_first("To")
    }

    pub fn call_id(&self) -> Option<&str> {
        self.header_first("Call-ID")
    }

    pub fn cseq(&self) -> Option<&str> {
        self.header_first("CSeq")
    }

    pub fn contact(&self) -> Option<&str> {
        self.header_first("Contact")
    }

    pub fn cseq_num_method(&self) -> Option<(u32, String)> {
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
}

pub fn parse_owned(raw: &[u8]) -> Result<SipMessage> {
    let text = std::str::from_utf8(raw)
        .map_err(|e| PjError::InvalidSip(format!("SIP is not UTF-8: {e}")))?;

    let (head, body) = split_head_body(text);
    let mut logical_lines = unfold_header_lines(head);
    if logical_lines.is_empty() {
        return Err(PjError::InvalidSip("empty SIP head".into()));
    }

    let start_line = logical_lines.remove(0).trim().to_string();
    let kind = parse_start_line(&start_line)?;
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();

    for line in logical_lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = normalize_header_name(k.trim());
            headers.entry(key).or_default().push(v.trim().to_string());
        }
    }

    Ok(SipMessage {
        raw: raw.to_vec(),
        start_line,
        kind,
        headers,
        body: body.as_bytes().to_vec(),
    })
}

fn parse_start_line(line: &str) -> Result<SipKind> {
    if line.starts_with("SIP/2.0") {
        let mut parts = line.splitn(3, ' ');
        let _version = parts.next();
        let code = parts
            .next()
            .ok_or_else(|| PjError::InvalidSip("missing response status".into()))?
            .parse::<u16>()
            .map_err(|e| PjError::InvalidSip(format!("invalid response code: {e}")))?;
        let reason = parts.next().unwrap_or("").trim().to_string();
        return Ok(SipKind::Response { code, reason });
    }

    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| PjError::InvalidSip("missing request method".into()))?
        .to_ascii_uppercase();
    let uri = parts
        .next()
        .ok_or_else(|| PjError::InvalidSip("missing request uri".into()))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| PjError::InvalidSip("missing request SIP version".into()))?;
    if version != "SIP/2.0" {
        return Err(PjError::InvalidSip(format!("unsupported SIP version: {version}")));
    }
    Ok(SipKind::Request { method, uri })
}

fn split_head_body(text: &str) -> (&str, &str) {
    if let Some(pos) = text.find("\r\n\r\n") {
        (&text[..pos], &text[pos + 4..])
    } else if let Some(pos) = text.find("\n\n") {
        (&text[..pos], &text[pos + 2..])
    } else {
        (text, "")
    }
}

fn unfold_header_lines(head: &str) -> Vec<String> {
    let mut out = Vec::<String>::new();
    for raw_line in head.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            out.push(line.to_string());
        }
    }
    out
}

pub fn normalize_header_name(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "v" => "via".into(),
        "f" => "from".into(),
        "t" => "to".into(),
        "i" => "call-id".into(),
        "m" => "contact".into(),
        "l" => "content-length".into(),
        "c" => "content-type".into(),
        other => other.into(),
    }
}

pub fn extract_tag(header_value: &str) -> Option<&str> {
    header_value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("tag="))
        .map(|v| v.trim())
}

pub fn extract_uri_from_name_addr(value: &str) -> Option<&str> {
    let value = value.trim();
    if let Some(start) = value.find('<') {
        let end = value[start + 1..].find('>')?;
        Some(&value[start + 1..start + 1 + end])
    } else if value.starts_with("sip:") || value.starts_with("sips:") {
        Some(value)
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
