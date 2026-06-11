use std::{fmt, str::FromStr};

use bytes::Bytes;

use crate::error::{Result, SipError};
use crate::types::CSeq;

/// Standard SIP methods recognized by the library.
///
/// The enum intentionally keeps `Other` so vendor/private extension methods can
/// be parsed and replied to without failing the packet path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Ack,
    Bye,
    Cancel,
    Info,
    Invite,
    Message,
    Notify,
    Options,
    Prack,
    Publish,
    Refer,
    Register,
    Subscribe,
    Update,
    Other(String),
}

impl SipMethod {
    /// Methods exposed in Allow responses. Keep this list sorted by the SIP
    /// token used on the wire so downstream logs/configs remain stable.
    pub const ALLOW_METHODS: &'static [&'static str] = &[
        "ACK",
        "BYE",
        "CANCEL",
        "INFO",
        "INVITE",
        "MESSAGE",
        "NOTIFY",
        "OPTIONS",
        "PRACK",
        "PUBLISH",
        "REFER",
        "REGISTER",
        "SUBSCRIBE",
        "UPDATE",
    ];

    pub const ALLOW_HEADER_VALUE: &'static str =
        "ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE";

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "ACK" => Self::Ack,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "INFO" => Self::Info,
            "INVITE" => Self::Invite,
            "MESSAGE" => Self::Message,
            "NOTIFY" => Self::Notify,
            "OPTIONS" => Self::Options,
            "PRACK" => Self::Prack,
            "PUBLISH" => Self::Publish,
            "REFER" => Self::Refer,
            "REGISTER" => Self::Register,
            "SUBSCRIBE" => Self::Subscribe,
            "UPDATE" => Self::Update,
            _ => Self::Other(s.trim().to_ascii_uppercase()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Info => "INFO",
            Self::Invite => "INVITE",
            Self::Message => "MESSAGE",
            Self::Notify => "NOTIFY",
            Self::Options => "OPTIONS",
            Self::Prack => "PRACK",
            Self::Publish => "PUBLISH",
            Self::Refer => "REFER",
            Self::Register => "REGISTER",
            Self::Subscribe => "SUBSCRIBE",
            Self::Update => "UPDATE",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn allow_header_value() -> &'static str {
        Self::ALLOW_HEADER_VALUE
    }

    pub fn is_standard(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// ACK is a special request: it has no normal server transaction for 2xx.
    pub fn is_ack(&self) -> bool {
        matches!(self, Self::Ack)
    }

    /// Methods that normally operate inside an existing dialog.
    pub fn is_dialog_method(&self) -> bool {
        matches!(
            self,
            Self::Ack | Self::Bye | Self::Info | Self::Notify | Self::Prack | Self::Refer | Self::Update
        )
    }

    /// Methods this GB28181-oriented library actively implements as first-class
    /// operations today. Other standard methods are still parsed and answered
    /// with protocol-safe generic responses.
    pub fn is_first_class_supported(&self) -> bool {
        matches!(
            self,
            Self::Ack
                | Self::Bye
                | Self::Cancel
                | Self::Info
                | Self::Invite
                | Self::Message
                | Self::Notify
                | Self::Options
                | Self::Register
                | Self::Update
        )
    }
}

impl fmt::Display for SipMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SipMethod {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl From<&str> for SipMethod {
    fn from(value: &str) -> Self {
        Self::parse(value)
    }
}

#[derive(Clone, Debug)]
pub struct SipResponseStatus {
    pub code: u16,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub enum SipPacketKind {
    Request { method: SipMethod, uri: String, version: String },
    Response { version: String, status: SipResponseStatus },
}

#[derive(Clone, Debug)]
pub struct SipHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct SipMessage {
    pub kind: SipPacketKind,
    pub headers: Vec<SipHeader>,
    pub body: Bytes,
    pub raw: Bytes,
}

pub trait HeaderMapExt {
    fn header(&self, name: &str) -> Option<&str>;
    fn headers(&self, name: &str) -> Vec<&str>;
    fn required_header(&self, name: &'static str) -> Result<&str>;
}

impl HeaderMapExt for SipMessage {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    fn headers(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }

    fn required_header(&self, name: &'static str) -> Result<&str> {
        self.header(name).ok_or(SipError::MissingHeader(name))
    }
}

impl SipMessage {
    pub fn method(&self) -> Option<&SipMethod> {
        match &self.kind {
            SipPacketKind::Request { method, .. } => Some(method),
            _ => None,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match &self.kind {
            SipPacketKind::Response { status, .. } => Some(status.code),
            _ => None,
        }
    }

    pub fn request_uri(&self) -> Option<&str> {
        match &self.kind {
            SipPacketKind::Request { uri, .. } => Some(uri),
            _ => None,
        }
    }

    pub fn call_id(&self) -> Result<String> {
        Ok(self.required_header("Call-ID")?.trim().to_string())
    }

    pub fn cseq(&self) -> Result<CSeq> {
        parse_cseq(self.required_header("CSeq")?)
    }

    pub fn from_tag(&self) -> Option<String> {
        extract_tag(self.header("From").or_else(|| self.header("f"))?)
    }

    pub fn to_tag(&self) -> Option<String> {
        extract_tag(self.header("To").or_else(|| self.header("t"))?)
    }

    pub fn via_branch(&self) -> Option<String> {
        self.header("Via").or_else(|| self.header("v")).and_then(extract_branch)
    }

    pub fn contact(&self) -> Option<String> {
        self.header("Contact").map(|s| s.trim().to_string())
    }
}

pub fn parse_cseq(value: &str) -> Result<CSeq> {
    let mut parts = value.split_whitespace();
    let number = parts
        .next()
        .ok_or(SipError::InvalidHeader { name: "CSeq", reason: "missing number".into() })?
        .parse::<u32>()
        .map_err(|e| SipError::InvalidHeader { name: "CSeq", reason: e.to_string() })?;
    let method = parts
        .next()
        .ok_or(SipError::InvalidHeader { name: "CSeq", reason: "missing method".into() })?
        .to_ascii_uppercase();
    Ok(CSeq { number, method })
}

pub fn extract_tag(value: &str) -> Option<String> {
    extract_param(value, "tag")
}

pub fn extract_branch(value: &str) -> Option<String> {
    extract_param(value, "branch")
}

pub fn extract_param(value: &str, key: &str) -> Option<String> {
    for part in value.split(';').skip(1) {
        let mut kv = part.trim().splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next().unwrap_or("").trim().trim_matches('"');
        if k.eq_ignore_ascii_case(key) {
            return Some(v.to_string());
        }
    }
    None
}

pub fn ensure_tag(value: &str, tag: &str) -> String {
    if extract_tag(value).is_some() {
        value.to_string()
    } else {
        format!("{};tag={}", value.trim(), tag)
    }
}

pub fn extract_user_from_uri_like(value: &str) -> Option<String> {
    let s = value.trim();
    let start = s.find("sip:").map(|i| i + 4)?;
    let rest = &s[start..];
    let end = rest.find(['@', '>', ';', ':']).unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(rest[..end].to_string())
    }
}

pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        183 => "Session Progress",
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        481 => "Call/Transaction Does Not Exist",
        486 => "Busy Here",
        487 => "Request Terminated",
        489 => "Bad Event",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        603 => "Decline",
        _ => "Unknown",
    }
}
