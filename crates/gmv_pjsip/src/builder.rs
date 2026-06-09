//! SIP message builders.
//!
//! These builders centralize SIP serialization and Content-Length calculation.
//! In the next step they can be internally rewritten to call PJSIP message
//! constructors/printers without changing the public GB28181-facing API.

use crate::dialog::InviteDialog;
use crate::error::{PjError, Result};
use crate::message::{ensure_name_addr, extract_uri, SipMessageView};
use crate::transport::{SipAssociation, SipTxPacket};

#[derive(Debug, Clone)]
pub struct ResponseOptions<'a> {
    pub status_code: u16,
    pub reason: &'a str,
    pub user_agent: &'a str,
    pub body: Option<&'a str>,
    pub content_type: Option<&'a str>,
    /// Add a To tag when generating final dialog-forming responses.
    pub to_tag: Option<&'a str>,
    pub extra_headers: Vec<(&'a str, &'a str)>,
}

impl<'a> ResponseOptions<'a> {
    pub fn new(status_code: u16, reason: &'a str, user_agent: &'a str) -> Self {
        Self {
            status_code,
            reason,
            user_agent,
            body: None,
            content_type: None,
            to_tag: None,
            extra_headers: Vec::new(),
        }
    }
}

pub fn build_response(req: &SipMessageView, opt: ResponseOptions<'_>) -> Result<Vec<u8>> {
    if !req.is_request() {
        return Err(PjError::Protocol(
            "cannot build response for SIP response".to_string(),
        ));
    }

    let body = opt.body.unwrap_or("");
    let mut out = String::with_capacity(512 + body.len());

    out.push_str(&format!("SIP/2.0 {} {}\r\n", opt.status_code, opt.reason));

    for via in req.via_headers() {
        out.push_str("Via: ");
        out.push_str(via);
        out.push_str("\r\n");
    }

    if let Some(from) = req.from() {
        out.push_str("From: ");
        out.push_str(from);
        out.push_str("\r\n");
    }

    if let Some(to) = req.to() {
        out.push_str("To: ");
        out.push_str(to);
        if let Some(tag) = opt.to_tag {
            if !to.to_ascii_lowercase().contains(";tag=") {
                out.push_str(";tag=");
                out.push_str(tag);
            }
        }
        out.push_str("\r\n");
    }

    if let Some(call_id) = req.call_id() {
        out.push_str("Call-ID: ");
        out.push_str(call_id);
        out.push_str("\r\n");
    }

    if let Some(cseq) = req.cseq() {
        out.push_str("CSeq: ");
        out.push_str(cseq);
        out.push_str("\r\n");
    }

    out.push_str("User-Agent: ");
    out.push_str(opt.user_agent);
    out.push_str("\r\n");

    for (name, value) in opt.extra_headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }

    if let Some(content_type) = opt.content_type {
        out.push_str("Content-Type: ");
        out.push_str(content_type);
        out.push_str("\r\n");
    }

    out.push_str(&format!("Content-Length: {}\r\n", body.as_bytes().len()));
    out.push_str("\r\n");
    out.push_str(body);

    Ok(out.into_bytes())
}

pub fn build_200_ok(req: &SipMessageView, user_agent: &str) -> Result<Vec<u8>> {
    build_response(req, ResponseOptions::new(200, "OK", user_agent))
}

pub fn build_400_bad_request(req: &SipMessageView, user_agent: &str) -> Result<Vec<u8>> {
    build_response(req, ResponseOptions::new(400, "Bad Request", user_agent))
}

pub fn build_481(req: &SipMessageView, user_agent: &str) -> Result<Vec<u8>> {
    build_response(
        req,
        ResponseOptions::new(481, "Call/Transaction Does Not Exist", user_agent),
    )
}

#[derive(Debug, Clone)]
pub struct BuildRequestOptions<'a> {
    pub method: &'a str,
    pub request_uri: &'a str,
    pub via_sent_by: &'a str,
    pub branch: &'a str,
    pub from: &'a str,
    pub from_tag: &'a str,
    pub to: &'a str,
    pub to_tag: Option<&'a str>,
    pub call_id: &'a str,
    pub cseq: u32,
    pub contact: Option<&'a str>,
    pub user_agent: &'a str,
    pub body: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub extra_headers: Vec<(&'a str, &'a str)>,
}

pub fn build_request(opt: BuildRequestOptions<'_>) -> Result<Vec<u8>> {
    let body = opt.body.unwrap_or("");
    let mut out = String::with_capacity(512 + body.len());

    out.push_str(&format!("{} {} SIP/2.0\r\n", opt.method, opt.request_uri));
    out.push_str(&format!(
        "Via: SIP/2.0/UDP {};rport;branch={}\r\n",
        opt.via_sent_by, opt.branch
    ));
    out.push_str(&format!(
        "From: {};tag={}\r\n",
        ensure_name_addr(opt.from),
        opt.from_tag
    ));
    out.push_str("To: ");
    out.push_str(&ensure_name_addr(opt.to));
    if let Some(tag) = opt.to_tag {
        out.push_str(";tag=");
        out.push_str(tag);
    }
    out.push_str("\r\n");
    out.push_str(&format!("Call-ID: {}\r\n", opt.call_id));
    out.push_str(&format!("CSeq: {} {}\r\n", opt.cseq, opt.method));

    if let Some(contact) = opt.contact {
        out.push_str("Contact: ");
        out.push_str(&ensure_name_addr(contact));
        out.push_str("\r\n");
    }

    out.push_str("Max-Forwards: 70\r\n");
    out.push_str("User-Agent: ");
    out.push_str(opt.user_agent);
    out.push_str("\r\n");

    for (name, value) in opt.extra_headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }

    if let Some(content_type) = opt.content_type {
        out.push_str("Content-Type: ");
        out.push_str(content_type);
        out.push_str("\r\n");
    }

    out.push_str(&format!("Content-Length: {}\r\n", body.as_bytes().len()));
    out.push_str("\r\n");
    out.push_str(body);

    Ok(out.into_bytes())
}

pub fn build_ack_for_invite_2xx(dialog: &InviteDialog, user_agent: &str) -> Result<Vec<u8>> {
    let remote_tag = dialog.remote_tag.as_deref().ok_or_else(|| {
        PjError::Dialog("cannot build ACK before remote tag is known".to_string())
    })?;

    let request_uri = dialog
        .remote_contact
        .as_deref()
        .and_then(extract_uri)
        .unwrap_or(dialog.invite_request_uri.as_str());

    build_request(BuildRequestOptions {
        method: "ACK",
        request_uri,
        via_sent_by: &dialog.local_sent_by,
        branch: &new_branch(),
        from: &dialog.local_uri,
        from_tag: &dialog.local_tag,
        to: &dialog.remote_uri,
        to_tag: Some(remote_tag),
        call_id: &dialog.call_id,
        cseq: dialog.invite_cseq,
        contact: Some(&dialog.local_contact),
        user_agent,
        body: None,
        content_type: None,
        extra_headers: Vec::new(),
    })
}

pub fn build_bye(dialog: &InviteDialog, user_agent: &str) -> Result<Vec<u8>> {
    let remote_tag = dialog.remote_tag.as_deref().ok_or_else(|| {
        PjError::Dialog("cannot build BYE before remote tag is known".to_string())
    })?;

    let request_uri = dialog
        .remote_contact
        .as_deref()
        .and_then(extract_uri)
        .unwrap_or(dialog.invite_request_uri.as_str());

    build_request(BuildRequestOptions {
        method: "BYE",
        request_uri,
        via_sent_by: &dialog.local_sent_by,
        branch: &new_branch(),
        from: &dialog.local_uri,
        from_tag: &dialog.local_tag,
        to: &dialog.remote_uri,
        to_tag: Some(remote_tag),
        call_id: &dialog.call_id,
        cseq: dialog.next_local_cseq,
        contact: Some(&dialog.local_contact),
        user_agent,
        body: None,
        content_type: None,
        extra_headers: Vec::new(),
    })
}

pub fn tx_packet(association: SipAssociation, bytes: Vec<u8>) -> SipTxPacket {
    SipTxPacket { association, bytes }
}

pub fn new_branch() -> String {
    format!("z9hG4bK{}", token())
}

pub fn token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos)
}
