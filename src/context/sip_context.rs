use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::auth::{
    build_www_authenticate, verify_digest_response, AuthConfig, AuthDecision, AuthRequirement,
    NonceStore, VerifyDigestRequest,
};
use crate::builder::{
    build_request, build_response, new_branch, new_call_id, new_tag, via, ResponseOptions,
};
use crate::context::{
    expires_at, CallStore, DialogId, DialogState, DialogStore, InviteCall, InviteState,
    RegisterBinding, RegisterStore, SipDialog, TransactionStore,
};
use crate::CreateSubscribe;
use crate::endpoint::{
    AckEvent, ByeEvent, CancelEvent, CreateBye, CreateInfo, CreateInvite, CreateMessage,
    CreatePlaybackSeekInfo, CreatePlaybackSpeedInfo, CreatePresetQueryMessage,
    CreateSnapshotControlMessage, CreateTalkInvite, IncomingInviteEvent, InviteAcceptedEvent,
    MessageEvent, MessageKind, RegisterEvent, SipAction, SipEvent, StandardRequestEvent,
    StandardResponseEvent,
};
use crate::error::{Result, SipError};
use crate::gb28181::sdp::{build_talk_sdp, SdpInfo, TalkSdpOptions};
use crate::gb28181::xml;
use crate::message::{
    ensure_tag, extract_user_from_uri_like, HeaderMapExt, SipMessage, SipMethod, SipPacketKind,
};
use crate::parser::parse_sip_message;
use crate::transport::{SipPacketMeta, SipTransportProtocol};

#[derive(Clone, Debug)]
pub struct SipLocalConfig {
    pub platform_id: String,
    pub realm: String,
    pub domain: String,
    pub user_agent: String,
    pub public_host: String,
    pub listen_port: u16,
    pub default_expires: u32,
    pub transaction_ttl: Duration,
    pub auth: AuthConfig,
}

impl SipLocalConfig {
    pub fn local_uri(&self) -> String {
        format!("sip:{}@{}", self.platform_id, self.domain)
    }
    pub fn contact(&self, proto: SipTransportProtocol) -> String {
        crate::builder::contact(
            &self.platform_id,
            &self.public_host,
            self.listen_port,
            proto,
        )
    }
}

#[derive(Debug)]
pub struct SipContext {
    pub local: SipLocalConfig,
    pub transactions: TransactionStore,
    pub registers: RegisterStore,
    pub dialogs: DialogStore,
    pub calls: CallStore,
    nonces: NonceStore,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub expired_transactions: usize,
    pub expired_registers: usize,
    pub expired_calls: usize,
    pub expired_dialogs: usize,
    pub expired_nonces: usize,
}

impl SipContext {
    pub fn new(local: SipLocalConfig) -> Arc<Self> {
        let ttl = local.transaction_ttl;
        let nonce_ttl = local.auth.nonce_ttl;
        Arc::new(Self {
            local,
            transactions: TransactionStore::new(ttl),
            registers: RegisterStore::new(),
            dialogs: DialogStore::new(),
            calls: CallStore::new(),
            nonces: NonceStore::new(nonce_ttl),
        })
    }

    pub fn cleanup_expired(&self) -> CleanupReport {
        self.cleanup_expired_with(self.local.transaction_ttl)
    }

    pub fn cleanup_expired_with(&self, terminated_retain_for: Duration) -> CleanupReport {
        CleanupReport {
            expired_transactions: self.transactions.cleanup(),
            expired_registers: self.registers.cleanup(),
            expired_calls: self.calls.cleanup_terminated(terminated_retain_for),
            expired_dialogs: self.dialogs.cleanup_terminated(terminated_retain_for),
            expired_nonces: self.nonces.cleanup(),
        }
    }

    pub fn on_packet(&self, bytes: Bytes, meta: SipPacketMeta) -> Result<SipAction> {
        let msg = parse_sip_message(bytes)?;
        match &msg.kind {
            SipPacketKind::Request { method, .. } => {
                self.on_request(msg.clone(), method.clone(), meta)
            }
            SipPacketKind::Response { .. } => self.on_response(msg, meta),
        }
    }

    fn on_request(
        &self,
        msg: SipMessage,
        method: SipMethod,
        meta: SipPacketMeta,
    ) -> Result<SipAction> {
        let tx_key = TransactionStore::key_from_request(&msg, meta.remote_addr);
        if let Some(key) = tx_key.as_ref() {
            if let Some(resp) = self.transactions.duplicate_response(key) {
                return Ok(SipAction::Send(resp));
            }
            self.transactions.mark_seen(key.clone());
        }

        let action = if let Some(action) = self.validate_request_method_cseq(&msg, &method)? {
            action
        } else {
            match method {
                SipMethod::Register => self.handle_register(&msg, &meta),
                SipMethod::Message => self.handle_message(&msg, &meta),
                SipMethod::Invite => self.handle_incoming_invite(&msg, &meta),
                SipMethod::Info => self.simple_ok(&msg, None),
                SipMethod::Ack => self.handle_ack(&msg),
                SipMethod::Bye => self.handle_bye(&msg),
                SipMethod::Cancel => self.handle_cancel(&msg),
                SipMethod::Options => self.handle_options(&msg, &meta),
                SipMethod::Notify => {
                    self.handle_standard_in_dialog_request(&msg, &meta, SipMethod::Notify, true)
                }
                SipMethod::Update => {
                    self.handle_standard_in_dialog_request(&msg, &meta, SipMethod::Update, true)
                }
                SipMethod::Prack => {
                    self.handle_standard_in_dialog_request(&msg, &meta, SipMethod::Prack, true)
                }
                SipMethod::Publish | SipMethod::Refer | SipMethod::Subscribe => {
                    self.not_implemented(&msg, Some(method))
                }
                SipMethod::Other(_) => self.not_implemented(&msg, Some(method)),
            }?
        };

        if let (Some(key), Some(bytes)) = (tx_key.as_ref(), action.first_tx_bytes()) {
            self.transactions.store_response(key, bytes.clone());
        }

        Ok(action)
    }

    fn on_response(&self, msg: SipMessage, _meta: SipPacketMeta) -> Result<SipAction> {
        let cseq = msg.cseq()?;
        let code = msg.status_code().unwrap_or(0);
        let call_id = msg.call_id()?;

        if cseq.method.eq_ignore_ascii_case("INVITE") {
            if (100..200).contains(&code) {
                self.calls.update_state(&call_id, InviteState::Proceeding);
                return Ok(SipAction::Event(SipEvent::InviteProceeding {
                    call_id,
                    status: code,
                }));
            }
            if (200..300).contains(&code) {
                return self.handle_invite_2xx_response(msg);
            }
            let stream_id = self
                .calls
                .get(&call_id)
                .map(|call| call.stream_id)
                .unwrap_or_default();
            self.calls.update_state(&call_id, InviteState::Failed);
            return Ok(SipAction::Event(SipEvent::InviteFailed {
                call_id,
                stream_id,
                status: code,
            }));
        }

        if cseq.method.eq_ignore_ascii_case("INFO") {
            if (100..200).contains(&code) {
                return Ok(SipAction::Event(SipEvent::InfoProceeding {
                    call_id,
                    cseq: cseq.number,
                    status: code,
                }));
            }
            if (200..300).contains(&code) {
                return Ok(SipAction::Event(SipEvent::InfoAccepted {
                    call_id,
                    cseq: cseq.number,
                    status: code,
                }));
            }
            return Ok(SipAction::Event(SipEvent::InfoFailed {
                call_id,
                cseq: cseq.number,
                status: code,
            }));
        }

        if cseq.method.eq_ignore_ascii_case("BYE") && (200..300).contains(&code) {
            self.calls.update_state(&call_id, InviteState::Terminated);
            return Ok(SipAction::Event(SipEvent::ByeConfirmed(ByeEvent {
                call_id,
                stream_id: None,
                device_id: None,
            })));
        }

        Ok(SipAction::Event(SipEvent::StandardResponse(
            StandardResponseEvent {
                method: SipMethod::parse(&cseq.method),
                call_id,
                cseq: cseq.number,
                status: code,
                contact: msg.contact(),
                record_routes: msg
                    .headers("Record-Route")
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect(),
                from_header: msg
                    .header("From")
                    .or_else(|| msg.header("f"))
                    .map(ToOwned::to_owned),
                to_header: msg
                    .header("To")
                    .or_else(|| msg.header("t"))
                    .map(ToOwned::to_owned),
                to_tag: msg.to_tag(),
                expires: parse_expires(&msg),
            },
        )))
    }

    fn validate_request_method_cseq(
        &self,
        msg: &SipMessage,
        method: &SipMethod,
    ) -> Result<Option<SipAction>> {
        let cseq = match msg.cseq() {
            Ok(cseq) => cseq,
            Err(_) => {
                let resp = build_response(
                    msg,
                    ResponseOptions {
                        status_code: 400,
                        reason: Some("Bad CSeq".into()),
                        server: Some(self.local.user_agent.clone()),
                        extra_headers: self.standard_capability_headers(),
                        ..Default::default()
                    },
                );
                return Ok(Some(SipAction::Send(resp)));
            }
        };

        if !cseq.method.eq_ignore_ascii_case(method.as_str()) {
            let resp = build_response(
                msg,
                ResponseOptions {
                    status_code: 400,
                    reason: Some("CSeq Method Mismatch".into()),
                    server: Some(self.local.user_agent.clone()),
                    extra_headers: vec![
                        ("Allow".into(), SipMethod::allow_header_value().into()),
                        (
                            "Warning".into(),
                            format!(
                                "CSeq method {} does not match request method {}",
                                cseq.method, method
                            ),
                        ),
                    ],
                    ..Default::default()
                },
            );
            return Ok(Some(SipAction::Send(resp)));
        }

        Ok(None)
    }

    fn handle_register(&self, msg: &SipMessage, meta: &SipPacketMeta) -> Result<SipAction> {
        let auth = self.authenticate_request(msg, "REGISTER")?;
        match &auth {
            AuthDecision::Challenge { header_value, .. } => {
                let resp = build_response(
                    msg,
                    ResponseOptions {
                        status_code: 401,
                        server: Some(self.local.user_agent.clone()),
                        to_tag: Some(new_tag()),
                        extra_headers: vec![("WWW-Authenticate".into(), header_value.clone())],
                        ..Default::default()
                    },
                );
                return Ok(SipAction::Send(resp));
            }
            AuthDecision::Forbidden(reason) => {
                let resp = build_response(
                    msg,
                    ResponseOptions {
                        status_code: 403,
                        reason: Some("Forbidden".into()),
                        server: Some(self.local.user_agent.clone()),
                        to_tag: Some(new_tag()),
                        extra_headers: vec![("Warning".into(), reason.clone())],
                        ..Default::default()
                    },
                );
                return Ok(SipAction::Send(resp));
            }
            _ => {}
        }

        let device_id = extract_user_from_uri_like(msg.header("From").unwrap_or_default())
            .or_else(|| extract_user_from_uri_like(msg.header("Contact").unwrap_or_default()))
            .unwrap_or_else(|| "unknown".into());
        let call_id = msg.call_id()?;
        let cseq = msg.cseq()?;
        let expires = parse_expires(msg).unwrap_or(self.local.default_expires);
        let authorized = match &auth {
            AuthDecision::Authorized { .. } | AuthDecision::Disabled => true,
            _ => false,
        };
        let username = auth_username(&auth);

        if expires == 0 {
            self.registers.remove(&device_id);
        } else {
            self.registers.upsert(RegisterBinding {
                device_id: device_id.clone(),
                contact: msg.contact(),
                local_addr: meta.local_addr,
                remote_addr: meta.remote_addr,
                protocol: meta.protocol,
                call_id: call_id.clone(),
                cseq: cseq.number,
                expires,
                expires_at: expires_at(expires),
                user_agent: msg.header("User-Agent").map(ToOwned::to_owned),
            });
        }

        let event = SipEvent::Register(RegisterEvent {
            device_id,
            contact: msg.contact(),
            support_lr: msg.contact().as_deref().is_some_and(contact_supports_lr),
            expires,
            call_id,
            cseq: cseq.number,
            authorized,
            username,
            association: meta.association(),
            user_agent: msg.header("User-Agent").map(ToOwned::to_owned),
            gb_version: msg.header("X-GB-Ver").map(ToOwned::to_owned),
        });
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                to_tag: Some(new_tag()),
                contact: msg.contact(),
                extra_headers: vec![("Expires".into(), expires.to_string())],
                ..Default::default()
            },
        );
        Ok(SipAction::SendAndEvent { bytes: resp, event })
    }

    fn handle_message(&self, msg: &SipMessage, meta: &SipPacketMeta) -> Result<SipAction> {
        let body_text = String::from_utf8_lossy(&msg.body);
        let cmd_type = xml::cmd_type_lossy(&body_text);
        let event = SipEvent::Message(MessageEvent {
            kind: classify_message_body(&msg.body),
            device_id: xml::device_id_lossy(&body_text)
                .or_else(|| extract_user_from_uri_like(msg.header("From").unwrap_or_default())),
            call_id: msg.call_id().ok(),
            cseq: msg.cseq().ok().map(|c| c.number),
            association: meta.association(),
            content_type: msg.header("Content-Type").map(ToOwned::to_owned),
            cmd_type,
            snapshot_session_id: xml::session_id_lossy(&body_text),
            body: msg.body.clone(),
        });
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                ..Default::default()
            },
        );
        Ok(SipAction::SendAndEvent { bytes: resp, event })
    }

    fn handle_incoming_invite(&self, msg: &SipMessage, meta: &SipPacketMeta) -> Result<SipAction> {
        let call_id = msg.call_id()?;
        let remote_tag = msg.from_tag().unwrap_or_else(new_tag);
        let local_tag = msg.to_tag().unwrap_or_else(new_tag);
        let local_header = ensure_tag(msg.header("To").unwrap_or_default(), &local_tag);
        let remote_header = msg.header("From").unwrap_or_default().to_string();
        let dialog_id = DialogId {
            call_id: call_id.clone(),
            local_tag: local_tag.clone(),
            remote_tag,
        };
        self.dialogs.insert(SipDialog {
            id: dialog_id.clone(),
            local_uri: local_header,
            remote_uri: remote_header,
            local_contact: self.local.contact(meta.protocol),
            remote_target: msg
                .contact()
                .or_else(|| msg.request_uri().map(ToOwned::to_owned))
                .unwrap_or_default(),
            protocol: meta.protocol,
            local_cseq: 1,
            remote_cseq: msg.cseq()?.number,
            route_set: Vec::new(),
            state: DialogState::Early,
            created_at: Instant::now(),
            updated_at: Instant::now(),
        });
        let trying = build_response(
            msg,
            ResponseOptions {
                status_code: 100,
                server: Some(self.local.user_agent.clone()),
                to_tag: Some(local_tag),
                ..Default::default()
            },
        );
        let event = SipEvent::IncomingInvite(IncomingInviteEvent {
            call_id,
            dialog_id,
            association: meta.association(),
            remote_sdp: String::from_utf8_lossy(&msg.body).to_string(),
            from: msg.header("From").unwrap_or_default().to_string(),
            to: msg.header("To").unwrap_or_default().to_string(),
            subject: msg.header("Subject").map(ToOwned::to_owned),
        });
        Ok(SipAction::SendManyAndEvent {
            bytes: vec![trying],
            event,
        })
    }

    fn handle_ack(&self, msg: &SipMessage) -> Result<SipAction> {
        let call_id = msg.call_id()?;
        self.calls.update_state(&call_id, InviteState::Established);
        if let Some(dialog) = self.dialogs.get_by_call_id(&call_id) {
            self.dialogs
                .update_state(&dialog.id, DialogState::Confirmed);
        }
        Ok(SipAction::Event(SipEvent::Ack(AckEvent { call_id })))
    }

    fn handle_bye(&self, msg: &SipMessage) -> Result<SipAction> {
        let call_id = msg.call_id()?;
        let call = self.calls.get(&call_id);
        self.calls.update_state(&call_id, InviteState::Terminated);
        if let Some(dialog) = self.dialogs.get_by_call_id(&call_id) {
            self.dialogs
                .update_state(&dialog.id, DialogState::Terminated);
        }
        let event = SipEvent::Bye(ByeEvent {
            call_id: call_id.clone(),
            stream_id: call.as_ref().map(|c| c.stream_id.clone()),
            device_id: call.as_ref().map(|c| c.device_id.clone()),
        });
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                ..Default::default()
            },
        );
        Ok(SipAction::SendAndEvent { bytes: resp, event })
    }

    fn handle_cancel(&self, msg: &SipMessage) -> Result<SipAction> {
        let call_id = msg.call_id()?;
        self.calls.update_state(&call_id, InviteState::Terminated);
        let event = SipEvent::Cancel(CancelEvent { call_id });
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                ..Default::default()
            },
        );
        Ok(SipAction::SendAndEvent { bytes: resp, event })
    }

    fn handle_options(&self, msg: &SipMessage, meta: &SipPacketMeta) -> Result<SipAction> {
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                contact: Some(self.local.contact(meta.protocol)),
                extra_headers: self.standard_capability_headers(),
                ..Default::default()
            },
        );
        Ok(SipAction::Send(resp))
    }

    fn handle_standard_in_dialog_request(
        &self,
        msg: &SipMessage,
        meta: &SipPacketMeta,
        method: SipMethod,
        emit_event: bool,
    ) -> Result<SipAction> {
        let call_id = msg.call_id().ok();

        if method.is_dialog_method() {
            match call_id
                .as_deref()
                .and_then(|id| self.dialogs.get_by_call_id(id))
            {
                Some(dialog) => self
                    .dialogs
                    .update_state(&dialog.id, DialogState::Confirmed),
                None if matches!(method, SipMethod::Notify) => {}
                None => return self.dialog_missing(msg),
            }
        }

        let event = emit_event.then(|| self.standard_request_event(msg, meta, method));
        self.simple_ok_with_headers(msg, self.standard_capability_headers(), event)
    }

    fn standard_request_event(
        &self,
        msg: &SipMessage,
        meta: &SipPacketMeta,
        method: SipMethod,
    ) -> SipEvent {
        SipEvent::StandardRequest(StandardRequestEvent {
            method,
            call_id: msg.call_id().ok(),
            cseq: msg.cseq().ok().map(|c| c.number),
            association: meta.association(),
            content_type: msg.header("Content-Type").map(ToOwned::to_owned),
            event: msg.header("Event").map(ToOwned::to_owned),
            from_tag: msg.from_tag(),
            to_tag: msg.to_tag(),
            subscription_state: msg.header("Subscription-State").map(ToOwned::to_owned),
            body: msg.body.clone(),
        })
    }

    fn standard_capability_headers(&self) -> Vec<(String, String)> {
        vec![
            ("Allow".into(), SipMethod::allow_header_value().into()),
            (
                "Accept".into(),
                "application/sdp, Application/MANSCDP+xml, Application/MANSRTSP".into(),
            ),
        ]
    }

    fn not_implemented(&self, msg: &SipMessage, method: Option<SipMethod>) -> Result<SipAction> {
        let mut headers = self.standard_capability_headers();
        if let Some(method) = method {
            headers.push(("Unsupported-Method".into(), method.to_string()));
        }
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 501,
                server: Some(self.local.user_agent.clone()),
                extra_headers: headers,
                ..Default::default()
            },
        );
        Ok(SipAction::Send(resp))
    }

    fn dialog_missing(&self, msg: &SipMessage) -> Result<SipAction> {
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 481,
                server: Some(self.local.user_agent.clone()),
                extra_headers: self.standard_capability_headers(),
                ..Default::default()
            },
        );
        Ok(SipAction::Send(resp))
    }

    fn simple_ok_with_headers(
        &self,
        msg: &SipMessage,
        extra_headers: Vec<(String, String)>,
        event: Option<SipEvent>,
    ) -> Result<SipAction> {
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                extra_headers,
                ..Default::default()
            },
        );
        Ok(match event {
            Some(event) => SipAction::SendAndEvent { bytes: resp, event },
            None => SipAction::Send(resp),
        })
    }

    fn simple_ok(&self, msg: &SipMessage, event: Option<SipEvent>) -> Result<SipAction> {
        let resp = build_response(
            msg,
            ResponseOptions {
                status_code: 200,
                server: Some(self.local.user_agent.clone()),
                ..Default::default()
            },
        );
        Ok(match event {
            Some(event) => SipAction::SendAndEvent { bytes: resp, event },
            None => SipAction::Send(resp),
        })
    }

    fn authenticate_request(&self, msg: &SipMessage, method: &str) -> Result<AuthDecision> {
        if !self.local.auth.enabled {
            return Ok(AuthDecision::Disabled);
        }
        let request_username = extract_user_from_uri_like(msg.header("From").unwrap_or_default())
            .or_else(|| extract_user_from_uri_like(msg.header("Contact").unwrap_or_default()))
            .ok_or_else(|| SipError::AuthFailed("request username not found".into()))?;
        let Some(provider) = self.local.auth.provider.as_ref() else {
            return Ok(AuthDecision::Forbidden("no password provider".into()));
        };
        match provider.requirement_for(&request_username, &self.local.auth.realm) {
            AuthRequirement::Disabled => return Ok(AuthDecision::Disabled),
            AuthRequirement::Forbidden => {
                return Ok(AuthDecision::Forbidden(
                    "device is disabled or unknown".into(),
                ));
            }
            AuthRequirement::Required => {}
        }
        let Some(auth) = msg.header("Authorization") else {
            let nonce = self.nonces.issue();
            return Ok(AuthDecision::Challenge {
                header_value: build_www_authenticate(
                    &self.local.auth.realm,
                    &nonce,
                    self.local.auth.algorithm,
                ),
                nonce,
            });
        };
        let uri = msg.request_uri().unwrap_or_default();
        match verify_digest_response(VerifyDigestRequest {
            method,
            uri,
            authorization: auth,
            realm: &self.local.auth.realm,
            default_algorithm: self.local.auth.algorithm,
            nonce_store: &self.nonces,
            provider: provider.as_ref(),
        }) {
            Ok(username) if username == request_username => {
                Ok(AuthDecision::Authorized { username })
            }
            Ok(_) => Ok(AuthDecision::Forbidden(
                "authorization username does not match request identity".into(),
            )),
            Err(e) => Ok(AuthDecision::Forbidden(e.to_string())),
        }
    }

    pub fn create_invite(&self, req: CreateInvite) -> Result<Bytes> {
        let call_id = req
            .call_id
            .unwrap_or_else(|| new_call_id(&self.local.public_host));
        let branch = new_branch();
        let local_tag = new_tag();
        let cseq = req.cseq.unwrap_or(1);
        let subject = req.subject.unwrap_or_else(|| match req.ssrc {
            Some(ssrc) => format!("{}:{},{}:0", req.channel_id, ssrc, self.local.platform_id),
            None => format!("{}:0,{}:0", req.channel_id, self.local.platform_id),
        });
        let start_line = format!("INVITE {} SIP/2.0", req.target_uri);
        let headers = vec![
            (
                "Via".into(),
                via(
                    &self.local.public_host,
                    self.local.listen_port,
                    req.protocol,
                    &branch,
                ),
            ),
            ("Max-Forwards".into(), "70".into()),
            (
                "From".into(),
                format!("<{}>;tag={}", self.local.local_uri(), local_tag),
            ),
            ("To".into(), format!("<{}>", req.target_uri)),
            ("Call-ID".into(), call_id.clone()),
            ("CSeq".into(), format!("{} INVITE", cseq)),
            ("Contact".into(), self.local.contact(req.protocol)),
            ("Subject".into(), subject),
            ("User-Agent".into(), self.local.user_agent.clone()),
        ];
        let bytes = build_request(
            &start_line,
            &headers,
            Some(Bytes::from(req.sdp.clone())),
            Some("application/sdp"),
        );
        self.calls.insert(InviteCall {
            call_id: call_id.clone(),
            dialog_id: None,
            device_id: req.device_id,
            channel_id: req.channel_id,
            stream_id: req.stream_id,
            ssrc: req.ssrc,
            invite_cseq: cseq,
            protocol: req.protocol,
            state: InviteState::Calling,
            local_sdp: Some(req.sdp),
            remote_sdp: None,
            remote_contact: None,
            created_at: Instant::now(),
            updated_at: Instant::now(),
        });
        Ok(bytes)
    }

    fn handle_invite_2xx_response(&self, msg: SipMessage) -> Result<SipAction> {
        let call_id = msg.call_id()?;
        let mut call = self
            .calls
            .get(&call_id)
            .ok_or_else(|| SipError::CallNotFound(call_id.clone()))?;
        let remote_tag = msg.to_tag().ok_or_else(|| SipError::InvalidHeader {
            name: "To",
            reason: "2xx INVITE missing To tag".into(),
        })?;
        let local_tag = msg.from_tag().ok_or_else(|| SipError::InvalidHeader {
            name: "From",
            reason: "2xx INVITE missing From tag".into(),
        })?;
        let dialog_id = DialogId {
            call_id: call_id.clone(),
            local_tag,
            remote_tag,
        };
        let remote_target = msg
            .contact()
            .unwrap_or_else(|| format!("sip:{}@{}", call.device_id, self.local.domain));
        let remote_sdp = String::from_utf8_lossy(&msg.body).to_string();

        self.dialogs.insert(SipDialog {
            id: dialog_id.clone(),
            local_uri: msg.header("From").unwrap_or_default().to_string(),
            remote_uri: msg.header("To").unwrap_or_default().to_string(),
            local_contact: self.local.contact(call.protocol),
            remote_target: remote_target.clone(),
            protocol: call.protocol,
            local_cseq: call.invite_cseq,
            remote_cseq: 0,
            route_set: Vec::new(),
            state: DialogState::Confirmed,
            created_at: Instant::now(),
            updated_at: Instant::now(),
        });
        call.dialog_id = Some(dialog_id.clone());
        call.state = InviteState::Established;
        call.remote_sdp = Some(remote_sdp.clone());
        call.remote_contact = Some(remote_target.clone());
        call.updated_at = Instant::now();
        self.calls.update(call.clone());

        let ack = self.build_ack_for_invite_2xx(&call_id)?;
        let event = SipEvent::InviteAccepted(InviteAcceptedEvent {
            call_id,
            dialog_id,
            device_id: call.device_id,
            channel_id: call.channel_id,
            stream_id: call.stream_id,
            ssrc: call.ssrc,
            remote_contact: Some(remote_target),
            remote_sdp: remote_sdp.clone(),
            sdp_info: SdpInfo::parse_lossy(&remote_sdp),
        });
        Ok(SipAction::SendAndEvent { bytes: ack, event })
    }

    pub fn build_ack_for_invite_2xx(&self, call_id: &str) -> Result<Bytes> {
        let call = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipError::CallNotFound(call_id.into()))?;
        let dialog_id = call
            .dialog_id
            .clone()
            .ok_or_else(|| SipError::DialogNotFound(call_id.into()))?;
        let dialog = self
            .dialogs
            .get(&dialog_id)
            .ok_or_else(|| SipError::DialogNotFound(call_id.into()))?;
        let start_line = format!("ACK {} SIP/2.0", dialog.remote_target);
        let branch = new_branch();
        let headers = vec![
            (
                "Via".into(),
                via(
                    &self.local.public_host,
                    self.local.listen_port,
                    dialog.protocol,
                    &branch,
                ),
            ),
            ("Max-Forwards".into(), "70".into()),
            ("From".into(), dialog.local_uri.clone()),
            ("To".into(), dialog.remote_uri.clone()),
            ("Call-ID".into(), dialog.id.call_id.clone()),
            ("CSeq".into(), format!("{} ACK", call.invite_cseq)),
            ("Contact".into(), dialog.local_contact.clone()),
            ("User-Agent".into(), self.local.user_agent.clone()),
        ];
        Ok(build_request(&start_line, &headers, None, None))
    }

    /// Build an in-dialog SIP INFO request. This is the safe primitive used by
    /// playback seek/speed and future GB28181 in-dialog controls. The caller
    /// supplies only business body/content-type; dialog headers are generated
    /// from stored SIP context.
    pub fn create_info(&self, req: CreateInfo) -> Result<Bytes> {
        let (call, dialog_id, dialog) =
            self.resolve_call_dialog(req.call_id.as_deref(), req.stream_id.as_deref())?;
        let cseq = self
            .dialogs
            .next_local_cseq(&dialog_id)
            .unwrap_or(dialog.local_cseq + 1);
        let start_line = format!("INFO {} SIP/2.0", dialog.remote_target);
        let branch = new_branch();
        let mut headers = vec![
            (
                "Via".into(),
                via(
                    &self.local.public_host,
                    self.local.listen_port,
                    dialog.protocol,
                    &branch,
                ),
            ),
            ("Max-Forwards".into(), "70".into()),
            ("From".into(), dialog.local_uri.clone()),
            ("To".into(), dialog.remote_uri.clone()),
            ("Call-ID".into(), dialog.id.call_id.clone()),
            ("CSeq".into(), format!("{} INFO", cseq)),
            ("Contact".into(), dialog.local_contact.clone()),
            ("User-Agent".into(), self.local.user_agent.clone()),
        ];
        headers.extend(req.extra_headers);
        let _ = call;
        Ok(build_request(
            &start_line,
            &headers,
            Some(req.body),
            Some(&req.content_type),
        ))
    }

    pub fn create_playback_seek_info(&self, req: CreatePlaybackSeekInfo) -> Result<Bytes> {
        let body = xml::build_mansrtsp_seek_body(req.seek_second, req.rtsp_cseq.unwrap_or(1));
        self.create_info(CreateInfo {
            call_id: req.call_id,
            stream_id: req.stream_id,
            body: Bytes::from(body),
            content_type: xml::CONTENT_TYPE_MANSRTSP.to_string(),
            extra_headers: Vec::new(),
        })
    }

    pub fn create_playback_speed_info(&self, req: CreatePlaybackSpeedInfo) -> Result<Bytes> {
        let body = xml::build_mansrtsp_speed_body(
            req.scale,
            req.range_start_second,
            req.rtsp_cseq.unwrap_or(1),
        );
        self.create_info(CreateInfo {
            call_id: req.call_id,
            stream_id: req.stream_id,
            body: Bytes::from(body),
            content_type: xml::CONTENT_TYPE_MANSRTSP.to_string(),
            extra_headers: Vec::new(),
        })
    }

    pub fn create_talk_invite(&self, req: CreateTalkInvite) -> Result<Bytes> {
        let ssrc = req.ssrc.unwrap_or_else(|| rand::random::<u32>());
        let sdp = build_talk_sdp(TalkSdpOptions {
            ip: req.media_ip,
            port: req.media_port,
            ssrc,
            payload_type: req.payload_type,
            codec: req.codec,
            mode: req.mode,
        });
        self.create_invite(CreateInvite {
            device_id: req.device_id,
            channel_id: req.channel_id,
            stream_id: req.talk_id,
            target_uri: req.target_uri,
            sdp,
            ssrc: Some(ssrc),
            protocol: req.protocol,
            call_id: req.call_id,
            cseq: req.cseq,
            subject: req.subject,
        })
    }

    pub fn create_preset_query_message(&self, req: CreatePresetQueryMessage) -> Result<Bytes> {
        self.create_message(CreateMessage {
            target_uri: req.target_uri,
            body: Bytes::from(xml::build_preset_query_xml(&req.device_id)),
            content_type: xml::CONTENT_TYPE_MANSCDP_XML.to_string(),
            protocol: req.protocol,
            call_id: req.call_id,
            cseq: req.cseq,
        })
    }

    pub fn create_snapshot_control_message(
        &self,
        req: CreateSnapshotControlMessage,
    ) -> Result<Bytes> {
        self.create_message(CreateMessage {
            target_uri: req.target_uri,
            body: Bytes::from(xml::build_snapshot_control_xml(
                &req.channel_id,
                req.snap_num,
                req.interval,
                &req.upload_url,
                &req.session_id,
            )),
            content_type: xml::CONTENT_TYPE_MANSCDP_XML.to_string(),
            protocol: req.protocol,
            call_id: req.call_id,
            cseq: req.cseq,
        })
    }

    fn resolve_call_dialog(
        &self,
        call_id: Option<&str>,
        stream_id: Option<&str>,
    ) -> Result<(InviteCall, DialogId, SipDialog)> {
        let call = if let Some(call_id) = call_id {
            self.calls
                .get(call_id)
                .ok_or_else(|| SipError::CallNotFound(call_id.into()))?
        } else if let Some(stream_id) = stream_id {
            self.calls
                .get_by_stream(stream_id)
                .ok_or_else(|| SipError::CallNotFound(stream_id.into()))?
        } else {
            return Err(SipError::CallNotFound(
                "missing call_id or stream_id".into(),
            ));
        };
        let dialog_id = call
            .dialog_id
            .clone()
            .ok_or_else(|| SipError::DialogNotFound(call.call_id.clone()))?;
        let dialog = self
            .dialogs
            .get(&dialog_id)
            .ok_or_else(|| SipError::DialogNotFound(call.call_id.clone()))?;
        Ok((call, dialog_id, dialog))
    }

    pub fn create_bye(&self, req: CreateBye) -> Result<Bytes> {
        let call = if let Some(call_id) = req.call_id.as_deref() {
            self.calls
                .get(call_id)
                .ok_or_else(|| SipError::CallNotFound(call_id.into()))?
        } else if let Some(stream_id) = req.stream_id.as_deref() {
            self.calls
                .get_by_stream(stream_id)
                .ok_or_else(|| SipError::CallNotFound(stream_id.into()))?
        } else {
            return Err(SipError::CallNotFound(
                "missing call_id or stream_id".into(),
            ));
        };
        let dialog_id = call
            .dialog_id
            .clone()
            .ok_or_else(|| SipError::DialogNotFound(call.call_id.clone()))?;
        let dialog = self
            .dialogs
            .get(&dialog_id)
            .ok_or_else(|| SipError::DialogNotFound(call.call_id.clone()))?;
        let cseq = self
            .dialogs
            .next_local_cseq(&dialog_id)
            .unwrap_or(dialog.local_cseq + 1);
        let start_line = format!("BYE {} SIP/2.0", dialog.remote_target);
        let branch = new_branch();
        let headers = vec![
            (
                "Via".into(),
                via(
                    &self.local.public_host,
                    self.local.listen_port,
                    dialog.protocol,
                    &branch,
                ),
            ),
            ("Max-Forwards".into(), "70".into()),
            ("From".into(), dialog.local_uri.clone()),
            ("To".into(), dialog.remote_uri.clone()),
            ("Call-ID".into(), dialog.id.call_id.clone()),
            ("CSeq".into(), format!("{} BYE", cseq)),
            ("Contact".into(), dialog.local_contact.clone()),
            ("User-Agent".into(), self.local.user_agent.clone()),
        ];
        self.calls
            .update_state(&call.call_id, InviteState::Terminating);
        self.dialogs
            .update_state(&dialog_id, DialogState::Terminating);
        Ok(build_request(&start_line, &headers, None, None))
    }

    pub fn create_message(&self, req: CreateMessage) -> Result<Bytes> {
        let call_id = req
            .call_id
            .unwrap_or_else(|| new_call_id(&self.local.public_host));
        let branch = new_branch();
        let start_line = format!("MESSAGE {} SIP/2.0", req.target_uri);
        let headers = vec![
            (
                "Via".into(),
                via(
                    &self.local.public_host,
                    self.local.listen_port,
                    req.protocol,
                    &branch,
                ),
            ),
            ("Max-Forwards".into(), "70".into()),
            (
                "From".into(),
                format!("<{}>;tag={}", self.local.local_uri(), new_tag()),
            ),
            ("To".into(), format!("<{}>", req.target_uri)),
            ("Call-ID".into(), call_id),
            ("CSeq".into(), format!("{} MESSAGE", req.cseq.unwrap_or(1))),
            ("User-Agent".into(), self.local.user_agent.clone()),
        ];
        Ok(build_request(
            &start_line,
            &headers,
            Some(req.body),
            Some(&req.content_type),
        ))
    }

    pub fn create_subscribe(&self, req: CreateSubscribe) -> Result<Bytes> {
        let call_id = req
            .call_id
            .unwrap_or_else(|| new_call_id(&self.local.public_host));
        let branch = new_branch();
        let from_header = req
            .from_header
            .unwrap_or_else(|| format!("<{}>;tag={}", self.local.local_uri(), new_tag()));
        let to_header = req
            .to_header
            .unwrap_or_else(|| format!("<{}>", req.target_uri));
        let start_line = format!("SUBSCRIBE {} SIP/2.0", req.target_uri);
        let mut headers = vec![
            (
                "Via".into(),
                via(
                    &self.local.public_host,
                    self.local.listen_port,
                    req.protocol,
                    &branch,
                ),
            ),
            ("Max-Forwards".into(), "70".into()),
            ("From".into(), from_header),
            ("To".into(), to_header),
            ("Call-ID".into(), call_id),
            (
                "CSeq".into(),
                format!("{} SUBSCRIBE", req.cseq.unwrap_or(1)),
            ),
            ("Contact".into(), self.local.contact(req.protocol)),
            ("Event".into(), req.event),
            ("Expires".into(), req.expires.to_string()),
            ("User-Agent".into(), self.local.user_agent.clone()),
        ];
        headers.extend(
            req.route_set
                .into_iter()
                .map(|route| ("Route".to_string(), route)),
        );
        Ok(build_request(
            &start_line,
            &headers,
            Some(req.body),
            Some(&req.content_type),
        ))
    }
}

fn contact_supports_lr(contact: &str) -> bool {
    contact.split(';').skip(1).any(|part| {
        part.trim()
            .trim_end_matches('>')
            .split('=')
            .next()
            .is_some_and(|name| name.trim().eq_ignore_ascii_case("lr"))
    })
}

fn parse_expires(msg: &SipMessage) -> Option<u32> {
    msg.header("Expires")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .or_else(|| {
            msg.header("Contact").and_then(|contact| {
                contact.split(';').find_map(|p| {
                    let (k, v) = p.trim().split_once('=')?;
                    if k.eq_ignore_ascii_case("expires") {
                        v.parse().ok()
                    } else {
                        None
                    }
                })
            })
        })
}

fn auth_username(auth: &AuthDecision) -> Option<String> {
    match auth {
        AuthDecision::Authorized { username } => Some(username.clone()),
        _ => None,
    }
}

fn classify_message_body(body: &Bytes) -> MessageKind {
    let text = String::from_utf8_lossy(body);
    match xml::cmd_type_lossy(&text).as_deref() {
        Some("Keepalive") => MessageKind::Keepalive,
        Some("Catalog") => MessageKind::Catalog,
        Some("DeviceInfo") => MessageKind::DeviceInfo,
        Some("RecordInfo") => MessageKind::RecordInfo,
        Some("Alarm") => MessageKind::Alarm,
        Some("MediaStatus") => MessageKind::MediaStatus,
        Some("DeviceControl") => MessageKind::DeviceControl,
        Some("DeviceConfig") => MessageKind::DeviceConfig,
        Some("PresetQuery") => MessageKind::PresetQuery,
        Some("UploadSnapShotFinished") => MessageKind::UploadSnapshotFinished,
        _ => MessageKind::Unknown,
    }
}
