//! SIP dialog state with GB28181-friendly metadata.
//!
//! PJSIP parser/builder validation is already used by this crate. This module
//! keeps a Rust-owned dialog view so `session` can perform business idempotency
//! without touching raw PJSIP pointers. When a full PJSIP base-dialog bridge is
//! added, it can live behind these types.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::builder;
use crate::error::{poisoned, PjError, Result};
use crate::message::{extract_uri, SipMessageView};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    Early,
    Confirmed,
    Terminating,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct InviteDialog {
    pub id: Option<DialogId>,

    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: Option<String>,

    pub invite_cseq: u32,
    pub next_local_cseq: u32,
    pub last_remote_cseq: Option<u32>,

    pub local_uri: String,
    pub remote_uri: String,
    pub local_contact: String,
    pub remote_contact: Option<String>,
    pub invite_request_uri: String,
    pub local_sent_by: String,

    pub state: DialogState,

    /// Opaque business key owned by gmv session, e.g. stream_id/play_session_id.
    pub gb_session_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewInviteDialog {
    pub call_id: String,
    pub local_tag: String,
    pub invite_cseq: u32,
    pub local_uri: String,
    pub remote_uri: String,
    pub local_contact: String,
    pub invite_request_uri: String,
    pub local_sent_by: String,
    pub gb_session_key: Option<String>,
}

impl InviteDialog {
    pub fn new_uac(opt: NewInviteDialog) -> Self {
        Self {
            id: None,
            call_id: opt.call_id,
            local_tag: opt.local_tag,
            remote_tag: None,
            invite_cseq: opt.invite_cseq,
            next_local_cseq: opt.invite_cseq + 1,
            last_remote_cseq: None,
            local_uri: opt.local_uri,
            remote_uri: opt.remote_uri,
            local_contact: opt.local_contact,
            remote_contact: None,
            invite_request_uri: opt.invite_request_uri,
            local_sent_by: opt.local_sent_by,
            state: DialogState::Early,
            gb_session_key: opt.gb_session_key,
        }
    }

    pub fn confirm_from_2xx(&mut self, resp: &SipMessageView) -> Result<DialogId> {
        if !resp.is_response() {
            return Err(PjError::Dialog("confirm_from_2xx requires response".to_string()));
        }

        let status = resp.status_code.unwrap_or(0);
        if !(200..=299).contains(&status) {
            return Err(PjError::Dialog(format!(
                "confirm_from_2xx requires 2xx response, got {status}"
            )));
        }

        let remote_tag = resp.to_tag().ok_or_else(|| {
            PjError::Dialog("2xx INVITE response missing To tag".to_string())
        })?;

        self.remote_tag = Some(remote_tag.clone());
        if let Some(contact) = resp.contact() {
            self.remote_contact = Some(contact.to_string());
        }
        self.state = DialogState::Confirmed;

        let id = DialogId {
            call_id: self.call_id.clone(),
            local_tag: self.local_tag.clone(),
            remote_tag,
        };
        self.id = Some(id.clone());
        Ok(id)
    }

    pub fn update_remote_cseq(&mut self, msg: &SipMessageView) {
        if let Some((num, _method)) = msg.cseq_parts() {
            self.last_remote_cseq = Some(num);
        }
    }

    pub fn ack_for_2xx(&self, user_agent: &str) -> Result<Vec<u8>> {
        builder::build_ack_for_invite_2xx(self, user_agent)
    }

    pub fn bye(&mut self, user_agent: &str) -> Result<Vec<u8>> {
        self.state = DialogState::Terminating;
        let out = builder::build_bye(self, user_agent)?;
        self.next_local_cseq += 1;
        Ok(out)
    }

    pub fn remote_target_uri(&self) -> &str {
        self.remote_contact
            .as_deref()
            .and_then(extract_uri)
            .unwrap_or(self.invite_request_uri.as_str())
    }
}

#[derive(Debug, Default)]
pub struct DialogStore {
    early_by_call_id: Mutex<HashMap<String, InviteDialog>>,
    confirmed: Mutex<HashMap<DialogId, InviteDialog>>,
    tombstones: Mutex<HashMap<DialogId, InviteDialog>>,
}

impl DialogStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_early(&self, dialog: InviteDialog) -> Result<()> {
        let mut m = self
            .early_by_call_id
            .lock()
            .map_err(|_| poisoned("DialogStore.early_by_call_id"))?;
        m.insert(dialog.call_id.clone(), dialog);
        Ok(())
    }

    pub fn get_early(&self, call_id: &str) -> Result<Option<InviteDialog>> {
        let m = self
            .early_by_call_id
            .lock()
            .map_err(|_| poisoned("DialogStore.early_by_call_id"))?;
        Ok(m.get(call_id).cloned())
    }

    pub fn confirm_early_from_2xx(&self, call_id: &str, resp: &SipMessageView) -> Result<InviteDialog> {
        let mut early = self
            .early_by_call_id
            .lock()
            .map_err(|_| poisoned("DialogStore.early_by_call_id"))?;

        let mut dialog = early
            .remove(call_id)
            .ok_or_else(|| PjError::Dialog(format!("early dialog not found for Call-ID {call_id}")))?;

        let id = dialog.confirm_from_2xx(resp)?;

        let mut confirmed = self
            .confirmed
            .lock()
            .map_err(|_| poisoned("DialogStore.confirmed"))?;
        confirmed.insert(id, dialog.clone());
        Ok(dialog)
    }

    pub fn upsert_confirmed(&self, dialog: InviteDialog) -> Result<()> {
        let id = dialog
            .id
            .clone()
            .ok_or_else(|| PjError::Dialog("confirmed dialog missing DialogId".to_string()))?;
        let mut confirmed = self
            .confirmed
            .lock()
            .map_err(|_| poisoned("DialogStore.confirmed"))?;
        confirmed.insert(id, dialog);
        Ok(())
    }

    pub fn get_confirmed(&self, id: &DialogId) -> Result<Option<InviteDialog>> {
        let confirmed = self
            .confirmed
            .lock()
            .map_err(|_| poisoned("DialogStore.confirmed"))?;
        Ok(confirmed.get(id).cloned())
    }

    pub fn terminate(&self, id: &DialogId) -> Result<Option<InviteDialog>> {
        let mut confirmed = self
            .confirmed
            .lock()
            .map_err(|_| poisoned("DialogStore.confirmed"))?;
        let Some(mut dialog) = confirmed.remove(id) else {
            return Ok(None);
        };
        dialog.state = DialogState::Terminated;
        let mut tombstones = self
            .tombstones
            .lock()
            .map_err(|_| poisoned("DialogStore.tombstones"))?;
        tombstones.insert(id.clone(), dialog.clone());
        Ok(Some(dialog))
    }
}
