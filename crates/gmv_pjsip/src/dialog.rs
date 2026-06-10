use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::message::SipMessage;
use crate::transport::SipAssociation;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    pub association: SipAssociation,
    pub call_id: String,
    pub invite_cseq: u32,
    pub local_uri: String,
    pub local_tag: String,
    pub local_contact: String,
    pub remote_uri: String,
    pub remote_tag: Option<String>,
    pub remote_contact: Option<String>,
    pub invite_request_uri: String,
    pub state: DialogState,
}

impl InviteDialog {
    pub fn id(&self) -> Option<DialogId> {
        Some(DialogId {
            call_id: self.call_id.clone(),
            local_tag: self.local_tag.clone(),
            remote_tag: self.remote_tag.clone()?,
        })
    }

    pub fn update_from_2xx(&mut self, resp: &SipMessage) {
        if let Some(tag) = resp.to_tag() {
            self.remote_tag = Some(tag);
        }
        if let Some(contact) = resp.contact() {
            self.remote_contact = Some(contact.to_string());
        }
        self.state = DialogState::Confirmed;
    }
}

#[derive(Debug, Default, Clone)]
pub struct DialogStore {
    early_by_call_id: Arc<RwLock<HashMap<String, InviteDialog>>>,
    confirmed: Arc<RwLock<HashMap<DialogId, InviteDialog>>>,
}

impl DialogStore {
    pub fn insert_early(&self, dialog: InviteDialog) {
        self.early_by_call_id
            .write()
            .expect("dialog store poisoned")
            .insert(dialog.call_id.clone(), dialog);
    }

    pub fn get_early(&self, call_id: &str) -> Option<InviteDialog> {
        self.early_by_call_id
            .read()
            .expect("dialog store poisoned")
            .get(call_id)
            .cloned()
    }

    pub fn update_early<F>(&self, call_id: &str, f: F) -> Option<InviteDialog>
    where
        F: FnOnce(&mut InviteDialog),
    {
        let mut guard = self.early_by_call_id.write().expect("dialog store poisoned");
        let dlg = guard.get_mut(call_id)?;
        f(dlg);
        Some(dlg.clone())
    }

    pub fn confirm(&self, call_id: &str) -> Option<InviteDialog> {
        let mut early = self.early_by_call_id.write().expect("dialog store poisoned");
        let dialog = early.get(call_id)?.clone();
        let id = dialog.id()?;
        self.confirmed
            .write()
            .expect("dialog store poisoned")
            .insert(id, dialog.clone());
        Some(dialog)
    }

    pub fn get_confirmed(&self, id: &DialogId) -> Option<InviteDialog> {
        self.confirmed
            .read()
            .expect("dialog store poisoned")
            .get(id)
            .cloned()
    }
}
