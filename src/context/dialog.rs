use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::transport::SipTransportProtocol;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialogState {
    Early,
    Confirmed,
    Terminating,
    Terminated,
}

#[derive(Clone, Debug)]
pub struct SipDialog {
    pub id: DialogId,
    /// Full local-side header value, including tag. Used as From for local requests.
    pub local_uri: String,
    /// Full remote-side header value, including tag when known. Used as To for local requests.
    pub remote_uri: String,
    pub local_contact: String,
    pub remote_target: String,
    pub protocol: SipTransportProtocol,
    pub local_cseq: u32,
    pub remote_cseq: u32,
    pub route_set: Vec<String>,
    pub state: DialogState,
    pub created_at: Instant,
    pub updated_at: Instant,
}

#[derive(Debug)]
pub struct DialogStore {
    dialogs: DashMap<DialogId, SipDialog>,
    by_call_id: DashMap<String, DialogId>,
}

impl DialogStore {
    pub fn new() -> Self {
        Self {
            dialogs: DashMap::new(),
            by_call_id: DashMap::new(),
        }
    }

    pub fn insert(&self, dialog: SipDialog) {
        self.by_call_id.insert(dialog.id.call_id.clone(), dialog.id.clone());
        self.dialogs.insert(dialog.id.clone(), dialog);
    }

    pub fn get(&self, id: &DialogId) -> Option<SipDialog> {
        self.dialogs.get(id).map(|v| v.clone())
    }

    pub fn get_by_call_id(&self, call_id: &str) -> Option<SipDialog> {
        let id = self.by_call_id.get(call_id)?.clone();
        self.get(&id)
    }

    pub fn update_state(&self, id: &DialogId, state: DialogState) {
        if let Some(mut d) = self.dialogs.get_mut(id) {
            d.state = state;
            d.updated_at = Instant::now();
        }
    }

    pub fn next_local_cseq(&self, id: &DialogId) -> Option<u32> {
        let mut d = self.dialogs.get_mut(id)?;
        d.local_cseq += 1;
        d.updated_at = Instant::now();
        Some(d.local_cseq)
    }

    pub fn remove(&self, id: &DialogId) -> Option<SipDialog> {
        let dialog = self.dialogs.remove(id).map(|(_, v)| v)?;
        self.by_call_id.remove(&dialog.id.call_id);
        Some(dialog)
    }

    pub fn cleanup_terminated(&self, retain_for: Duration) -> usize {
        let now = Instant::now();
        let expired: Vec<DialogId> = self
            .dialogs
            .iter()
            .filter_map(|item| {
                let dialog = item.value();
                if dialog.state == DialogState::Terminated
                    && now.duration_since(dialog.updated_at) >= retain_for
                {
                    Some(dialog.id.clone())
                } else {
                    None
                }
            })
            .collect();

        let removed = expired.len();
        for id in expired {
            self.remove(&id);
        }
        removed
    }
}

impl Default for DialogStore {
    fn default() -> Self {
        Self::new()
    }
}
