use std::time::Instant;

use dashmap::DashMap;

use crate::context::DialogId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteState {
    Calling,
    Proceeding,
    Established,
    Terminating,
    Terminated,
    Failed,
}

#[derive(Clone, Debug)]
pub struct InviteCall {
    pub call_id: String,
    pub dialog_id: Option<DialogId>,
    pub device_id: String,
    pub channel_id: String,
    pub stream_id: String,
    pub ssrc: Option<u32>,
    pub invite_cseq: u32,
    pub state: InviteState,
    pub local_sdp: Option<String>,
    pub remote_sdp: Option<String>,
    pub remote_contact: Option<String>,
    pub created_at: Instant,
    pub updated_at: Instant,
}

#[derive(Debug)]
pub struct CallStore {
    calls: DashMap<String, InviteCall>,
    by_stream: DashMap<String, String>,
}

impl CallStore {
    pub fn new() -> Self { Self { calls: DashMap::new(), by_stream: DashMap::new() } }
    pub fn insert(&self, call: InviteCall) {
        self.by_stream.insert(call.stream_id.clone(), call.call_id.clone());
        self.calls.insert(call.call_id.clone(), call);
    }
    pub fn get(&self, call_id: &str) -> Option<InviteCall> { self.calls.get(call_id).map(|v| v.clone()) }
    pub fn get_by_stream(&self, stream_id: &str) -> Option<InviteCall> {
        let call_id = self.by_stream.get(stream_id)?.clone();
        self.get(&call_id)
    }
    pub fn update(&self, call: InviteCall) { self.calls.insert(call.call_id.clone(), call); }
    pub fn update_state(&self, call_id: &str, state: InviteState) {
        if let Some(mut c) = self.calls.get_mut(call_id) { c.state = state; c.updated_at = Instant::now(); }
    }
    pub fn remove(&self, call_id: &str) -> Option<InviteCall> {
        let call = self.calls.remove(call_id).map(|(_, v)| v)?;
        self.by_stream.remove(&call.stream_id);
        Some(call)
    }
}

impl Default for CallStore { fn default() -> Self { Self::new() } }
