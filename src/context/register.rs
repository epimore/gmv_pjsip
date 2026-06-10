use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::transport::SipTransportProtocol;

#[derive(Clone, Debug)]
pub struct RegisterBinding {
    pub device_id: String,
    pub contact: Option<String>,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: SipTransportProtocol,
    pub call_id: String,
    pub cseq: u32,
    pub expires: u32,
    pub expires_at: Instant,
    pub user_agent: Option<String>,
}

#[derive(Debug)]
pub struct RegisterStore {
    bindings: DashMap<String, RegisterBinding>,
}

impl RegisterStore {
    pub fn new() -> Self {
        Self {
            bindings: DashMap::new(),
        }
    }

    pub fn upsert(&self, binding: RegisterBinding) {
        self.bindings.insert(binding.device_id.clone(), binding);
    }

    pub fn remove(&self, device_id: &str) -> Option<RegisterBinding> {
        self.bindings.remove(device_id).map(|(_, v)| v)
    }

    pub fn get(&self, device_id: &str) -> Option<RegisterBinding> {
        self.bindings.get(device_id).map(|v| v.clone())
    }

    pub fn cleanup(&self) -> usize {
        let now = Instant::now();
        let before = self.bindings.len();
        self.bindings.retain(|_, b| b.expires_at > now);
        before.saturating_sub(self.bindings.len())
    }
}

impl Default for RegisterStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn expires_at(expires: u32) -> Instant {
    Instant::now() + Duration::from_secs(expires as u64)
}
