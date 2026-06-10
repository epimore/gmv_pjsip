use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;

use crate::message::SipMessage;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ServerTransactionKey {
    pub branch: Option<String>,
    pub call_id: String,
    pub cseq_number: u32,
    pub method: String,
    pub remote_addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct ServerTransaction {
    pub key: ServerTransactionKey,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub last_response: Option<Bytes>,
}

#[derive(Debug)]
pub struct TransactionStore {
    ttl: Duration,
    server: DashMap<ServerTransactionKey, ServerTransaction>,
}

impl TransactionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            server: DashMap::new(),
        }
    }

    pub fn key_from_request(msg: &SipMessage, remote_addr: SocketAddr) -> Option<ServerTransactionKey> {
        let call_id = msg.call_id().ok()?;
        let cseq = msg.cseq().ok()?;
        Some(ServerTransactionKey {
            branch: msg.via_branch(),
            call_id,
            cseq_number: cseq.number,
            method: cseq.method,
            remote_addr,
        })
    }

    pub fn duplicate_response(&self, key: &ServerTransactionKey) -> Option<Bytes> {
        self.server.get_mut(key).and_then(|mut tx| {
            tx.last_seen = Instant::now();
            tx.last_response.clone()
        })
    }

    pub fn mark_seen(&self, key: ServerTransactionKey) {
        let now = Instant::now();
        self.server.entry(key.clone()).or_insert(ServerTransaction {
            key,
            created_at: now,
            last_seen: now,
            last_response: None,
        });
    }

    pub fn store_response(&self, key: &ServerTransactionKey, response: Bytes) {
        let now = Instant::now();
        self.server
            .entry(key.clone())
            .and_modify(|tx| {
                tx.last_seen = now;
                tx.last_response = Some(response.clone());
            })
            .or_insert(ServerTransaction {
                key: key.clone(),
                created_at: now,
                last_seen: now,
                last_response: Some(response),
            });
    }

    pub fn cleanup(&self) -> usize {
        let ttl = self.ttl;
        let now = Instant::now();
        let before = self.server.len();
        self.server.retain(|_, tx| now.duration_since(tx.last_seen) <= ttl);
        before.saturating_sub(self.server.len())
    }
}
