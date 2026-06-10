use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::message::SipMessage;
use crate::transport::SipAssociation;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerTransactionKey {
    pub transport: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub branch: Option<String>,
    pub method: String,
    pub call_id: String,
    pub cseq_num: u32,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
}

impl ServerTransactionKey {
    pub fn from_request(assoc: &SipAssociation, req: &SipMessage) -> Option<Self> {
        let method = req.method()?.to_string();
        let call_id = req.call_id()?.to_string();
        let (cseq_num, _) = req.cseq_num_method()?;
        let branch = req.via().and_then(extract_branch).map(ToOwned::to_owned);
        Some(Self {
            transport: assoc.transport.as_str().into(),
            local_addr: assoc.local_addr.to_string(),
            remote_addr: assoc.remote_addr.to_string(),
            branch,
            method,
            call_id,
            cseq_num,
            from_tag: req.from_tag(),
            to_tag: req.to_tag(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientTransactionKey {
    pub method: String,
    pub call_id: String,
    pub cseq_num: u32,
    pub branch: Option<String>,
}

impl ClientTransactionKey {
    pub fn from_response(resp: &SipMessage) -> Option<Self> {
        let call_id = resp.call_id()?.to_string();
        let (cseq_num, method) = resp.cseq_num_method()?;
        let branch = resp.via().and_then(extract_branch).map(ToOwned::to_owned);
        Some(Self {
            method,
            call_id,
            cseq_num,
            branch,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerTransaction {
    pub key: ServerTransactionKey,
    pub request_digest: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub expires_at_ms: u64,
    pub last_response: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ClientTransaction {
    pub key: ClientTransactionKey,
    pub request: Vec<u8>,
    pub created_at_ms: u64,
    pub last_response_status: Option<u16>,
    pub last_ack: Option<Vec<u8>>,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone)]
pub enum ServerTxDecision {
    New(ServerTransactionKey),
    DuplicateReturn(Vec<u8>),
    DuplicateProcessing,
    ReplayConflict,
}

#[derive(Debug, Default, Clone)]
pub struct TransactionStore {
    server: Arc<RwLock<HashMap<ServerTransactionKey, ServerTransaction>>>,
    client: Arc<RwLock<HashMap<ClientTransactionKey, ClientTransaction>>>,
}

impl TransactionStore {
    pub fn on_server_request(
        &self,
        assoc: &SipAssociation,
        req: &SipMessage,
        ttl: Duration,
    ) -> Option<ServerTxDecision> {
        let key = ServerTransactionKey::from_request(assoc, req)?;
        let digest = request_digest(req);
        let now = now_ms();

        let mut map = self.server.write().expect("transaction store poisoned");
        if let Some(tx) = map.get_mut(&key) {
            tx.last_seen_ms = now;
            if tx.request_digest != digest {
                return Some(ServerTxDecision::ReplayConflict);
            }
            if let Some(resp) = &tx.last_response {
                return Some(ServerTxDecision::DuplicateReturn(resp.clone()));
            }
            return Some(ServerTxDecision::DuplicateProcessing);
        }

        map.insert(
            key.clone(),
            ServerTransaction {
                key: key.clone(),
                request_digest: digest,
                first_seen_ms: now,
                last_seen_ms: now,
                expires_at_ms: now + ttl.as_millis() as u64,
                last_response: None,
            },
        );

        Some(ServerTxDecision::New(key))
    }

    pub fn store_server_response(&self, key: &ServerTransactionKey, response: Vec<u8>) {
        if let Some(tx) = self
            .server
            .write()
            .expect("transaction store poisoned")
            .get_mut(key)
        {
            tx.last_response = Some(response);
        }
    }

    pub fn insert_client(&self, tx: ClientTransaction) {
        self.client
            .write()
            .expect("transaction store poisoned")
            .insert(tx.key.clone(), tx);
    }

    pub fn update_client_response(&self, key: &ClientTransactionKey, status: u16) {
        if let Some(tx) = self
            .client
            .write()
            .expect("transaction store poisoned")
            .get_mut(key)
        {
            tx.last_response_status = Some(status);
        }
    }

    pub fn store_client_ack(&self, key: &ClientTransactionKey, ack: Vec<u8>) {
        if let Some(tx) = self
            .client
            .write()
            .expect("transaction store poisoned")
            .get_mut(key)
        {
            tx.last_ack = Some(ack);
        }
    }

    pub fn get_client_ack(&self, key: &ClientTransactionKey) -> Option<Vec<u8>> {
        self.client
            .read()
            .expect("transaction store poisoned")
            .get(key)
            .and_then(|tx| tx.last_ack.clone())
    }

    pub fn gc_expired(&self) {
        let now = now_ms();
        self.server
            .write()
            .expect("transaction store poisoned")
            .retain(|_, tx| tx.expires_at_ms > now);
        self.client
            .write()
            .expect("transaction store poisoned")
            .retain(|_, tx| tx.expires_at_ms > now);
    }
}

pub fn request_digest(req: &SipMessage) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    req.start_line.hash(&mut h);
    req.call_id().hash(&mut h);
    req.cseq().hash(&mut h);
    req.from().hash(&mut h);
    req.to().hash(&mut h);
    req.body().hash(&mut h);
    h.finish()
}

pub fn extract_branch(via: &str) -> Option<&str> {
    via.split(';')
        .find_map(|p| p.trim().strip_prefix("branch="))
        .map(str::trim)
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
