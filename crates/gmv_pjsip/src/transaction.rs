//! SIP transaction and duplicate suppression.
//!
//! This module provides the transaction boundary expected by gmv session. It is
//! intentionally independent from gmv business state. It stores the last
//! response for server transactions and the last ACK for INVITE 2xx handling.
//!
//! When a full PJSIP transaction-layer bridge is added behind `SipEndpoint`,
//! these public keys/decisions can remain stable while internals move to
//! `pjsip_transaction`.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{poisoned, PjError, Result};
use crate::message::SipMessageView;
use crate::transport::{SipAssociation, SipTransportProtocol};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ServerTxKey {
    pub protocol: SipTransportProtocol,
    pub local_addr: String,
    pub remote_addr: String,
    pub branch: Option<String>,
    pub method: String,
    pub call_id: String,
    pub cseq_num: u32,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
}

impl ServerTxKey {
    pub fn from_request(assoc: &SipAssociation, req: &SipMessageView) -> Result<Self> {
        let method = req.method.clone().ok_or_else(|| {
            PjError::Transaction("cannot build ServerTxKey for response".to_string())
        })?;
        let call_id = req
            .call_id()
            .ok_or_else(|| PjError::Transaction("missing Call-ID".to_string()))?
            .to_string();
        let (cseq_num, _cseq_method) = req
            .cseq_parts()
            .ok_or_else(|| PjError::Transaction("invalid CSeq".to_string()))?;

        Ok(Self {
            protocol: assoc.protocol,
            local_addr: assoc.local_addr.to_string(),
            remote_addr: assoc.remote_addr.to_string(),
            branch: req.branch(),
            method,
            call_id,
            cseq_num,
            from_tag: req.from_tag(),
            to_tag: req.to_tag(),
        })
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ClientTxKey {
    pub method: String,
    pub call_id: String,
    pub cseq_num: u32,
    pub branch: Option<String>,
}

impl ClientTxKey {
    pub fn from_response(resp: &SipMessageView) -> Result<Self> {
        let call_id = resp
            .call_id()
            .ok_or_else(|| PjError::Transaction("missing Call-ID".to_string()))?
            .to_string();
        let (cseq_num, method) = resp
            .cseq_parts()
            .ok_or_else(|| PjError::Transaction("invalid CSeq".to_string()))?;

        Ok(Self {
            method,
            call_id,
            cseq_num,
            branch: resp.branch(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTxState {
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTxState {
    Calling,
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct ServerTransaction {
    pub key: ServerTxKey,
    pub state: ServerTxState,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub expires_at_ms: u64,
    pub request_digest: u64,
    pub last_response: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ClientTransaction {
    pub key: ClientTxKey,
    pub state: ClientTxState,
    pub request: Vec<u8>,
    pub created_at_ms: u64,
    pub last_send_ms: u64,
    pub expires_at_ms: u64,
    pub retransmit_count: u32,
    pub last_response_status: Option<u16>,
    pub last_ack: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum ServerTxDecision {
    New(ServerTxKey),
    DuplicateReturnLastResponse(Vec<u8>),
    DuplicateNoResponse,
    ReplayedReject,
}

#[derive(Debug, Clone)]
pub enum ClientTxDecision {
    Matched(ClientTxKey),
    DuplicateInvite2xxAck(Vec<u8>),
    Unknown,
}

#[derive(Debug)]
pub struct TransactionStore {
    server_txs: Mutex<HashMap<ServerTxKey, ServerTransaction>>,
    client_txs: Mutex<HashMap<ClientTxKey, ClientTransaction>>,
    server_ttl_ms: u64,
    client_ttl_ms: u64,
}

impl Default for TransactionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionStore {
    pub fn new() -> Self {
        Self {
            server_txs: Mutex::new(HashMap::new()),
            client_txs: Mutex::new(HashMap::new()),
            server_ttl_ms: 64_000,
            client_ttl_ms: 64_000,
        }
    }

    pub fn on_request(
        &self,
        assoc: &SipAssociation,
        req: &SipMessageView,
    ) -> Result<ServerTxDecision> {
        let key = ServerTxKey::from_request(assoc, req)?;
        let digest = request_digest(req);
        let now = now_ms();

        let mut map = self
            .server_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.server_txs"))?;

        if let Some(tx) = map.get_mut(&key) {
            tx.last_seen_ms = now;

            if tx.request_digest != digest {
                return Ok(ServerTxDecision::ReplayedReject);
            }

            if let Some(resp) = &tx.last_response {
                return Ok(ServerTxDecision::DuplicateReturnLastResponse(resp.clone()));
            }

            return Ok(ServerTxDecision::DuplicateNoResponse);
        }

        let tx = ServerTransaction {
            key: key.clone(),
            state: ServerTxState::Proceeding,
            first_seen_ms: now,
            last_seen_ms: now,
            expires_at_ms: now + self.server_ttl_ms,
            request_digest: digest,
            last_response: None,
        };

        map.insert(key.clone(), tx);
        Ok(ServerTxDecision::New(key))
    }

    pub fn store_server_response(&self, key: &ServerTxKey, response: Vec<u8>) -> Result<()> {
        let mut map = self
            .server_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.server_txs"))?;

        let tx = map
            .get_mut(key)
            .ok_or_else(|| PjError::Transaction("server transaction not found".to_string()))?;
        tx.state = ServerTxState::Completed;
        tx.last_response = Some(response);
        Ok(())
    }

    pub fn insert_client_request(&self, key: ClientTxKey, request: Vec<u8>) -> Result<()> {
        let now = now_ms();
        let tx = ClientTransaction {
            key: key.clone(),
            state: ClientTxState::Calling,
            request,
            created_at_ms: now,
            last_send_ms: now,
            expires_at_ms: now + self.client_ttl_ms,
            retransmit_count: 0,
            last_response_status: None,
            last_ack: None,
        };

        let mut map = self
            .client_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.client_txs"))?;
        map.insert(key, tx);
        Ok(())
    }

    pub fn on_response(&self, resp: &SipMessageView) -> Result<ClientTxDecision> {
        let key = ClientTxKey::from_response(resp)?;
        let status = resp.status_code.unwrap_or(0);

        let mut map = self
            .client_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.client_txs"))?;

        let Some(tx) = map.get_mut(&key) else {
            return Ok(ClientTxDecision::Unknown);
        };

        if key.method == "INVITE" && (200..=299).contains(&status) {
            if let Some(ack) = &tx.last_ack {
                return Ok(ClientTxDecision::DuplicateInvite2xxAck(ack.clone()));
            }
        }

        tx.last_response_status = Some(status);
        tx.state = if status < 200 {
            ClientTxState::Proceeding
        } else {
            ClientTxState::Completed
        };

        Ok(ClientTxDecision::Matched(key))
    }

    pub fn store_invite_ack(&self, key: &ClientTxKey, ack: Vec<u8>) -> Result<()> {
        let mut map = self
            .client_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.client_txs"))?;
        let tx = map
            .get_mut(key)
            .ok_or_else(|| PjError::Transaction("client transaction not found".to_string()))?;
        tx.last_ack = Some(ack);
        Ok(())
    }

    pub fn expire(&self) -> Result<()> {
        let now = now_ms();
        self.server_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.server_txs"))?
            .retain(|_, tx| tx.expires_at_ms > now);
        self.client_txs
            .lock()
            .map_err(|_| poisoned("TransactionStore.client_txs"))?
            .retain(|_, tx| tx.expires_at_ms > now);
        Ok(())
    }
}

pub fn request_digest(req: &SipMessageView) -> u64 {
    let mut h = DefaultHasher::new();
    req.start_line.hash(&mut h);
    for header in &req.headers {
        // Content-Length is transport framing, not business identity.
        if header.name.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        header.name.to_ascii_lowercase().hash(&mut h);
        header.value.hash(&mut h);
    }
    req.body.hash(&mut h);
    h.finish()
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
