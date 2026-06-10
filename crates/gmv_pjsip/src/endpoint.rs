use std::sync::Arc;
use std::time::Duration;

use crate::builder::{build_response, ResponseOptions};
use crate::dialog::DialogStore;
use crate::error::{PjError, Result};
use crate::message::{SipKind, SipMessage};
use crate::runtime::PjRuntime;
use crate::transaction::{ServerTxDecision, TransactionStore};
use crate::transport::{SipAssociation, SipTxPacket};

#[derive(Debug, Clone)]
pub enum SipEventKind {
    Request(SipMessage),
    Response(SipMessage),
}

#[derive(Debug, Clone)]
pub struct SipEvent {
    pub association: SipAssociation,
    pub kind: SipEventKind,
}

#[derive(Debug, Clone)]
pub enum EndpointRxResult {
    Event(SipEvent),
    Tx(SipTxPacket),
    Drop,
}

/// High-level endpoint facade used by gmv_session.
///
/// Runtime initialization uses real PJSIP endpoint + transaction + UA modules. Bytes are validated
/// by PJSIP parser. Tokio UDP/TCP sockets remain in gmv and are represented by SipAssociation.
#[derive(Clone)]
pub struct SipEndpoint {
    runtime: Arc<PjRuntime>,
    tx_store: TransactionStore,
    dialogs: DialogStore,
    pub user_agent: String,
    pub server_tx_ttl: Duration,
}

impl SipEndpoint {
    pub fn new(runtime: Arc<PjRuntime>, user_agent: impl Into<String>) -> Self {
        Self {
            runtime,
            tx_store: TransactionStore::default(),
            dialogs: DialogStore::default(),
            user_agent: user_agent.into(),
            server_tx_ttl: Duration::from_secs(64),
        }
    }

    pub fn runtime(&self) -> &PjRuntime {
        &self.runtime
    }

    pub fn transactions(&self) -> &TransactionStore {
        &self.tx_store
    }

    pub fn dialogs(&self) -> &DialogStore {
        &self.dialogs
    }

    pub fn parse(&self, raw: &[u8]) -> Result<SipMessage> {
        SipMessage::parse(&self.runtime, raw)
    }

    /// Parse incoming bytes and apply SIP transaction-level dedupe for incoming requests.
    ///
    /// The returned `Event` should be handled by session/src/gb/sip. The returned `Tx` is an automatic
    /// transaction response, such as returning the previous response for a retransmitted request.
    pub fn rx_bytes(&self, association: SipAssociation, raw: &[u8]) -> Result<EndpointRxResult> {
        let msg = self.parse(raw)?;

        match &msg.kind {
            SipKind::Request { .. } => match self
                .tx_store
                .on_server_request(&association, &msg, self.server_tx_ttl)
            {
                Some(ServerTxDecision::New(_)) => Ok(EndpointRxResult::Event(SipEvent {
                    association,
                    kind: SipEventKind::Request(msg),
                })),
                Some(ServerTxDecision::DuplicateReturn(bytes)) => {
                    Ok(EndpointRxResult::Tx(SipTxPacket::new(association, bytes)))
                }
                Some(ServerTxDecision::DuplicateProcessing) => Ok(EndpointRxResult::Drop),
                Some(ServerTxDecision::ReplayConflict) => {
                    let bytes = build_response(
                        &self.runtime,
                        &msg,
                        ResponseOptions {
                            code: 400,
                            reason: "Bad Request",
                            user_agent: &self.user_agent,
                            body: None,
                            content_type: None,
                            extra_headers: Vec::new(),
                        },
                    )?;
                    Ok(EndpointRxResult::Tx(SipTxPacket::new(association, bytes)))
                }
                None => Err(PjError::InvalidSip(
                    "request cannot be converted into transaction key".into(),
                )),
            },
            SipKind::Response { .. } => Ok(EndpointRxResult::Event(SipEvent {
                association,
                kind: SipEventKind::Response(msg),
            })),
        }
    }

    pub fn store_response_for_request(&self, assoc: &SipAssociation, req: &SipMessage, resp: &[u8]) {
        if let Some(key) = crate::transaction::ServerTransactionKey::from_request(assoc, req) {
            self.tx_store.store_server_response(&key, resp.to_vec());
        }
    }
}
