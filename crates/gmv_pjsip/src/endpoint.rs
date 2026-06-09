//! Main safe endpoint facade used by `session`.
//!
//! `io.rs` should call `rx_bytes()` and then handle emitted events. When
//! business code decides a response/request must be sent, call the builder
//! helpers and `queue_tx()` / `drain_tx()`.

use std::sync::Arc;

use crate::builder::{self, ResponseOptions};
use crate::dialog::{DialogStore, InviteDialog};
use crate::error::{PjError, Result};
use crate::message::SipMessageView;
use crate::runtime::PjRuntime;
use crate::transaction::{ClientTxDecision, ClientTxKey, ServerTxDecision, ServerTxKey, TransactionStore};
use crate::transport::{SipAssociation, SipTxPacket, TransportBridge};

#[derive(Debug, Clone)]
pub struct SipEndpointConfig {
    pub user_agent: String,
}

impl Default for SipEndpointConfig {
    fn default() -> Self {
        Self {
            user_agent: "Gmv PJSIP".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SipEndpoint {
    runtime: PjRuntime,
    config: SipEndpointConfig,
    transactions: Arc<TransactionStore>,
    dialogs: Arc<DialogStore>,
    transport: Arc<TransportBridge>,
}

#[derive(Debug, Clone)]
pub enum SipEvent {
    IncomingRequest {
        association: SipAssociation,
        tx_key: ServerTxKey,
        message: SipMessageView,
    },
    IncomingResponse {
        association: SipAssociation,
        tx_key: Option<ClientTxKey>,
        message: SipMessageView,
    },
    DuplicateRequestResponse {
        association: SipAssociation,
        bytes: Vec<u8>,
    },
    DuplicateInvite2xxAck {
        association: SipAssociation,
        bytes: Vec<u8>,
    },
    ReplayedRequest {
        association: SipAssociation,
        message: SipMessageView,
    },
    UnknownResponse {
        association: SipAssociation,
        message: SipMessageView,
    },
}

impl SipEndpoint {
    pub fn new(runtime: PjRuntime, config: SipEndpointConfig) -> Self {
        Self {
            runtime,
            config,
            transactions: Arc::new(TransactionStore::new()),
            dialogs: Arc::new(DialogStore::new()),
            transport: Arc::new(TransportBridge::new()),
        }
    }

    pub fn user_agent(&self) -> &str {
        &self.config.user_agent
    }

    pub fn transactions(&self) -> Arc<TransactionStore> {
        Arc::clone(&self.transactions)
    }

    pub fn dialogs(&self) -> Arc<DialogStore> {
        Arc::clone(&self.dialogs)
    }

    pub fn rx_bytes(&self, association: SipAssociation, bytes: &[u8]) -> Result<Vec<SipEvent>> {
        let message = SipMessageView::parse(&self.runtime, bytes)?;

        if message.is_request() {
            match self.transactions.on_request(&association, &message)? {
                ServerTxDecision::New(tx_key) => Ok(vec![SipEvent::IncomingRequest {
                    association,
                    tx_key,
                    message,
                }]),
                ServerTxDecision::DuplicateReturnLastResponse(bytes) => {
                    Ok(vec![SipEvent::DuplicateRequestResponse { association, bytes }])
                }
                ServerTxDecision::DuplicateNoResponse => Ok(Vec::new()),
                ServerTxDecision::ReplayedReject => Ok(vec![SipEvent::ReplayedRequest {
                    association,
                    message,
                }]),
            }
        } else {
            match self.transactions.on_response(&message)? {
                ClientTxDecision::Matched(tx_key) => Ok(vec![SipEvent::IncomingResponse {
                    association,
                    tx_key: Some(tx_key),
                    message,
                }]),
                ClientTxDecision::DuplicateInvite2xxAck(bytes) => {
                    Ok(vec![SipEvent::DuplicateInvite2xxAck { association, bytes }])
                }
                ClientTxDecision::Unknown => Ok(vec![SipEvent::UnknownResponse {
                    association,
                    message,
                }]),
            }
        }
    }

    pub fn complete_request(
        &self,
        association: SipAssociation,
        tx_key: &ServerTxKey,
        response: Vec<u8>,
    ) -> Result<()> {
        self.transactions
            .store_server_response(tx_key, response.clone())?;
        self.queue_tx(SipTxPacket {
            association,
            bytes: response,
        })
    }

    pub fn build_and_complete_response(
        &self,
        association: SipAssociation,
        tx_key: &ServerTxKey,
        req: &SipMessageView,
        opt: ResponseOptions<'_>,
    ) -> Result<()> {
        let response = builder::build_response(req, opt)?;
        self.complete_request(association, tx_key, response)
    }

    pub fn queue_tx(&self, packet: SipTxPacket) -> Result<()> {
        self.transport.enqueue(packet)
    }

    pub fn drain_tx(&self) -> Result<Vec<SipTxPacket>> {
        self.transport.drain()
    }

    pub fn register_client_request(
        &self,
        association: SipAssociation,
        key: ClientTxKey,
        request: Vec<u8>,
    ) -> Result<()> {
        self.transactions.insert_client_request(key, request.clone())?;
        self.queue_tx(SipTxPacket {
            association,
            bytes: request,
        })
    }

    pub fn insert_early_dialog(&self, dialog: InviteDialog) -> Result<()> {
        self.dialogs.insert_early(dialog)
    }

    /// Handle a 2xx response for a UAC INVITE: confirm dialog and generate ACK.
    ///
    /// Caller should invoke this after receiving `SipEvent::IncomingResponse`
    /// whose CSeq method is INVITE and status is 2xx.
    pub fn confirm_invite_and_queue_ack(
        &self,
        association: SipAssociation,
        resp: &SipMessageView,
        client_tx_key: &ClientTxKey,
    ) -> Result<InviteDialog> {
        let call_id = resp
            .call_id()
            .ok_or_else(|| PjError::Dialog("2xx response missing Call-ID".to_string()))?;
        let dialog = self.dialogs.confirm_early_from_2xx(call_id, resp)?;
        let ack = dialog.ack_for_2xx(self.user_agent())?;
        self.transactions.store_invite_ack(client_tx_key, ack.clone())?;
        self.queue_tx(SipTxPacket {
            association,
            bytes: ack,
        })?;
        Ok(dialog)
    }

    pub fn expire_transactions(&self) -> Result<()> {
        self.transactions.expire()
    }
}
