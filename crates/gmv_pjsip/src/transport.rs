//! Transport bridge types between gmv Tokio IO and the SIP core.
//!
//! This crate does not bind sockets. The caller owns UDP/TCP IO and passes
//! received bytes into `SipEndpoint::rx_bytes()`. Outbound bytes are queued as
//! `SipTxPacket` values and the caller writes them through its existing IO.

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::error::{poisoned, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipTransportProtocol {
    Udp,
    Tcp,
    Tls,
}

impl fmt::Display for SipTransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipTransportProtocol::Udp => f.write_str("UDP"),
            SipTransportProtocol::Tcp => f.write_str("TCP"),
            SipTransportProtocol::Tls => f.write_str("TLS"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipAssociation {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: SipTransportProtocol,
}

impl SipAssociation {
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        protocol: SipTransportProtocol,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            protocol,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SipRxPacket {
    pub association: SipAssociation,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SipTxPacket {
    pub association: SipAssociation,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct TransportBridge {
    tx_queue: Mutex<VecDeque<SipTxPacket>>,
}

impl TransportBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&self, packet: SipTxPacket) -> Result<()> {
        let mut q = self
            .tx_queue
            .lock()
            .map_err(|_| poisoned("TransportBridge.tx_queue"))?;
        q.push_back(packet);
        Ok(())
    }

    pub fn drain(&self) -> Result<Vec<SipTxPacket>> {
        let mut q = self
            .tx_queue
            .lock()
            .map_err(|_| poisoned("TransportBridge.tx_queue"))?;

        Ok(q.drain(..).collect())
    }
}
