use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SipTransportProtocol {
    Udp,
    Tcp,
    Tls,
}

impl SipTransportProtocol {
    pub fn as_sip_token(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SipAssociation {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: SipTransportProtocol,
}

#[derive(Clone, Debug)]
pub struct SipPacketMeta {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: SipTransportProtocol,
    pub received_at: Instant,
}

#[derive(Clone, Debug)]
pub struct SipRxPacket {
    pub bytes: Bytes,
    pub meta: SipPacketMeta,
}

#[derive(Clone, Debug)]
pub struct SipTxPacket {
    pub bytes: Bytes,
    pub association: SipAssociation,
}

impl SipPacketMeta {
    pub fn association(&self) -> SipAssociation {
        SipAssociation {
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            protocol: self.protocol,
        }
    }
}
