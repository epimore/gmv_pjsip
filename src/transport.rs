use std::fmt;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipTransport {
    Udp,
    Tcp,
    Tls,
}

impl SipTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        }
    }
}

impl fmt::Display for SipTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipAssociation {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub transport: SipTransport,
}

#[derive(Debug, Clone)]
pub struct SipTxPacket {
    pub association: SipAssociation,
    pub bytes: Vec<u8>,
}

impl SipTxPacket {
    pub fn new(association: SipAssociation, bytes: Vec<u8>) -> Self {
        Self { association, bytes }
    }
}

pub fn sent_by_from_addr(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

pub fn sip_uri_host_port(addr: SocketAddr) -> String {
    sent_by_from_addr(addr)
}
