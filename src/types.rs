use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(pub String);
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(pub String);
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallId(pub String);
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SipUri(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CSeq {
    pub number: u32,
    pub method: String,
}

impl fmt::Display for DeviceId { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) } }
impl fmt::Display for StreamId { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) } }
impl fmt::Display for CallId { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) } }
impl fmt::Display for SipUri { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) } }
