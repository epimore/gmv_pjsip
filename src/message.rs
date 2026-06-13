use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Ack,
    Bye,
    Cancel,
    Info,
    Invite,
    Message,
    Notify,
    Options,
    Prack,
    Publish,
    Refer,
    Register,
    Subscribe,
    Update,
    Other(String),
}

impl SipMethod {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "ACK" => Self::Ack,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "INFO" => Self::Info,
            "INVITE" => Self::Invite,
            "MESSAGE" => Self::Message,
            "NOTIFY" => Self::Notify,
            "OPTIONS" => Self::Options,
            "PRACK" => Self::Prack,
            "PUBLISH" => Self::Publish,
            "REFER" => Self::Refer,
            "REGISTER" => Self::Register,
            "SUBSCRIBE" => Self::Subscribe,
            "UPDATE" => Self::Update,
            _ => Self::Other(value.trim().to_ascii_uppercase()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Info => "INFO",
            Self::Invite => "INVITE",
            Self::Message => "MESSAGE",
            Self::Notify => "NOTIFY",
            Self::Options => "OPTIONS",
            Self::Prack => "PRACK",
            Self::Publish => "PUBLISH",
            Self::Refer => "REFER",
            Self::Register => "REGISTER",
            Self::Subscribe => "SUBSCRIBE",
            Self::Update => "UPDATE",
            Self::Other(value) => value,
        }
    }
}

impl fmt::Display for SipMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SipMethod {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(value))
    }
}

pub fn extract_tag(value: &str) -> Option<String> {
    extract_param(value, "tag")
}

pub fn extract_param(value: &str, key: &str) -> Option<String> {
    for part in value.split(';').skip(1) {
        let mut fields = part.trim().splitn(2, '=');
        let name = fields.next()?.trim();
        let value = fields.next().unwrap_or("").trim().trim_matches('"');
        if name.eq_ignore_ascii_case(key) {
            return Some(value.to_string());
        }
    }
    None
}

pub fn extract_uri(value: &str) -> Option<String> {
    let value = value.trim();
    if let (Some(start), Some(end)) = (value.find('<'), value.find('>')) {
        if end > start + 1 {
            return Some(value[start + 1..end].trim().to_string());
        }
    }
    let end = value.find(';').unwrap_or(value.len());
    let uri = value[..end].trim();
    (!uri.is_empty()).then(|| uri.to_string())
}

#[cfg(test)]
mod tests {
    use super::{extract_tag, extract_uri, SipMethod};

    #[test]
    fn parses_business_method_and_header_values() {
        assert_eq!(SipMethod::parse("notify"), SipMethod::Notify);
        assert_eq!(
            extract_tag("<sip:device@example.com>;tag=remote"),
            Some("remote".into())
        );
        assert_eq!(
            extract_uri("\"Device\" <sip:device@example.com>;expires=3600"),
            Some("sip:device@example.com".into())
        );
    }
}
