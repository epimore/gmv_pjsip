#[derive(Clone, Debug, Default)]
pub struct SdpInfo {
    pub session_name: Option<String>,
    pub connection_addr: Option<String>,
    pub media_port: Option<u16>,
    pub media_proto: Option<String>,
    pub media_payloads: Vec<String>,
    pub ssrc: Option<String>,
    pub raw: String,
}

impl SdpInfo {
    pub fn parse_lossy(sdp: &str) -> Self {
        let mut out = SdpInfo { raw: sdp.to_string(), ..Default::default() };
        for line in sdp.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("s=") {
                out.session_name = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("c=") {
                out.connection_addr = v.split_whitespace().last().map(ToOwned::to_owned);
            } else if let Some(v) = line.strip_prefix("m=") {
                let parts: Vec<_> = v.split_whitespace().collect();
                if parts.len() >= 3 {
                    out.media_port = parts[1].parse().ok();
                    out.media_proto = Some(parts[2].to_string());
                    out.media_payloads = parts.iter().skip(3).map(|s| s.to_string()).collect();
                }
            } else if let Some(v) = line.strip_prefix("y=") {
                out.ssrc = Some(v.to_string());
            }
        }
        out
    }
}

#[derive(Clone, Debug)]
pub struct PlaySdpOptions {
    pub ip: String,
    pub port: u16,
    pub ssrc: u32,
    pub payload_type: u8,
}

pub fn build_play_sdp(opts: PlaySdpOptions) -> String {
    format!(
        "v=0\r\no={} 0 0 IN IP4 {}\r\ns=Play\r\nc=IN IP4 {}\r\nt=0 0\r\nm=video {} RTP/AVP {}\r\na=recvonly\r\na=rtpmap:{} PS/90000\r\ny={}\r\n",
        opts.ssrc, opts.ip, opts.ip, opts.port, opts.payload_type, opts.payload_type, opts.ssrc
    )
}
