use gmv_pjsip::{parse_sip_message, PjRuntime};

fn main() -> anyhow::Result<()> {
    let _rt = PjRuntime::init()?;
    let raw = b"OPTIONS sip:34020000002000000001@127.0.0.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
From: <sip:34020000001320000001@127.0.0.1>;tag=1\r\n\
To: <sip:34020000002000000001@127.0.0.1>\r\n\
Call-ID: test-call\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

    let kind = parse_sip_message(raw)?;
    println!("parsed: {kind:?}");
    Ok(())
}
