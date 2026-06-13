use rand::{distributions::Alphanumeric, Rng};

pub const CONTENT_TYPE_MANSCDP_XML: &str = "Application/MANSCDP+xml";
pub const CONTENT_TYPE_MANSRTSP: &str = "Application/MANSRTSP";

pub fn next_sn() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

pub fn extract_xml_value_lossy(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

pub fn cmd_type_lossy(xml: &str) -> Option<String> {
    extract_xml_value_lossy(xml, "CmdType")
}

pub fn device_id_lossy(xml: &str) -> Option<String> {
    extract_xml_value_lossy(xml, "DeviceID")
}

pub fn session_id_lossy(xml: &str) -> Option<String> {
    extract_xml_value_lossy(xml, "SessionID")
}

pub fn build_preset_query_xml(device_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n<Query>\r\n<CmdType>PresetQuery</CmdType>\r\n<SN>{}</SN>\r\n<DeviceID>{}</DeviceID>\r\n</Query>\r\n",
        next_sn(),
        device_id
    )
}

pub fn build_snapshot_control_xml(
    channel_id: &str,
    snap_num: u8,
    interval: u8,
    upload_url: &str,
    session_id: &str,
) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n<Control>\r\n<CmdType>DeviceConfig</CmdType>\r\n<SN>{}</SN>\r\n<DeviceID>{}</DeviceID>\r\n<SnapShotConfig>\r\n<SnapNum>{}</SnapNum>\r\n<Interval>{}</Interval>\r\n<UploadURL>{}</UploadURL>\r\n<SessionID>{}</SessionID>\r\n</SnapShotConfig>\r\n</Control>\r\n",
        next_sn(),
        channel_id,
        snap_num,
        interval,
        upload_url,
        session_id
    )
}

pub fn build_mansrtsp_seek_body(seek_second: f64, rtsp_cseq: u32) -> String {
    format!(
        "PLAY RTSP/1.0\r\nCSeq: {}\r\nRange: npt={:.3}-\r\n\r\n",
        rtsp_cseq,
        seek_second.max(0.0)
    )
}

pub fn build_mansrtsp_speed_body(
    scale: f32,
    range_start_second: Option<f64>,
    rtsp_cseq: u32,
) -> String {
    let mut body = format!("PLAY RTSP/1.0\r\nCSeq: {rtsp_cseq}\r\nScale: {scale:.3}\r\n");
    if let Some(start) = range_start_second {
        body.push_str(&format!("Range: npt={:.3}-\r\n", start.max(0.0)));
    }
    body.push_str("\r\n");
    body
}
