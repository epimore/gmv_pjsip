use bytes::Bytes;

use crate::context::{DialogId, SipContext};
use crate::gb28181::sdp::{SdpInfo, TalkAudioCodec, TalkSdpMode};
use crate::transport::{SipAssociation, SipPacketMeta, SipTransportProtocol};
use crate::error::{Result, SipError};
use crate::message::SipMethod;

pub type SipEndpoint = SipContext;

#[derive(Clone, Debug)]
pub enum SipAction {
    Send(Bytes),
    SendMany(Vec<Bytes>),
    Event(SipEvent),
    SendAndEvent { bytes: Bytes, event: SipEvent },
    SendManyAndEvent { bytes: Vec<Bytes>, event: SipEvent },
    Ignore,
    DropDuplicate,
}

impl SipAction {
    pub fn first_tx_bytes(&self) -> Option<&Bytes> {
        match self {
            SipAction::Send(b) => Some(b),
            SipAction::SendMany(v) => v.first(),
            SipAction::SendAndEvent { bytes, .. } => Some(bytes),
            SipAction::SendManyAndEvent { bytes, .. } => bytes.first(),
            _ => None,
        }
    }

    pub fn into_output(self, association: SipAssociation) -> SipOutput {
        let mut sends = Vec::new();
        let mut event = None;
        match self {
            SipAction::Send(b) => sends.push((association, b)),
            SipAction::SendMany(v) => sends.extend(v.into_iter().map(|b| (association.clone(), b))),
            SipAction::Event(e) => event = Some(e),
            SipAction::SendAndEvent { bytes, event: e } => { sends.push((association, bytes)); event = Some(e); }
            SipAction::SendManyAndEvent { bytes, event: e } => {
                sends.extend(bytes.into_iter().map(|b| (association.clone(), b)));
                event = Some(e);
            }
            SipAction::Ignore | SipAction::DropDuplicate => {}
        }
        SipOutput { sends, event }
    }
}

#[derive(Clone, Debug)]
pub struct SipOutput {
    pub sends: Vec<(SipAssociation, Bytes)>,
    pub event: Option<SipEvent>,
}

#[derive(Clone, Debug)]
pub enum SipEvent {
    Register(RegisterEvent),
    Message(MessageEvent),
    IncomingInvite(IncomingInviteEvent),
    InviteProceeding { call_id: String, status: u16 },
    InviteAccepted(InviteAcceptedEvent),
    InviteFailed { call_id: String, status: u16 },
    InfoProceeding { call_id: String, status: u16 },
    InfoAccepted { call_id: String, status: u16 },
    InfoFailed { call_id: String, status: u16 },
    Ack(AckEvent),
    Bye(ByeEvent),
    ByeConfirmed(ByeEvent),
    Cancel(CancelEvent),
    StandardRequest(StandardRequestEvent),
    StandardResponse(StandardResponseEvent),
}


#[derive(Clone, Debug)]
pub struct StandardRequestEvent {
    pub method: SipMethod,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
    pub association: SipAssociation,
    pub content_type: Option<String>,
    pub body: Bytes,
}

#[derive(Clone, Debug)]
pub struct StandardResponseEvent {
    pub method: SipMethod,
    pub call_id: String,
    pub status: u16,
}

#[derive(Clone, Debug)]
pub struct RegisterEvent {
    pub device_id: String,
    pub contact: Option<String>,
    pub expires: u32,
    pub authorized: bool,
    pub username: Option<String>,
    pub association: SipAssociation,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Keepalive,
    Catalog,
    DeviceInfo,
    RecordInfo,
    Alarm,
    MediaStatus,
    DeviceControl,
    DeviceConfig,
    PresetQuery,
    UploadSnapshotFinished,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct MessageEvent {
    pub kind: MessageKind,
    pub device_id: Option<String>,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
    pub association: SipAssociation,
    pub content_type: Option<String>,
    pub cmd_type: Option<String>,
    /// GB28181 snapshot upload Notify carries SessionID. Session layer can use
    /// this key to wake the snapshot waiter without reparsing SIP headers.
    pub snapshot_session_id: Option<String>,
    pub body: Bytes,
}

#[derive(Clone, Debug)]
pub struct IncomingInviteEvent {
    pub call_id: String,
    pub dialog_id: DialogId,
    pub association: SipAssociation,
    pub remote_sdp: String,
    pub from: String,
    pub to: String,
    pub subject: Option<String>,
}

#[derive(Clone, Debug)]
pub struct InviteAcceptedEvent {
    pub call_id: String,
    pub dialog_id: DialogId,
    pub device_id: String,
    pub channel_id: String,
    pub stream_id: String,
    pub ssrc: Option<u32>,
    pub remote_contact: Option<String>,
    pub remote_sdp: String,
    pub sdp_info: SdpInfo,
}

#[derive(Clone, Debug)]
pub struct AckEvent { pub call_id: String }

#[derive(Clone, Debug)]
pub struct ByeEvent {
    pub call_id: String,
    pub stream_id: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CancelEvent { pub call_id: String }

#[derive(Clone, Debug)]
pub struct CreateInvite {
    pub device_id: String,
    pub channel_id: String,
    pub stream_id: String,
    pub target_uri: String,
    pub sdp: String,
    pub ssrc: Option<u32>,
    pub protocol: SipTransportProtocol,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
    pub subject: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CreateTalkInvite {
    pub device_id: String,
    pub channel_id: String,
    /// Business id used by session/talk layer. Stored in InviteCall.stream_id.
    pub talk_id: String,
    pub target_uri: String,
    pub media_ip: String,
    pub media_port: u16,
    pub ssrc: Option<u32>,
    pub payload_type: u8,
    pub codec: TalkAudioCodec,
    pub mode: TalkSdpMode,
    pub protocol: SipTransportProtocol,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
    pub subject: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CreateBye {
    pub call_id: Option<String>,
    pub stream_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CreateMessage {
    pub target_uri: String,
    pub body: Bytes,
    pub content_type: String,
    pub protocol: SipTransportProtocol,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CreateInfo {
    pub call_id: Option<String>,
    pub stream_id: Option<String>,
    pub body: Bytes,
    pub content_type: String,
    pub extra_headers: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct CreatePlaybackSeekInfo {
    pub call_id: Option<String>,
    pub stream_id: Option<String>,
    pub seek_second: f64,
    pub rtsp_cseq: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CreatePlaybackSpeedInfo {
    pub call_id: Option<String>,
    pub stream_id: Option<String>,
    pub scale: f32,
    pub range_start_second: Option<f64>,
    pub rtsp_cseq: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CreatePresetQueryMessage {
    pub target_uri: String,
    pub device_id: String,
    pub protocol: SipTransportProtocol,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CreateSnapshotControlMessage {
    pub target_uri: String,
    pub channel_id: String,
    pub snap_num: u8,
    pub interval: u8,
    pub upload_url: String,
    pub session_id: String,
    pub protocol: SipTransportProtocol,
    pub call_id: Option<String>,
    pub cseq: Option<u32>,
}

impl SipContext {
    pub fn handle_rx_packet(&self, bytes: Bytes, meta: SipPacketMeta) -> Result<SipOutput> {
        let association = meta.association();
        let action = self.on_packet(bytes, meta)?;
        Ok(action.into_output(association))
    }

    pub fn require_call_id(call_id: Option<String>) -> Result<String> {
        call_id.ok_or_else(|| SipError::CallNotFound("missing call-id".into()))
    }
}
