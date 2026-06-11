# gmv_pjsip

`gmv_pjsip` is the GB28181-oriented SIP context layer used by GMV.

Layering:

```text
gmv_pjsip_sys  -> raw PJPROJECT/PJSIP FFI and auth shim
gmv_pjsip      -> safe SIP parser/builder/context/dialog/transaction API
session         -> business logic; does not build SIP headers manually
```

## Current mid-term capabilities

- REGISTER digest challenge/verify and registration binding context.
- MESSAGE handling and automatic 200 OK response.
- INVITE dialog/call context and ACK/BYE generation.
- In-dialog INFO safe API for playback seek/speed.
- Talk-specific INVITE + SDP helpers.
- Snapshot/preset helper APIs:
  - PresetQuery MESSAGE body generation.
  - SnapShotConfig MESSAGE body generation.
  - UploadSnapShotFinished event extraction with `snapshot_session_id`.
- Timed cleanup of transactions, registers, dialogs, calls, and nonce cache.

## Build configuration

Prefer project-controlled PJPROJECT 2.17+ builds:

```toml
[env]
PJSIP_INCLUDE_DIR = { value = "../gmv/third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_LIBS_DIR    = { value = "../gmv/third_party/pjproject-2.17/dist/lib", relative = true }
```

`pkg-config` is also supported. If no explicit environment variables are set,
`gmv_pjsip_sys` probes `libpjproject` through the default pkg-config path.

## New business APIs

Playback seek/speed should use:

```rust
SipContext::create_playback_seek_info(...)
SipContext::create_playback_speed_info(...)
```

Talk should use:

```rust
SipContext::create_talk_invite(...)
```

Preset snapshot support should use:

```rust
SipContext::create_preset_query_message(...)
SipContext::create_snapshot_control_message(...)
```

Incoming snapshot completion is delivered as:

```rust
SipEvent::Message(MessageEvent {
    kind: MessageKind::UploadSnapshotFinished,
    snapshot_session_id: Some(...),
    ..
})
```

## Notes

`gmv_pjsip` owns SIP context. Session/business code should not manually compose
Via, From/To tag, Call-ID, CSeq, branch, Contact, ACK, BYE, or in-dialog INFO
headers.


## SIP method coverage

The safe layer recognizes the standard method set used by GB28181 and common SIP extensions: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE. See `SIP_METHODS.md` for response policy and extension handling.
