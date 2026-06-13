# gmv_pjsip

`gmv_pjsip` is GMV's safe GB28181 runtime over PJSIP 2.17.

```text
session Rust IO  -> UDP datagrams / TCP chunks
gmv_pjsip        -> owned commands, events, and send completions
gmv_pjsip_sys    -> versioned C shim and PJSIP custom transport
PJSIP            -> parser, transaction, dialog, INVITE, auth, and evsub
```

Rust owns network sockets and TCP associations. The PJSIP owner thread receives
owned packet data through `pjsip_tpmgr_receive_packet()`. PJSIP outbound
`send_msg()` calls are copied into `SipTransmit`; Rust IO reports the final
write result with `SipRuntime::complete_send`.

## Runtime coverage

- UDP datagrams and fragmented/coalesced TCP chunks.
- REGISTER Digest challenge, asynchronous credential lookup, refresh, and
  unregister.
- Stateful inbound and outbound MESSAGE and OPTIONS.
- UAC/UAS INVITE, provisional/final responses, ACK, CANCEL, BYE, and dialog
  INFO. The safe UAS API currently exposes non-success final responses only.
- SUBSCRIBE establish, refresh, unsubscribe, and NOTIFY.
- Owned runtime events with operation, association, Call-ID, CSeq, tag, event,
  subscription-state, content type, and body metadata.
- Ordered transport close, pending send completion, and runtime shutdown;
  session completes pending business waiters with 503 during shutdown.

`SipRuntime` is intentionally `!Send` and `!Sync`. Creation, polling, all PJSIP
operations, stop, and destroy must stay on the owner thread. Tokio tasks use
bounded command/event channels and never retain PJSIP pointers.

## Build configuration

Use the project-controlled PJPROJECT build:

```toml
[env]
PJSIP_INCLUDE_DIR = { value = "../gmv/third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_LIBS_DIR    = { value = "../gmv/third_party/pjproject-2.17/dist/lib", relative = true }
```

`session/build_pjsip_bootstrap.sh` builds the pinned source archive. Generated
`dist/`, bindings, and machine-local configure outputs must not be committed.

Prototype capacity defaults are:

- runtime and SIP IO channel capacity: 32,768;
- pending REGISTER auth: 20,000;
- maximum SIP packet: 65,535 bytes;
- maximum PJSIP transports: 32,768.

## Safe API

The safe layer exports:

- `SipRuntime::receive_packet`, `close_transport`, and `complete_send`;
- `send_message`, `send_invite`, `send_dialog_request`, `respond_invite`, and
  `send_subscribe`;
- `complete_auth_lookup`;
- owned `SipRuntimeEvent` and `SipTransmit` receivers.

GB28181 XML and SDP helpers remain in Rust. Session/business code must not
manually compose Via, From/To tags, Call-ID, CSeq, branch, Contact, ACK, BYE, or
in-dialog INFO headers.

## Verification

```bash
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```
