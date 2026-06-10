# gmv_pjsip

`gmv_pjsip` is a GB28181-oriented SIP context library built around PJPROJECT/PJSIP.
It is intended to sit between GMV's async IO/session layer and the low-level
`gmv_pjsip_sys` FFI bindings.

## Crates

- `gmv_pjsip_sys`: low-level PJPROJECT/PJSIP bindgen crate.
- `gmv_pjsip`: safe SIP parsing, response/request building, REGISTER/MESSAGE/INVITE/BYE context, transaction de-duplication, dialog state, and digest-auth helpers.

## Build model

`gmv_pjsip_sys` does **not** download PJPROJECT. The main application, CI image,
Dockerfile, or bootstrap script should build/install PJPROJECT and then expose it
to Cargo through one of these mechanisms:

```toml
# .cargo/config.toml in the main application, not committed by this library.
[env]
PJSIP_INCLUDE_DIR = { value = "third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_LIBS_DIR    = { value = "third_party/pjproject-2.17/dist/lib", relative = true }
```

or:

```toml
[env]
PJSIP_PKG_CONFIG_PATH = { value = "third_party/pjproject-2.17/dist/lib/pkgconfig", relative = true }
```

Supported environment variables:

- `PJSIP_INCLUDE_DIR`
- `PJSIP_DLL_PATH`
- `PJSIP_PKG_CONFIG_PATH`
- `PJSIP_LIBS_DIR`
- `PJSIP_BINDING_PATH`

Priority:

```text
PJSIP_DLL_PATH > PJSIP_LIBS_DIR > PJSIP_PKG_CONFIG_PATH > system pkg-config
```

`pkg-config` is only a discovery mechanism. It does not download dependencies.
The default `pkg-config` path requires `libpjproject >= 2.15.1`; PJPROJECT 2.17
is recommended for GMV.

## Runtime boundary

`session` should depend on `gmv_pjsip`, not `gmv_pjsip_sys`.

Recommended flow:

```text
io.rs receives bytes
  -> SipContext::handle_rx_packet(bytes, meta)
  -> SipAction / SipEvent
  -> GMV session handles business events
  -> io.rs sends SipOutput bytes
```

SIP header correctness, Call-ID/CSeq/tag/branch generation, transaction replay,
REGISTER bindings, Dialog state, INVITE/ACK/BYE state, and digest helpers are
centralized in this crate.

## Authentication status

The production path uses PJSIP digest calculation through `gmv_pjsip_sys` shim
functions. A pure Rust MD5 fallback is kept for tests or builds without
PJPROJECT by disabling default features.

Full `pjsip_auth_srv_verify()` / `pjsip_auth_srv_challenge2()` integration is a
future step because it requires retaining live `pjsip_rx_data` / `pjsip_tx_data`
objects across the parser/auth/builder boundary.

## Tests

With PJPROJECT available:

```bash
cargo test
```

Without PJPROJECT, run the Rust-only flow tests with the fallback digest path:

```bash
cargo test --no-default-features
```
