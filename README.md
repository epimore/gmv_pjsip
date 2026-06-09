# gmv PJSIP bootstrap + Rust binding skeleton

This package contains:

- `scripts/build_pjsip_bootstrap.sh`: downloads pjproject into `third_party/`, builds static libraries, installs to `dist/`.
- `crates/gmv_pjsip_sys`: low-level bindgen crate, similar in spirit to `rsmpeg`'s FFI layer.
- `crates/gmv_pjsip`: safe wrapper entry point for GB28181-oriented SIP code.

## Install pjproject

From your gmv repo root:

```bash
chmod +x scripts/build_pjsip_bootstrap.sh
PJSIP_VERSION=2.17 ./scripts/build_pjsip_bootstrap.sh
export PJSIP_ROOT="$PWD/third_party/pjproject-2.17/dist"
```

## Cargo workspace

Add to root `Cargo.toml`:

```toml
[workspace]
members = [
  "crates/gmv_pjsip_sys",
  "crates/gmv_pjsip",
]
```

Then build:

```bash
cargo build -p gmv_pjsip_sys
cargo build -p gmv_pjsip
```

## Important

This is a binding skeleton, not a finished GB28181 SIP stack. The next layer should expose
high-level APIs such as:

- `build_invite_play()`
- `build_ack_for_invite_2xx()`
- `build_bye()`
- `parse_response()`
- `parse_request()`
- `SipDialogContext`
- `InviteClientTransaction`

Do not let `unsafe` PJSIP pointers leak into `gmv_session`.
