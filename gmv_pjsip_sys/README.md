# gmv_pjsip_sys

Low-level Rust FFI bindings for PJPROJECT/PJSIP.

This crate intentionally stays at the sys layer:

- discovers an already installed/built PJPROJECT;
- emits Cargo link metadata;
- generates or copies `bindings.rs`;
- does not download PJPROJECT;
- does not decide the final application packaging strategy.

The safe API should live in `gmv_pjsip`. Application/session crates should not depend on raw pointers from this crate directly.

## Discovery priority

`build.rs` uses this priority:

1. `DOCS_RS` &mdash; copy `src/bindings.rs` placeholder.
2. `PJSIP_DLL_PATH` &mdash; explicit dynamic/import library path from the main app.
3. `PJSIP_LIBS_DIR` &mdash; explicit library directory from the main app.
4. `PJSIP_PKG_CONFIG_PATH` &mdash; explicit pkg-config directory from the main app.
5. default pkg-config probe for `libpjproject` >= 2.15.1.

`pkg-config` does not download dependencies. It only discovers an installed PJPROJECT package and returns compile/link metadata. Build or install PJPROJECT in the main workspace, CI image, Dockerfile, or bootstrap script.

## Environment variables

Only these variables are consumed:

```text
DOCS_RS
OUT_DIR
PJSIP_INCLUDE_DIR
PJSIP_DLL_PATH
PJSIP_PKG_CONFIG_PATH
PJSIP_LIBS_DIR
PJSIP_BINDING_PATH
```

There is deliberately no `PJSIP_LINK_MODE`. Static/dynamic behavior is controlled by the main application through the provided files, `.pc` metadata, and platform linker configuration.

## Recommended pkg-config setup

```toml
[env]
PJSIP_PKG_CONFIG_PATH = { value = "third_party/pjproject-2.17/dist/lib/pkgconfig", relative = true }
```

Optional include override for bindgen:

```toml
[env]
PJSIP_INCLUDE_DIR     = { value = "third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_PKG_CONFIG_PATH = { value = "third_party/pjproject-2.17/dist/lib/pkgconfig", relative = true }
```

## Manual split-static setup

```toml
[env]
PJSIP_INCLUDE_DIR = { value = "third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_LIBS_DIR    = { value = "third_party/pjproject-2.17/dist/lib", relative = true }
```

The build script scans split PJPROJECT static libraries such as:

```text
libpjsip-*.a
libpjsip-ua-*.a
libpjsip-simple-*.a
libpjlib-util-*.a
libpj-*.a
```

PJMEDIA and PJNATH are present in the link-order list, but their header includes and bindgen allowlists are commented until the safe layer needs them.

## Manual dynamic setup

Linux:

```toml
[env]
PJSIP_INCLUDE_DIR = { value = "third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_DLL_PATH    = { value = "third_party/pjproject-2.17/dist/lib/libpjproject.so", relative = true }
```

macOS:

```toml
[env]
PJSIP_INCLUDE_DIR = { value = "third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_DLL_PATH    = { value = "third_party/pjproject-2.17/dist/lib/libpjproject.dylib", relative = true }
```

Windows usually needs an import library path rather than only a `.dll` path:

```toml
[env]
PJSIP_INCLUDE_DIR = { value = "third_party/pjproject-2.17/dist/include", relative = true }
PJSIP_DLL_PATH    = { value = "third_party/pjproject-2.17/dist/lib/pjproject.lib", relative = true }
```

## Extending to PJNATH/PJMEDIA

To expose PJNATH/PJMEDIA later:

1. uncomment the corresponding headers in `wrapper.h`;
2. uncomment the corresponding allowlist lines in `build.rs`;
3. prefer pkg-config so system libraries selected by the PJPROJECT build are emitted correctly.

## PJSIP auth shim

This package also includes `shim.c`/`shim.h`, a tiny C shim around PJPROJECT's
Digest Authentication API. It exposes stable C functions for Rust so the safe
`gmv_pjsip` layer can call `pjsip_auth_create_digest2()` without depending on
bindgen's generated layout names for `pjsip_cred_info` and auth enum constants.

The shim supports MD5, SHA-256, and SHA-512-256 when the linked PJPROJECT build
supports them. The build script rejects pkg-config discovered PJPROJECT versions older than 2.15.1; PJPROJECT 2.17 is recommended. Full `pjsip_auth_srv_verify()` usage is kept as the next step once
`gmv_pjsip` retains `pjsip_rx_data`/`pjsip_tx_data` handles through parsing and
response generation.

## Native runtime prototype

`shim.h` also exposes version 1 of the `gmv_sip_*` C ABI. The prototype owns
PJLIB, a PJSIP endpoint, the transaction layer, IPv4 UDP/TCP listeners, and one
event-polling thread. Its lifecycle is:

```text
gmv_sip_runtime_config_init
gmv_sip_runtime_create
gmv_sip_runtime_start
gmv_sip_runtime_stop
gmv_sip_runtime_destroy
```

The current integration harness binds loopback random ports and verifies UDP
`OPTIONS` and TCP `MESSAGE` requests receive stateful `200 OK` responses. Event
callbacks report the request method, transport, response status, and raw
PJPROJECT status.

Prototype constraints:

- only one active runtime is supported per process;
- callback string views are borrowed and valid only during the callback;
- IPv4 UDP/TCP is supported; TLS and IPv6 are deferred;
- REGISTER authentication, dialogs, INVITE, SUBSCRIBE, and `session` backend
  switching are not part of this prototype.
