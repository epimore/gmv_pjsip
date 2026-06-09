#!/usr/bin/env bash
set -euo pipefail

# Minimal PJSIP/pjproject static build bootstrap for gmv developers.
# - Downloads pjproject source into gmv/third_party
# - Builds static libs
# - Installs into <source>/dist
#
# Env:
#   PJSIP_VERSION=2.17
#   JOBS=$(nproc)
#   FORCE_REDOWNLOAD=0|1
#   DISABLE_SSL=1|0
#   HOST=<configure-host>              # optional cross compile host, e.g. aarch64-linux-gnu
#   CC/CXX/AR/RANLIB/STRIP=...          # optional toolchain variables

PJSIP_VERSION="${PJSIP_VERSION:-2.17}"
JOBS="${JOBS:-$(nproc)}"
FORCE_REDOWNLOAD="${FORCE_REDOWNLOAD:-0}"
DISABLE_SSL="${DISABLE_SSL:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GMV_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
THIRD_PARTY_DIR="$GMV_ROOT/third_party"
SRC_DIR="$THIRD_PARTY_DIR/pjproject-${PJSIP_VERSION}"
ARCHIVE_PATH="$THIRD_PARTY_DIR/pjproject-${PJSIP_VERSION}.tar.gz"
PREFIX="$SRC_DIR/dist"

SRC_URL="https://github.com/pjsip/pjproject/archive/refs/tags/${PJSIP_VERSION}.tar.gz"

CONFIGURE_EXTRA=()
if [[ -n "${HOST:-}" ]]; then
  CONFIGURE_EXTRA+=("--host=$HOST")
fi
if [[ "$DISABLE_SSL" == "1" ]]; then
  CONFIGURE_EXTRA+=("--disable-ssl")
fi

echo "== PJSIP/pjproject bootstrap build =="
echo "gmv root:   $GMV_ROOT"
echo "version:    $PJSIP_VERSION"
echo "source dir: $SRC_DIR"
echo "prefix:     $PREFIX"
echo "jobs:       $JOBS"
echo "disable ssl:$DISABLE_SSL"
echo

mkdir -p "$THIRD_PARTY_DIR"

if [[ "$FORCE_REDOWNLOAD" == "1" ]]; then
  echo "[0/9] force cleanup existing source/archive"
  rm -rf "$SRC_DIR"
  rm -f "$ARCHIVE_PATH"
fi

if [[ ! -f "$SRC_DIR/configure" ]]; then
  echo "[1/9] download source"
  if [[ ! -f "$ARCHIVE_PATH" ]]; then
    curl -fL "$SRC_URL" -o "$ARCHIVE_PATH"
  else
    echo "archive already exists: $ARCHIVE_PATH"
  fi

  echo "[2/9] extract source"
  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  tar -xf "$ARCHIVE_PATH" --strip-components=1 -C "$SRC_DIR"
else
  echo "[1/9] source already present, skip download"
fi

cd "$SRC_DIR"

if [[ ! -f configure ]]; then
  echo "[FATAL] configure not found in $SRC_DIR"
  exit 1
fi

echo "[3/9] write pjlib/include/pj/config_site.h"
cat > pjlib/include/pj/config_site.h <<'CFG'
#pragma once

/* gmv uses pjproject for SIP signaling only. Media/RTP pipeline stays in Rust. */
#define PJ_HAS_IPV6 1
#define PJ_IOQUEUE_MAX_HANDLES 4096
#define PJ_IOQUEUE_HAS_SAFE_UNREG 1
#define PJ_ENABLE_EXTRA_CHECK 0
#define PJSIP_MAX_PKT_LEN 65535
#define PJSIP_MAX_URL_SIZE 512
#define PJSIP_MAX_MODULE 64

/* Reduce footprint: keep SIP/SDP, avoid unused media features where possible. */
#define PJMEDIA_HAS_VIDEO 0
#define PJMEDIA_HAS_SRTP 0
#define PJMEDIA_HAS_SPEEX_CODEC 0
#define PJMEDIA_HAS_SPEEX_AEC 0
#define PJMEDIA_HAS_GSM_CODEC 0
#define PJMEDIA_HAS_ILBC_CODEC 0
#define PJMEDIA_HAS_L16_CODEC 0
#define PJMEDIA_HAS_G722_CODEC 0
#define PJMEDIA_HAS_G7221_CODEC 0
#define PJMEDIA_HAS_OPENCORE_AMRNB_CODEC 0
#define PJMEDIA_HAS_OPENCORE_AMRWB_CODEC 0
#define PJMEDIA_HAS_WEBRTC_AEC 0
#define PJMEDIA_AUDIO_DEV_HAS_PORTAUDIO 0
#define PJMEDIA_AUDIO_DEV_HAS_ALSA 0
#define PJMEDIA_AUDIO_DEV_HAS_NULL_AUDIO 1
CFG

echo "[4/9] clean old build/install"
make distclean >/dev/null 2>&1 || true
rm -rf "$PREFIX"
mkdir -p "$PREFIX"

export CFLAGS="${CFLAGS:-} -O2 -fPIC"
export CXXFLAGS="${CXXFLAGS:-} -O2 -fPIC"
export LDFLAGS="${LDFLAGS:-}"

echo "[5/9] configure"
./configure \
  --prefix="$PREFIX" \
  --disable-shared \
  --enable-static \
  --disable-sound \
  --disable-video \
  --disable-opencore-amr \
  --disable-silk \
  --disable-opus \
  --disable-libwebrtc \
  --disable-speex-aec \
  "${CONFIGURE_EXTRA[@]}"

echo "[6/9] make dep"
make dep

echo "[7/9] build"
make -j"$JOBS"

echo "[8/9] install"
make install

echo "[9/9] verify install"
echo "-> headers:"
test -f "$PREFIX/include/pjsip.h"
test -f "$PREFIX/include/pjlib.h"
ls -lh "$PREFIX/include/pjsip.h" "$PREFIX/include/pjlib.h"

echo
echo "-> static libs:"
find "$PREFIX/lib" -maxdepth 1 -type f -name 'lib*.a' -printf '%f\n' | sort

echo
echo "-> ensure no shared libs:"
if find "$PREFIX/lib" -maxdepth 1 \( -name '*.so' -o -name '*.dylib' \) | grep -q .; then
  echo "[ERROR] shared libs found"
  find "$PREFIX/lib" -maxdepth 1 \( -name '*.so' -o -name '*.dylib' \) -print
  exit 1
else
  echo "OK"
fi

echo
echo "Done: PJSIP static minimal build complete"
echo "Install prefix: $PREFIX"
echo
cat <<MSG
Next:
  export PJSIP_ROOT="$PREFIX"
  cargo build -p gmv_pjsip_sys
MSG
