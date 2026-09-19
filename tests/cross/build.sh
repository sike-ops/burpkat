#!/usr/bin/env bash
# Rebuild the cross-glibc host/payload variants used by run.sh.
#
# host      -> ET_EXEC  (-no-pie)
# host-pie  -> ET_DYN   (PIE)      (burpkat also accepts a PIE host)
# payload   -> ET_DYN   (PIE)      (burpkat requires a PIE payload)
#
# The .note.gnu.build-id section is forced because burpkat rewrites it, and
# not every toolchain emits one by default.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/tests/cross"
OUT="${OUT:-/tmp/opencode/cross}"

CFLAGS="-O0 -pthread -Wl,--build-id=sha1"

build_container() {
  local image="$1" name="$2"
  mkdir -p "$OUT/$name"
  docker run --rm -v "$SRC:/src:ro" -v "$OUT/$name:/out" -w /out "$image" \
    bash -c "gcc $CFLAGS -no-pie -o host /src/host.c &&
             gcc $CFLAGS -fPIE -pie -o host-pie /src/host.c &&
             gcc $CFLAGS -fPIE -pie -o payload /src/payload.c &&
             ldd --version | head -1"
}

build_local() {
  local name="$1"
  mkdir -p "$OUT/$name"
  gcc $CFLAGS -no-pie -o "$OUT/$name/host" "$SRC/host.c"
  gcc $CFLAGS -fPIE -pie -o "$OUT/$name/host-pie" "$SRC/host.c"
  gcc $CFLAGS -fPIE -pie -o "$OUT/$name/payload" "$SRC/payload.c"
  ldd --version | head -1
}

build_container gcc:11 glibc231
build_container gcc:13 glibc236
build_container gcc:14 glibc241
build_local glibc243
