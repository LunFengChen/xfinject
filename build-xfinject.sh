#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT" "$OUT/tmp"
cd "$ROOT"

GO_BIN="${GO_BIN:-go}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK:-/home/xiaofeng/Android/Sdk/ndk/27.0.12077973}}"
NDK_HOST="${NDK_HOST:-linux-x86_64}"
API="${API:-23}"
CC_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/aarch64-linux-android${API}-clang"
CXX_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/aarch64-linux-android${API}-clang++"

if [[ ! -x "$CC_BIN" ]]; then
  echo "missing Android NDK clang: $CC_BIN" >&2
  exit 1
fi

# Device CLI: useful for standalone smoke tests and xfinjectd prototype.
GOOS=android GOARCH=arm64 CGO_ENABLED=0 GOTMPDIR="$OUT/tmp" \
  "$GO_BIN" build -trimpath -ldflags='-s -w' -o "$OUT/xfinjectd" ./cmd/xfinjectd

# C ABI shared library: intended to be wrapped by future native daemon/service.
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="$CC_BIN" CXX="$CXX_BIN" GOTMPDIR="$OUT/tmp" \
  "$GO_BIN" build -trimpath -ldflags='-s -w' -buildmode=c-shared -o "$OUT/libxfinject.so" ./cmd/libxfinject

file "$OUT/xfinjectd" "$OUT/libxfinject.so"

if [[ "${XFINJECT_UPDATE_PREBUILTS:-0}" == "1" ]]; then
  mkdir -p "$ROOT/prebuilts/arm64"
  cp -f "$OUT/xfinjectd" "$ROOT/prebuilts/arm64/xfinjectd"
  cp -f "$OUT/libxfinject.so" "$ROOT/prebuilts/arm64/libxfinject.so"
  echo "updated $ROOT/prebuilts/arm64"
fi
