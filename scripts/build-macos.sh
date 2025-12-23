#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FYNE_BIN="$(go env GOPATH)/bin/fyne"
FYNE_CMD="$(command -v fyne || true)"
if [ -z "$FYNE_CMD" ] && [ -x "$FYNE_BIN" ]; then
  FYNE_CMD="$FYNE_BIN"
fi

needs_install=true
if [ -n "$FYNE_CMD" ]; then
  if command -v otool >/dev/null 2>&1; then
    if command -v rg >/dev/null 2>&1; then
      if otool -l "$FYNE_CMD" 2>/dev/null | rg -q "LC_UUID"; then
        needs_install=false
      fi
    else
      if otool -l "$FYNE_CMD" 2>/dev/null | grep -q "LC_UUID"; then
        needs_install=false
      fi
    fi
  elif "$FYNE_CMD" version >/dev/null 2>&1; then
    needs_install=false
  fi
fi

if [ "$needs_install" = true ]; then
  echo "fyne CLI not found or incompatible. Installing..." >&2
  GOFLAGS="-ldflags=-linkmode=external" go install fyne.io/fyne/v2/cmd/fyne@v2.4.5
  FYNE_CMD="$FYNE_BIN"
fi

GOFLAGS_EXTRA="-ldflags=-linkmode=external"
if [ -n "${GOFLAGS:-}" ]; then
  export GOFLAGS="${GOFLAGS} ${GOFLAGS_EXTRA}"
else
  export GOFLAGS="${GOFLAGS_EXTRA}"
fi

mkdir -p dist

ICON_PATH="$ROOT_DIR/assets/icon.png"
if [ ! -f "$ICON_PATH" ]; then
  echo "Missing application icon at \"$ICON_PATH\"" >&2
  exit 1
fi

go build -o dist/flasher-helper ./cmd/flasher-helper

"$FYNE_CMD" package -os darwin -src ./cmd/flasher-gui -name "Netboot Flasher" -appID "com.netbootflasher.app" -icon "$ICON_PATH"
mv "Netboot Flasher.app" dist/

hdiutil create -volname "Netboot Flasher" -srcfolder "dist/Netboot Flasher.app" -ov -format UDZO "dist/Netboot-Flasher.dmg"
echo "Wrote dist/Netboot Flasher.app and dist/Netboot-Flasher.dmg"
