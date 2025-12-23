#!/usr/bin/env bash
set -euo pipefail

exec go run -mod=mod -ldflags='-linkmode=external' ./cmd/flasher-gui
