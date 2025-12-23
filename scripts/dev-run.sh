#!/usr/bin/env bash
set -euo pipefail

exec go run -ldflags='-linkmode=external' ./cmd/flasher-helper "$@"
