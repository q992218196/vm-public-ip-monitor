#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../agent"
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/vm-agent-linux-amd64 ./cmd/vm-agent
sha256sum bin/vm-agent-linux-amd64 > bin/SHA256SUMS
