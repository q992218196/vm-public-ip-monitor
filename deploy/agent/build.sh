#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../agent"
mkdir -p bin
version=$(cat VERSION)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$version" -o bin/vm-agent-linux-amd64 ./cmd/vm-agent
cp VERSION bin/VERSION
cp ../deploy/agent/install.sh ../deploy/agent/uninstall.sh bin/
(cd bin && sha256sum vm-agent-linux-amd64 install.sh uninstall.sh > SHA256SUMS)
