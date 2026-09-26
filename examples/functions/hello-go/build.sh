#!/usr/bin/env bash
# Build hello-go as a Lambda deployment package: function.zip with bootstrap.wasm.
#   examples/functions/hello-go/build.sh [output.zip]
set -euo pipefail
cd "$(dirname "$0")"
out="${1:-$PWD/function.zip}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$tmp/bootstrap.wasm" .
(cd "$tmp" && python3 -m zipfile -c "$out" bootstrap.wasm)
echo "$out"
