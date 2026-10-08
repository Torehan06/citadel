#!/usr/bin/env bash
# M9's exit drill (see drill.py): three local regions, steady-state
# replication lag, then thessia-1 stopped for --outage seconds (default 600)
# while writes continue, then convergence after it returns.
#
#   examples/multiregion-local/drill.sh                     # the full 10-minute drill
#   examples/multiregion-local/drill.sh --outage 30 --steady 15 --mode kill
#
# Data lives under .harness/data/m9-drill and is deleted afterwards. Needs a
# python with boto3: $DRILL_PYTHON, or one of the harness virtualenvs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export CITADEL_MR_DATA="${CITADEL_MR_DATA:-$ROOT/.harness/data/m9-drill}"
export AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$ROOT/harness/aws.config}"
export AWS_SHARED_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$ROOT/harness/aws.credentials}"
PY="${DRILL_PYTHON:-}"
if [ -z "$PY" ]; then
  for p in python3 "$ROOT"/.harness/venv/*/bin/python; do
    if "$p" -c 'import boto3' 2>/dev/null; then PY=$p; break; fi
  done
fi
[ -n "$PY" ] || { echo "FAIL drill::python-with-boto3 (set DRILL_PYTHON)"; exit 1; }
REGIONS="$ROOT/examples/multiregion-local/regions.sh"
"$REGIONS" clean >/dev/null 2>&1 || true
trap '"$REGIONS" clean >/dev/null 2>&1 || true' EXIT
"$REGIONS" start >/dev/null
"$PY" "$ROOT/examples/multiregion-local/drill.py" "$@"
