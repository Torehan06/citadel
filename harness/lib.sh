# shellcheck shell=bash
# Shared helpers for the harness scripts. Source it; don't run it.

set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
H="$ROOT/.harness"            # all harness state lives here (gitignored)
mkdir -p "$H"/{bin,cache,venv,results,logs,data}

# ---- safety: nothing in this repo may reach real AWS or bill an API key ------
# Point every AWS SDK/CLI at the repo's fake config so ~/.aws is never read.
export AWS_CONFIG_FILE="$ROOT/harness/aws.config"
export AWS_SHARED_CREDENTIALS_FILE="$ROOT/harness/aws.credentials"
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_PROFILE
# Subscription only: an API key in the environment makes Claude Code / Codex bill per token.
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN OPENAI_API_KEY CODEX_API_KEY

log()  { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die()  { log "FATAL: $*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Portable timeout (macOS has no `timeout` by default).
# usage: run_with_timeout SECONDS cmd args...   -> exit 124 on timeout
run_with_timeout() {
  local secs=$1; shift
  local flag="$H/.timeout.$$.$RANDOM"
  rm -f "$flag"
  "$@" &
  local pid=$!
  (
    # poll instead of one long sleep, so the watcher exits on its own
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
      if [ "$waited" -ge "$secs" ]; then
        : >"$flag"
        kill -TERM "$pid" 2>/dev/null
        grace=0
        while kill -0 "$pid" 2>/dev/null && [ $grace -lt 20 ]; do sleep 1; grace=$((grace + 1)); done
        kill -KILL "$pid" 2>/dev/null
        break
      fi
      sleep 1; waited=$((waited + 1))
    done
  ) &
  local watcher=$!
  wait "$pid"
  local rc=$?
  wait "$watcher" 2>/dev/null
  if [ -e "$flag" ]; then rm -f "$flag"; rc=124; fi
  return $rc
}

port_busy() {
  if have lsof; then lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; return; fi
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# ---- building and running a throwaway region for tests -----------------------
build_citadel() {
  (cd "$ROOT" && make -s build) >"$H/results/build.log" 2>&1 || {
    tail -30 "$H/results/build.log" >&2
    return 1
  }
}

CITADEL_PID=""
CITADEL_DATA=""   # the throwaway data dir of the running region; stop_citadel deletes it
# usage: start_citadel PORT LOGFILE  (fresh data dir every time)
start_citadel() {
  local port=$1 logfile=$2
  if port_busy "$port"; then
    log "port $port is already in use."
    [ "$port" = 5000 ] && [ "$(uname)" = Darwin ] && \
      log "On macOS this is usually AirPlay Receiver: System Settings > General > AirDrop & Handoff > AirPlay Receiver = off."
    return 3
  fi
  CITADEL_DATA="$H/data/conformance-$port-$$"
  rm -rf "$CITADEL_DATA"; mkdir -p "$CITADEL_DATA"
  "$H/bin/citadel" serve --region tuchanka-1 --listen "127.0.0.1:$port" --data "$CITADEL_DATA" \
    --bootstrap "$ROOT/harness/bootstrap.json" --conformance --log text >"$logfile" 2>&1 &
  CITADEL_PID=$!

  for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$port/_citadel/healthz" >/dev/null 2>&1; then return 0; fi
    kill -0 "$CITADEL_PID" 2>/dev/null || break
    sleep 0.2
  done
  log "citadel did not become healthy on :$port. Last server log lines:"
  tail -20 "$logfile" >&2
  stop_citadel
  return 1
}

stop_citadel() {
  if [ -n "$CITADEL_PID" ] && kill -0 "$CITADEL_PID" 2>/dev/null; then
    kill "$CITADEL_PID" 2>/dev/null
    wait "$CITADEL_PID" 2>/dev/null
  fi
  CITADEL_PID=""
  # Throwaway region data (~200 MB per s3 run) would otherwise fill the disk.
  if [ -n "$CITADEL_DATA" ]; then rm -rf "$CITADEL_DATA"; fi
  CITADEL_DATA=""
}

# ---- pinned upstream test suites -----------------------------------------------
# shellcheck source=../conformance/pins.env
source "$ROOT/conformance/pins.env"

# usage: fetch_pinned NAME URL SHA [sparse dirs...]
fetch_pinned() {
  local name=$1 url=$2 sha=$3; shift 3
  local dir="$H/cache/$name"
  if [ -f "$dir/.pinned" ] && [ "$(cat "$dir/.pinned")" = "$sha" ]; then return 0; fi
  log "fetching $name @ ${sha:0:10} (one-time)"
  rm -rf "$dir"; mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" remote add origin "$url"
  if [ $# -gt 0 ]; then git -C "$dir" sparse-checkout set "$@"; fi
  git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$sha" || return 3
  git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD || return 3
  echo "$sha" >"$dir/.pinned"
}

# Conformance suites need Python >= 3.11 (Alternator's tests use enum.StrEnum).
# macOS ships 3.9, so prefer a Homebrew python if one is installed.
if [ -z "${PYTHON:-}" ]; then
  for p in python3.13 python3.12 python3.11 python3; do have "$p" && { PYTHON=$p; break; }; done
fi
# usage: ensure_venv NAME pip-args...   (re-created when the args change)
ensure_venv() {
  local name=$1; shift
  local venv="$H/venv/$name" stamp
  stamp="$(printf '%s ' "$@")"
  if [ -f "$venv/.stamp" ] && [ "$(cat "$venv/.stamp")" = "$stamp" ]; then return 0; fi
  log "creating python venv for $name (one-time)"
  rm -rf "$venv"
  "$PYTHON" -m venv "$venv" || return 3
  "$venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1
  "$venv/bin/pip" install -q "$@" || return 3
  echo "$stamp" >"$venv/.stamp"
}
