#!/usr/bin/env bash
# Three Citadel regions on one machine, as described by regions.json:
# palaven-1 (home, :8441), tuchanka-1 (:8440) and thessia-1 (:8442), each its
# own process with its own data directory under .harness/data/multiregion/.
#
#   examples/multiregion-local/regions.sh start            # build, start all three, wait until healthy
#   examples/multiregion-local/regions.sh status           # role, home reachability, feed position
#   examples/multiregion-local/regions.sh pause palaven-1  # SIGSTOP (static-stability drills)
#   examples/multiregion-local/regions.sh resume palaven-1 # SIGCONT
#   examples/multiregion-local/regions.sh restart thessia-1
#   examples/multiregion-local/regions.sh stop             # stop all (data is kept)
#   examples/multiregion-local/regions.sh clean            # stop all and delete the data
#
# The shared region key is generated once per data directory and exported as
# CITADEL_REGION_KEY; it never lands in the repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REG="$ROOT/examples/multiregion-local/regions.json"
DATA="${CITADEL_MR_DATA:-$ROOT/.harness/data/multiregion}"
BIN="$ROOT/.harness/bin/citadel"
REGIONS=(palaven-1 tuchanka-1 thessia-1)

endpoint() { python3 -c 'import json,sys; print(next(r["endpoint"] for r in json.load(open(sys.argv[1]))["regions"] if r["name"]==sys.argv[2]))' "$REG" "$1"; }
pidfile() { echo "$DATA/$1/citadel.pid"; }
running() { local p; p=$(cat "$(pidfile "$1")" 2>/dev/null) && kill -0 "$p" 2>/dev/null; }

key() {
  mkdir -p "$DATA"
  [ -s "$DATA/region.key" ] || { umask 077; openssl rand -hex 32 >"$DATA/region.key"; }
  cat "$DATA/region.key"
}

start_one() {
  local r=$1 ep addr
  running "$r" && { echo "$r already running (pid $(cat "$(pidfile "$r")"))"; return 0; }
  ep=$(endpoint "$r"); addr=${ep#http://}
  mkdir -p "$DATA/$r"
  CITADEL_REGION_KEY=$(key) "$BIN" serve --region "$r" --listen "$addr" --data "$DATA/$r" \
    --bootstrap "$ROOT/harness/bootstrap.json" --regions "$REG" --log text \
    >>"$DATA/$r/citadel.log" 2>&1 &
  echo $! >"$(pidfile "$r")"
  for _ in $(seq 1 100); do
    curl -fsS "$ep/_citadel/healthz" >/dev/null 2>&1 && { echo "$r up on $ep (pid $(cat "$(pidfile "$r")"))"; return 0; }
    sleep 0.1
  done
  echo "$r did not become healthy; see $DATA/$r/citadel.log" >&2
  return 1
}

stop_one() {
  local r=$1 p
  running "$r" || { rm -f "$(pidfile "$r")"; return 0; }
  p=$(cat "$(pidfile "$r")")
  kill -CONT "$p" 2>/dev/null || true
  kill "$p"
  for _ in $(seq 1 50); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
  rm -f "$(pidfile "$r")"
  echo "$r stopped"
}

cmd=${1:-}; shift || true
case "$cmd" in
  start)
    (cd "$ROOT" && make -s build)
    for r in "${@:-${REGIONS[@]}}"; do start_one "$r"; done ;;
  stop)
    for r in "${@:-${REGIONS[@]}}"; do stop_one "$r"; done ;;
  restart)
    for r in "${@:-${REGIONS[@]}}"; do stop_one "$r"; start_one "$r"; done ;;
  pause)
    for r in "$@"; do kill -STOP "$(cat "$(pidfile "$r")")" && echo "$r paused (SIGSTOP)"; done ;;
  resume)
    for r in "$@"; do kill -CONT "$(cat "$(pidfile "$r")")" && echo "$r resumed (SIGCONT)"; done ;;
  status)
    for r in "${REGIONS[@]}"; do
      printf '%-11s ' "$r"
      curl -fsS -m 1 "$(endpoint "$r")/_citadel/healthz" 2>/dev/null || echo "(not answering)"
    done ;;
  clean)
    for r in "${REGIONS[@]}"; do stop_one "$r"; done
    rm -rf "$DATA" ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2 ;;
esac
