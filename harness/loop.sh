#!/usr/bin/env bash
# The night shift: run agent sessions back to back, judge each one with the
# ratchet, keep what improves the numbers, revert what breaks them, and stop
# (instead of spending the usage allowance) when the crew is stuck.
#
#   harness/loop.sh                          defaults from harness/loop.env (Claude Code, opus -> sonnet chain)
#   harness/loop.sh --until 07:30            stop at 07:30 local time
#   harness/loop.sh --models sonnet          one night on a different chain (comma-separated, best first)
#   harness/loop.sh --model claude-opus-5-5 --effort high    pin one exact model and raise effort
#   harness/loop.sh --agent codex            use Codex CLI (ChatGPT plan) instead
#   harness/loop.sh --push                   push after every green session (CI runs the conformance suites too)
#   harness/loop.sh --yolo                   skip permission checks: ONLY inside a disposable Linux VM/container
#
# Options: --subagent-model M  --max-iters N  --max-turns N  --session-minutes N  --strikes N  --cooldown SECONDS
# Stop it gracefully from another terminal: touch .harness/STOP
# Protected path: agents must not edit this file.
source "$(dirname "$0")/lib.sh"
cd "$ROOT" || exit 1

# defaults, then harness/loop.env, then flags
CLAUDE_MODELS=opus,sonnet CLAUDE_EFFORT="" CLAUDE_SUBAGENT_MODEL=sonnet CODEX_MODELS=""
STEP_UP_AFTER_MIN=300 MAX_ITERS=8 MAX_TURNS=60 SESSION_MINUTES=50
# shellcheck source=loop.env
[ -f "$ROOT/harness/loop.env" ] && source "$ROOT/harness/loop.env"

AGENT=claude MODELS_FLAG="" EFFORT_FLAG="unset" SUBAGENT_FLAG="unset" UNTIL=""
SESSION_MIN=$SESSION_MINUTES
PUSH=0 YOLO=0 STRIKES_MAX=3 COOLDOWN=60 LIMIT_SLEEP=${CITADEL_LIMIT_SLEEP:-1800}
while [ $# -gt 0 ]; do
  case "$1" in
    --agent) AGENT=$2; shift 2 ;;
    --model|--models) MODELS_FLAG=$2; shift 2 ;;
    --effort) EFFORT_FLAG=$2; shift 2 ;;
    --subagent-model) SUBAGENT_FLAG=$2; shift 2 ;;
    --until) UNTIL=$2; shift 2 ;;
    --max-iters) MAX_ITERS=$2; shift 2 ;;
    --max-turns) MAX_TURNS=$2; shift 2 ;;
    --session-minutes) SESSION_MIN=$2; shift 2 ;;
    --strikes) STRIKES_MAX=$2; shift 2 ;;
    --cooldown) COOLDOWN=$2; shift 2 ;;
    --push) PUSH=1; shift ;;
    --yolo) YOLO=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

# ---- model chain ----------------------------------------------------------------
# Opus burns a 5-hour window fastest. The chain lets a night keep going on the
# next model when a model-specific limit hits, instead of sleeping.
case "$AGENT" in
  claude) CHAIN_STR=${MODELS_FLAG:-$CLAUDE_MODELS}
          EFFORT=$CLAUDE_EFFORT; [ "$EFFORT_FLAG" != unset ] && EFFORT=$EFFORT_FLAG
          SUBAGENT_MODEL=$CLAUDE_SUBAGENT_MODEL; [ "$SUBAGENT_FLAG" != unset ] && SUBAGENT_MODEL=$SUBAGENT_FLAG ;;
  codex)  CHAIN_STR=${MODELS_FLAG:-$CODEX_MODELS}; EFFORT=""; SUBAGENT_MODEL="" ;;
  *) die "unknown agent $AGENT (claude or codex)" ;;
esac
IFS=',' read -r -a CHAIN <<<"$(echo "$CHAIN_STR" | tr -d ' ')"
[ ${#CHAIN[@]} -eq 0 ] && CHAIN=("")      # empty = the agent CLI's own default model
IDX=0 DOWN_AT=0
cur_model() { echo "${CHAIN[$IDX]}"; }
rest_of_chain() {                          # models after the current one, comma-separated
  local i out=""
  for ((i = IDX + 1; i < ${#CHAIN[@]}; i++)); do out="$out${out:+,}${CHAIN[$i]}"; done
  echo "$out"
}
session_tag() { local m; m=$(cur_model); echo "$AGENT${m:+/$m}${EFFORT:+@$EFFORT}"; }

# ---- preflight -------------------------------------------------------------------
git rev-parse --git-dir >/dev/null 2>&1 || die "not a git repo: run 'git init && git add -A && git commit -m init' first"
[ -z "$(git status --porcelain)" ] || die "working tree not clean: commit or stash first (the loop resets to known-good commits)"
[ -f STUCK.md ] && die "STUCK.md exists: read it, fix or re-plan, delete it, commit, then restart"
for t in go git python3 curl; do have "$t" || die "missing $t"; done
if [ -z "${CITADEL_AGENT_CMD:-}" ]; then
  have "$AGENT" || die "agent CLI '$AGENT' not found on PATH"
fi
if [ $YOLO = 1 ]; then
  [ "$(uname)" = Darwin ] && die "--yolo is refused on macOS: run it only inside a disposable Linux VM or container"
  [ "$(id -u)" = 0 ] && die "--yolo must not run as root"
fi
PP_FLAG=0 FB_FLAG=0
if [ "$AGENT" = claude ] && [ -z "${CITADEL_AGENT_CMD:-}" ]; then
  CLAUDE_HELP=$(claude --help 2>/dev/null)
  grep -q -- '--permission-prompts' <<<"$CLAUDE_HELP" && PP_FLAG=1
  grep -q -- '--fallback-model' <<<"$CLAUDE_HELP" && FB_FLAG=1
  if [ -n "$EFFORT" ] && ! grep -q -- '--effort' <<<"$CLAUDE_HELP"; then
    die "this Claude Code has no --effort flag; update it (claude update) or clear CLAUDE_EFFORT"
  fi
fi

UNTIL_EPOCH=$(python3 - "$UNTIL" <<'EOF'
import sys, datetime as dt
arg = sys.argv[1]
now = dt.datetime.now()
if not arg:
    print(int((now + dt.timedelta(hours=10)).timestamp())); sys.exit()
h, m = map(int, arg.split(":"))
t = now.replace(hour=h, minute=m, second=0, microsecond=0)
if t <= now: t += dt.timedelta(days=1)
print(int(t.timestamp()))
EOF
) || die "bad --until (use HH:MM)"

NIGHT="$H/logs/$(date +%Y%m%d-%H%M)"
mkdir -p "$NIGHT"; ln -sfn "$NIGHT" "$H/logs/latest"
git rev-parse HEAD >"$NIGHT/start.sha"
note() { echo "- $(date '+%H:%M') $*" | tee -a "$NIGHT/night.md" >&2; }
notify() {
  note "NOTIFY: $*"
  [ -n "${NTFY_TOPIC:-}" ] && curl -fsS -m 10 -d "citadel: $*" "https://ntfy.sh/$NTFY_TOPIC" >/dev/null 2>&1
  return 0
}
# keep a macOS host awake while the loop runs (a closed laptop still sleeps)
[ "$(uname)" = Darwin ] && have caffeinate && { caffeinate -i -w $$ & }

{ echo "# Night shift $(date '+%Y-%m-%d %H:%M')"; echo
  echo "agent=$AGENT models=${CHAIN_STR:-default} effort=${EFFORT:-default} subagents=${SUBAGENT_MODEL:-same} max_iters=$MAX_ITERS until=$(date -r "$UNTIL_EPOCH" '+%H:%M' 2>/dev/null || date -d "@$UNTIL_EPOCH" '+%H:%M')"
  echo; } >"$NIGHT/night.md"

# ---- ratchet wrapper: retries infra hiccups (wifi drops at 3am) --------------------
ratchet() {
  local rc tries=0
  while :; do
    "$ROOT/harness/ratchet.sh" >"$NIGHT/ratchet-$1.log" 2>&1; rc=$?
    [ $rc != 3 ] && return $rc
    tries=$((tries + 1)); [ $tries -ge 3 ] && return 3
    note "ratchet infra problem, retrying in 5 min"; sleep 300
  done
}

note "baseline ratchet"
ratchet start; rc=$?
case $rc in
  0) git add conformance/baseline && git commit -q -m "ratchet: baseline $(grep -E '^[a-z0-9-]+: [0-9]+ passing' "$H/ratchet.last" | cut -d' ' -f1-3 | paste -sd, -)" && note "baselines raised before starting" ;;
  1) # make sure every enabled suite has a committed (possibly empty) baseline file
     for s in $(grep -vE '^[[:space:]]*(#|$)' conformance/suites | awk '{print $1}'); do
       [ -f "conformance/baseline/$s.txt" ] || : >"conformance/baseline/$s.txt"
     done
     git add conformance/baseline
     git diff --cached --quiet || git commit -q -m "ratchet: add empty baselines" ;;
  2) cat "$H/ratchet.last" >&2; die "the tree is RED before the night starts; fix it first" ;;
  3) cat "$H/ratchet.last" >&2; die "conformance infrastructure problem; see $NIGHT/ratchet-start.log" ;;
esac

# ---- prompt rendering ----------------------------------------------------------------
current_milestone() {
  # first "## M<n>" section in ROADMAP.md not marked done, with its body
  awk '
    /^##? / { if (grab) exit }
    /^## M[0-9]+/ { if ($0 !~ /\[done\]/) grab = 1 }
    grab { print }
  ' ROADMAP.md | head -60
}

todo_families() {
  python3 - "$H/results" <<'EOF'
import sys, os, re, collections
res = sys.argv[1]
suites = [l.split()[0] for l in open("conformance/suites") if l.strip() and not l.lstrip().startswith("#")]
for s in suites:
    p = os.path.join(res, f"{s}.todo")
    if not os.path.exists(p):
        continue
    ids = [l.strip() for l in open(p) if l.strip()]
    fams = collections.Counter()
    for i in ids:
        name = i.split("::")[-1]
        name = re.sub(r"\[.*\]$", "", name)
        parts = name.split("_")
        fams["_".join(parts[:3]) + "_*" if len(parts) > 3 else name] += 1
    print(f"{s}: {len(ids)} failing")
    for fam, n in fams.most_common(15):
        print(f"  {n:4d}  {fam}")
EOF
}

render_prompt() {
  MILESTONE="$(current_milestone)" RATCHET="$(cat "$H/ratchet.last")" PREVIOUS="$PREV_NOTE" \
  TODO="$(todo_families)" MAX_TURNS="$MAX_TURNS" COMMIT_BY="$((MAX_TURNS * 3 / 4))" \
  python3 - "$ROOT/harness/prompt.md" <<'EOF'
import os, sys
t = open(sys.argv[1]).read()
for k in ("MILESTONE", "RATCHET", "PREVIOUS", "TODO", "MAX_TURNS", "COMMIT_BY"):
    t = t.replace("{{%s}}" % k, os.environ.get(k, "").strip() or "(none)")
print(t)
EOF
}

# ---- one agent session -------------------------------------------------------------------
run_agent() { # prompt_file log_file
  local prompt log=$2 secs=$((SESSION_MIN * 60)) model fallback
  prompt="$(cat "$1")"
  model=$(cur_model); fallback=$(rest_of_chain)
  if [ -n "${CITADEL_AGENT_CMD:-}" ]; then          # used to test the harness itself
    CITADEL_SESSION_MODEL="$model" run_with_timeout "$secs" "$CITADEL_AGENT_CMD" "$prompt" >"$log" 2>&1 </dev/null
    return
  fi
  case "$AGENT" in
    claude)
      local -a args=(-p "$prompt" --max-turns "$MAX_TURNS"
                     --output-format stream-json --verbose
                     --settings "$ROOT/harness/claude-loop-settings.json")
      [ -n "$model" ] && args+=(--model "$model")
      [ -n "$EFFORT" ] && args+=(--effort "$EFFORT")
      # --fallback-model covers overload/outages only; usage limits are handled below by the chain.
      [ -n "$fallback" ] && [ $FB_FLAG = 1 ] && args+=(--fallback-model "$fallback")
      # NOT --bare: bare mode ignores the subscription login and needs an API key.
      if [ $YOLO = 1 ]; then args+=(--dangerously-skip-permissions)
      else args+=(--permission-mode auto); [ $PP_FLAG = 1 ] && args+=(--permission-prompts none)
      fi
      local -a envs=()
      [ -n "$SUBAGENT_MODEL" ] && envs=(CLAUDE_CODE_SUBAGENT_MODEL="$SUBAGENT_MODEL")
      run_with_timeout "$secs" env "${envs[@]}" claude "${args[@]}" >"$log" 2>&1 </dev/null ;;
    codex)
      # Codex's sandbox only lets it write inside the repo, so keep Go's caches here too.
      export GOCACHE="$H/go-build" GOMODCACHE="$H/go-mod" GOFLAGS=-modcacherw
      local -a args=(exec)
      if [ $YOLO = 1 ]; then args+=(--dangerously-bypass-approvals-and-sandbox)
      else args+=(--sandbox workspace-write -c sandbox_workspace_write.network_access=true)
      fi
      [ -n "$model" ] && args+=(-m "$model")
      run_with_timeout "$secs" codex "${args[@]}" "$prompt" >"$log" 2>&1 </dev/null ;;
  esac
}

# Only the tail of the log counts: tool output in the middle can mention "limit" innocently.
hit_limit() { tail -5 "$1" | grep -qiE "hit your [a-z0-9 -]*limit|usage limit|limit reached"; }
hit_weekly() { tail -5 "$1" | grep -qiE "weekly limit"; }
# "You've hit your Opus limit": only that model is exhausted; others may still have room.
hit_model_limit() { tail -5 "$1" | grep -qiE "hit your [a-z ]*(opus|sonnet|haiku|fable)[a-z ]*limit"; }

write_stuck() {
  {
    echo "# STUCK: the night shift stopped itself"
    echo
    echo "$(date '+%Y-%m-%d %H:%M'): $STRIKES_MAX sessions in a row without progress."
    echo
    echo "## Current milestone"; echo; current_milestone | head -5; echo
    echo "## Last notes"; echo; tail -8 "$NIGHT/night.md"; echo
    echo "## Last ratchet"; echo '```'; cat "$H/ratchet.last"; echo '```'; echo
    echo "## What to do"
    echo "- Read the session logs in .harness/logs/latest/ (and any harness/reverted-* branches)."
    echo "- Unstick it interactively (claude --model opus, maybe with --effort high), or split the milestone in ROADMAP.md into smaller steps."
    echo "- Then delete this file, commit, and restart the loop."
  } >STUCK.md
  git add STUCK.md && git commit -q -m "harness: stuck, needs a human"
}

# ---- the night ------------------------------------------------------------------------------
iter=0 strikes=0 PREV_NOTE=""
while :; do
  now=$(date +%s)
  [ "$now" -ge "$UNTIL_EPOCH" ] && { note "stopping: reached --until"; break; }
  [ $iter -ge "$MAX_ITERS" ] && { note "stopping: $MAX_ITERS sessions done"; break; }
  [ -f "$H/STOP" ] && { rm -f "$H/STOP"; note "stopping: STOP file"; break; }
  iter=$((iter + 1))
  TAG=$(session_tag)
  START=$(git rev-parse HEAD)
  unit_before=$(cat "$H/unit.count" 2>/dev/null || echo 0)
  render_prompt >"$NIGHT/s$iter.prompt.md"
  note "session $iter ($TAG): starting"
  run_agent "$NIGHT/s$iter.prompt.md" "$NIGHT/s$iter.log"; arc=$?
  [ $arc = 124 ] && note "session $iter ($TAG): hit the ${SESSION_MIN}-minute limit"

  if [ -n "$(git status --porcelain)" ]; then
    git add -A && git commit -q -m "wip(harness): uncommitted work from session $iter"
  fi
  commits=$(git rev-list --count "$START..HEAD")
  limited=0; stepped=0
  hit_limit "$NIGHT/s$iter.log" && limited=1

  # A model-specific limit with a model left in the chain: step down, keep working.
  if [ $limited = 1 ] && hit_model_limit "$NIGHT/s$iter.log" && [ $IDX -lt $((${#CHAIN[@]} - 1)) ]; then
    IDX=$((IDX + 1)); DOWN_AT=$(date +%s); limited=0; stepped=1
    note "session $iter ($TAG): LIMIT $(tail -5 "$NIGHT/s$iter.log" | grep -oiE "hit your [a-z ]*limit" | head -1); continuing on $(cur_model)"
  fi
  if [ $limited = 1 ] && hit_weekly "$NIGHT/s$iter.log"; then
    note "session $iter ($TAG): LIMIT weekly usage limit reached"
    [ "$commits" -gt 0 ] && { ratchet "s$iter" || git reset -q --hard "$START"; }
    notify "weekly limit reached, stopping for the night"
    break
  fi
  if [ $limited = 1 ] && [ "$commits" = 0 ]; then
    note "session $iter ($TAG): LIMIT usage limit hit before any work; sleeping $((LIMIT_SLEEP / 60)) min"
    iter=$((iter - 1))
    sleep "$LIMIT_SLEEP"; IDX=0; continue
  fi
  if [ $stepped = 1 ] && [ "$commits" = 0 ]; then
    iter=$((iter - 1)); continue          # not the crew's fault: retry at once on the next model
  fi
  if [ "$commits" = 0 ]; then
    strikes=$((strikes + 1))
    PREV_NOTE="The previous session made no commits (agent exit code $arc). Commit something small and working this time."
    note "session $iter ($TAG): no commits (strike $strikes/$STRIKES_MAX)"
  else
    # mechanical anti-cheat: the scoreboard belongs to the human
    touched=$(git diff --name-only "$START" HEAD -- harness conformance/baseline conformance/pins.env .github .claude AGENTS.md CLAUDE.md Makefile)
    removed_suite=$(git diff "$START" HEAD -- conformance/suites | grep -E '^-[^-]' || true)
    if [ -n "$touched$removed_suite" ]; then
      git branch -f "harness/reverted-s$iter-$(date +%m%d%H%M)" HEAD
      git reset -q --hard "$START"
      strikes=$((strikes + 1))
      PREV_NOTE="REVERTED: the previous session modified protected paths ($(echo "$touched" | tr '\n' ' ')${removed_suite:+conformance/suites removal}). Those belong to the human. Work around them or write the request in PROGRESS.md."
      note "session $iter ($TAG): REVERTED for touching protected paths: $(echo "$touched" | tr '\n' ' ') (strike $strikes/$STRIKES_MAX)"
    else
      skipdiff=$(git diff --stat "$START" HEAD -- conformance/skips ROADMAP.md | tail -1)
      [ -n "$skipdiff" ] && note "session $iter ($TAG): changed skip lists or ROADMAP, review: $skipdiff"
      ratchet "s$iter"; rrc=$?
      summary=$(grep -E '^[a-z0-9-]+: [0-9]+ passing' "$H/ratchet.last" | paste -sd';' -)
      case $rrc in
        0)
          git add conformance/baseline && git commit -q -m "ratchet: $summary"
          strikes=0
          PREV_NOTE="The previous session was kept and improved the numbers: $summary"
          note "session $iter ($TAG): IMPROVED ($commits commits) $summary" ;;
        1)
          unit_after=$(cat "$H/unit.count" 2>/dev/null || echo 0)
          if [ "$unit_after" -gt "$unit_before" ]; then
            PREV_NOTE="The previous session was kept: green, conformance unchanged, unit tests $unit_before -> $unit_after (groundwork)."
            note "session $iter ($TAG): kept, groundwork (unit tests $unit_before -> $unit_after)"
          else
            strikes=$((strikes + 1))
            PREV_NOTE="The previous session was kept but moved no number (conformance and unit tests unchanged). Aim at a failing conformance test this time."
            note "session $iter ($TAG): kept, but no measurable progress (strike $strikes/$STRIKES_MAX)"
          fi ;;
        2)
          branch="harness/reverted-s$iter-$(date +%m%d%H%M)"
          git branch -f "$branch" HEAD
          git reset -q --hard "$START"
          strikes=$((strikes + 1))
          PREV_NOTE="REVERTED: the previous session broke things, and its commits are saved on branch $branch (inspect with git diff $START $branch). Ratchet said:
$(tail -20 "$H/ratchet.last")
Try a smaller or different approach."
          note "session $iter ($TAG): REVERTED (regression/red), saved on $branch (strike $strikes/$STRIKES_MAX)" ;;
        3)
          notify "conformance infrastructure failing; stopping (tree left at session $iter's commits)"
          break ;;
      esac
      if [ $PUSH = 1 ] && [ $rrc -le 1 ]; then
        git push -q origin HEAD 2>>"$NIGHT/push.log" || note "push failed (see push.log)"
      fi
    fi
  fi

  if [ $strikes -ge "$STRIKES_MAX" ]; then
    write_stuck
    notify "stuck after $STRIKES_MAX sessions without progress; see STUCK.md"
    break
  fi
  # after at least one full session on a fallback model, try the top of the chain again
  if [ $IDX -gt 0 ] && [ $(( $(date +%s) - DOWN_AT )) -ge $((STEP_UP_AFTER_MIN * 60)) ]; then
    IDX=0; note "back to ${CHAIN[0]} after ${STEP_UP_AFTER_MIN} min on the fallback"
  fi
  if [ $limited = 1 ]; then
    note "session $iter ($TAG): LIMIT usage limit reached during session; sleeping $((LIMIT_SLEEP / 60)) min"
    sleep "$LIMIT_SLEEP"; IDX=0
  else
    sleep "$COOLDOWN"
  fi
done

"$ROOT/harness/report.sh"
