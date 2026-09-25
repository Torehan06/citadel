#!/usr/bin/env bash
# The ratchet: conformance numbers only go up.
#
#   harness/ratchet.sh               run everything, raise baselines on improvement
#   harness/ratchet.sh --check-only  compare only, never write (CI uses this)
#
# 1. vet + 3-platform build + unit tests must pass.
# 2. Every suite in conformance/suites runs; its pass set is compared with
#    conformance/baseline/<suite>.txt. Tests that stopped passing are re-run once
#    (flake filter); still failing = regression.
#
# Exit: 0 improved   1 green, unchanged   2 red (check failed / regression)   3 infra
# Writes a human- and agent-readable summary to .harness/ratchet.last
# Protected path: agents must not edit this file.
source "$(dirname "$0")/lib.sh"
export LC_ALL=C

CHECK_ONLY=0
[ "${1:-}" = "--check-only" ] && CHECK_ONLY=1
SUMMARY="$H/ratchet.last"
: >"$SUMMARY"
say() { echo "$*" | tee -a "$SUMMARY"; }
md() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$*" >>"$GITHUB_STEP_SUMMARY"; return 0; }

# ---- 1. static checks, build, unit tests ---------------------------------------
if ! (cd "$ROOT" && make -s vet cross) >"$H/results/check.log" 2>&1; then
  say "RED: make vet/cross failed"
  tail -40 "$H/results/check.log" | tee -a "$SUMMARY"
  exit 2
fi
if ! (cd "$ROOT" && go test -count=1 -v ./...) >"$H/results/unit.log" 2>&1; then
  say "RED: unit tests failed"
  grep -E '^(--- FAIL|FAIL|panic:)|_test.go:[0-9]+:' "$H/results/unit.log" | head -40 | tee -a "$SUMMARY"
  exit 2
fi
UNIT=$(grep -cE '^[[:space:]]*--- PASS' "$H/results/unit.log" || true)
echo "$UNIT" >"$H/unit.count"
say "unit tests: $UNIT passing"

# ---- 2. conformance suites -------------------------------------------------------------
SUITES=$(grep -vE '^[[:space:]]*(#|$)' "$ROOT/conformance/suites" 2>/dev/null | awk '{print $1}')
[ -n "$SUITES" ] || { say "no suites enabled in conformance/suites"; exit 1; }

md "## Citadel conformance scoreboard"
md ""
md "| suite | passing | baseline | change |"
md "|---|---:|---:|---:|"

improved=0; regressed=0; infra=0
for s in $SUITES; do
  # compare against a sorted private copy: the ratchet never touches the
  # committed baseline except to raise it at the very end
  base="$H/results/$s.base"
  if [ -f "$ROOT/conformance/baseline/$s.txt" ]; then sort "$ROOT/conformance/baseline/$s.txt" >"$base"; else : >"$base"; fi
  out=$("$ROOT/harness/conformance.sh" "$s" --quiet 2>&1); rc=$?
  case $rc in
    0) ;;
    1) say "RED: $out"; exit 2 ;;
    *) say "INFRA: $s: $out"; infra=1; continue ;;
  esac
  cur="$H/results/$s.pass"
  sort -o "$cur" "$cur"
  lost_f="$H/results/$s.lost"
  comm -23 "$base" "$cur" >"$lost_f"
  gained=$(comm -13 "$base" "$cur" | wc -l | tr -d ' ')
  lost=$(wc -l <"$lost_f" | tr -d ' ')
  flaky=0
  if [ "$lost" -gt 0 ]; then
    # flake filter: re-run exactly the lost tests once
    "$ROOT/harness/conformance.sh" "$s" --quiet --nodes "$lost_f" >/dev/null 2>&1
    if [ -f "$H/results/targeted-$s.pass" ]; then
      sort -o "$H/results/targeted-$s.pass" "$H/results/targeted-$s.pass"
      comm -23 "$lost_f" "$H/results/targeted-$s.pass" >"$lost_f.still"
    else
      cp "$lost_f" "$lost_f.still"
    fi
    still=$(wc -l <"$lost_f.still" | tr -d ' ')
    flaky=$((lost - still)); lost=$still
    mv "$lost_f.still" "$lost_f"
  fi
  nbase=$(wc -l <"$base" | tr -d ' '); ncur=$(wc -l <"$cur" | tr -d ' ')
  line="$s: $ncur passing (baseline $nbase, +$gained new, -$lost lost"
  [ "$flaky" -gt 0 ] && line="$line, $flaky flaky"
  say "$line)"
  md "| $s | $ncur | $nbase | +$gained / -$lost |"
  if [ "$lost" -gt 0 ]; then
    regressed=1
    say "  REGRESSION in $s, these passed before and fail now:"
    head -15 "$lost_f" | sed 's/^/    /' | tee -a "$SUMMARY"
  fi
  [ "$gained" -gt 0 ] && improved=1
  # candidates for the next session: failing, not on the human-approved skip list
  skips="$ROOT/conformance/skips/$s.txt"
  if [ -f "$skips" ]; then
    grep -vE '^[[:space:]]*(#|$)' "$skips" | awk '{print $1}' | sort >"$H/results/$s.skipids"
    comm -23 <(sort "$H/results/$s.fail") "$H/results/$s.skipids" >"$H/results/$s.todo"
  else
    sort "$H/results/$s.fail" >"$H/results/$s.todo"
  fi
done

if [ $regressed = 1 ]; then say "RESULT: RED (regression)"; exit 2; fi
# a suite that could not run means we cannot judge: never raise baselines then
if [ $infra = 1 ]; then say "RESULT: INFRA (some suites did not run)"; exit 3; fi
if [ $improved = 0 ]; then say "RESULT: green, no change"; exit 1; fi
if [ $CHECK_ONLY = 0 ]; then
  for s in $SUITES; do
    sort -u "$H/results/$s.base" "$H/results/$s.pass" -o "$ROOT/conformance/baseline/$s.txt"
  done
  say "RESULT: improved, baselines raised"
else
  say "RESULT: improved (check-only, baselines untouched)"
fi
exit 0
