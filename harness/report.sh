#!/usr/bin/env bash
# The five-minute morning report for the latest night shift.
#   harness/report.sh            latest night
#   harness/report.sh DIR        a specific .harness/logs/<night> directory
source "$(dirname "$0")/lib.sh"
cd "$ROOT" || exit 1
NIGHT="${1:-$H/logs/latest}"
[ -d "$NIGHT" ] || die "no night logs yet (run harness/loop.sh first)"
START=$(cat "$NIGHT/start.sha" 2>/dev/null)

hr() { printf '\n== %s ==\n' "$1"; }

cat "$NIGHT/night.md"

hr "Scoreboard (last ratchet)"
grep -E '^(unit tests|[a-z0-9-]+: [0-9]+ passing|RESULT|RED|INFRA)' "$H/ratchet.last" 2>/dev/null || echo "(no ratchet run yet)"

hr "Sessions by model (use this to decide which models earn their usage)"
sed -nE 's/.*session [0-9]+ \(([^)]+)\): (IMPROVED|kept, groundwork|kept, but no|REVERTED|no commits|LIMIT).*/\1|\2/p' "$NIGHT/night.md" \
  | awk -F'|' '
      { m[$1] = 1
        if ($2 == "IMPROVED") imp[$1]++
        else if ($2 == "kept, groundwork") gw[$1]++
        else if ($2 == "kept, but no") flat[$1]++
        else if ($2 == "REVERTED") rev[$1]++
        else if ($2 == "no commits") none[$1]++
        else if ($2 == "LIMIT") lim[$1]++ }
      END {
        n = 0
        for (k in m) { n++
          judged = imp[k] + gw[k] + flat[k] + rev[k] + none[k]
          printf "%-28s %2d judged: %d improved, %d groundwork, %d flat, %d reverted, %d no commits | %d limit hits\n",
                 k, judged, imp[k], gw[k], flat[k], rev[k], none[k], lim[k] }
        if (n == 0) print "(no sessions)" }'
grep -E 'LIMIT|back to ' "$NIGHT/night.md" | sed 's/^- //'

if [ -n "$START" ]; then
  hr "Kept commits since the night started"
  git log --oneline --no-decorate "$START..HEAD" | grep -v '^[0-9a-f]* ratchet:' | head -40
  [ "$(git rev-list --count "$START..HEAD")" = 0 ] && echo "(none)"

  hr "Review these: skip-list and roadmap edits by agents"
  if git diff --quiet "$START" HEAD -- conformance/skips ROADMAP.md; then
    echo "(none)"
  else
    git diff "$START" HEAD -- conformance/skips ROADMAP.md | head -80
  fi
fi

hr "Reverted work (branches you can inspect or delete)"
git branch --list 'harness/reverted-*' | tail -10
[ -z "$(git branch --list 'harness/reverted-*')" ] && echo "(none)"

if [ -f STUCK.md ]; then
  hr "STUCK.md (the loop will not restart until you delete it)"
  sed -n '1,12p' STUCK.md
fi

hr "Latest PROGRESS.md entries"
awk '/^### /{n++} n>0' PROGRESS.md | tail -30
echo
echo "Full logs: $NIGHT"
