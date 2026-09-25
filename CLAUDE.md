@AGENTS.md

## Claude Code specifics

- Under the loop you run headless (`claude -p`) with no one to answer permission prompts or questions. Don't ask. Decide and note it in PROGRESS.md.
- Don't spawn subagents for routine work. On a subscription plan they multiply usage, and the loop's budget is small. If you do spawn one, the loop runs it on `CLAUDE_SUBAGENT_MODEL` (Sonnet by default), not on your model.
- When a human runs you interactively in this repo, they're usually unsticking the crew. Start with STUCK.md (if present), `harness/report.sh`, and the tail of PROGRESS.md.
- `notes/` is the human's private learning log (local only, via .git/info/exclude). Read `notes/guide.md` to pitch explanations at their level. After each milestone, append a plain-English section to `notes/guide.md` (what was built, an everyday analogy, the new terms, one command to see it working) and add new terms to `notes/glossary.md`. Never commit `notes/`.
