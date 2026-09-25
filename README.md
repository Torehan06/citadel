# Citadel

A three-region AWS-compatible cloud on free machines, built mostly by unattended coding-agent sessions. `aws s3 cp`, boto3, and `terraform apply` should work against it, and the end state is a cloud that hosts its own git server and CI and deploys itself.

| Region | Machine |
|---|---|
| `tuchanka-1` | a laptop (dev region, sleeps) |
| `palaven-1` | Oracle Cloud Always Free ARM VM (always on, home of the control plane) |
| `thessia-1` | a GitHub Codespace (ephemeral, the canary region) |

What it is and how it's built: **ARCHITECTURE.md**. What gets built in which order, and how "done" is judged: **ROADMAP.md**. Rules for the agents: **AGENTS.md**.

## How the night shift works

Each night, `harness/loop.sh` runs a few agent sessions back to back. Every session gets a generated prompt: the current milestone, the latest scores, and the families of failing tests. The agent does one thing, commits, and exits. Then the harness judges the result:

1. **Auto-commit.** Uncommitted leftovers are auto-committed, so no work is lost to a turn limit.
2. **Protected paths.** If the session touched the harness, the baselines, CI, or the agent rules, its work is reverted. The scoreboard belongs to the human operator.
3. **The ratchet** (`harness/ratchet.sh`) runs: gofmt, vet, and unit tests; a build for all three platforms; then every enabled **conformance suite**. The conformance suites are other people's test suites for the real AWS APIs:
   - Ceph's s3-tests
   - Scylla's DynamoDB tests
   - moto's SQS/IAM/Lambda/Route 53 tests
   - aws CLI round trips
4. **The verdict:**
   - More tests pass → the work is kept and the baseline is raised.
   - Anything that used to pass now fails → the session is reverted and saved on a `harness/reverted-*` branch.
   - Three sessions in a row with no progress → the loop writes `STUCK.md`, sends an optional push notification, and stops instead of spending more usage.

Numbers can only go up, agents can't edit the numbers, and GitHub Actions re-checks everything independently on every push.

## First night (about 45 minutes)

On the dev machine (macOS with Homebrew shown):

```bash
brew install go python@3.12 awscli tmux        # Homebrew python: the DynamoDB suite needs >= 3.11
cd citadel
git init -b main && git add -A && git commit -m "scaffold: citadel M0"
```

Create a **public** GitHub repo (public repos get free Actions minutes, including arm64 and macOS runners), then push:

```bash
git remote add origin git@github.com:<owner>/citadel.git && git push -u origin main
```

Sanity check. The first conformance run downloads the pinned suites and builds venvs once:

```bash
make check
harness/conformance.sh s3          # expect "s3: 0 passed, 494 failed": the stub answers NotImplemented to everything
harness/conformance.sh smoke-s3    # expect 0/12
```

Start the shift:

```bash
tmux new -s night
harness/loop.sh --until 07:30 --push     # models and effort come from harness/loop.env
# detach with Ctrl-b d. On a macOS host the loop keeps the machine awake with caffeinate (a closed laptop still sleeps).
```

In the morning:

```bash
harness/report.sh
```

Optional push notifications: subscribe a phone to a hard-to-guess **ntfy** topic and `export NTFY_TOPIC=<topic>` before starting the loop. A push arrives when the loop gets stuck or hits a usage limit.

Before M4 (SQS) on macOS, turn off **System Settings → General → AirDrop & Handoff → AirPlay Receiver**. moto's tests need port 5000, which AirPlay uses on macOS.

## Models and usage

**Model setup.** Model choice lives in `harness/loop.env`, so switching models is a one-line edit rather than a code change. Flags override it for a single night.

| Setting | Default | What it does |
|---|---|---|
| `CLAUDE_MODELS` | `opus,sonnet` | Model chain, best first. Every session runs on the first model until that model hits its own usage limit. The loop then continues on the next model instead of sleeping, and goes back to the first after `STEP_UP_AFTER_MIN` (5 h, one usage window). |
| `CLAUDE_EFFORT` | empty (model default) | `low` to `max`. The biggest lever on usage after the model itself. |
| `CLAUDE_SUBAGENT_MODEL` | `sonnet` | Model for any subagents a session spawns. Subagents mostly search and read; on the largest model they'd multiply usage. Leave it empty to use the session's model. |

**New models.** Aliases (`opus`, `sonnet`, `haiku`) follow whatever Claude Code currently maps them to, so when newer Sonnet or Haiku releases land, the chain picks them up with no edit. To freeze a version, use its full ID (`claude-opus-5-5`).

**One-night overrides:**

```bash
harness/loop.sh --models sonnet                          # an all-Sonnet night, e.g. to compare
harness/loop.sh --models opus,sonnet,haiku               # longer chain for a long night
harness/loop.sh --model claude-opus-5-5 --effort high    # pinned model, more thinking
```

**Judge models on results.** `harness/report.sh` prints a per-model line: sessions judged, how many improved the scores, how many were reverted, and how many limit hits. Compare kept work per usage window across models; that's the number to decide on.

**Usage and billing safety.**
- Subscription plans meter Claude Code in rolling usage windows, and one agent session uses many prompts. When every model in the chain is out, the loop sleeps and retries; when it reports a weekly limit, it stops.
- Leave paid overage ("extra usage") off in the account settings if the night shift must never cost more than the subscription.
- **Never set `ANTHROPIC_API_KEY`.** In `-p` mode Claude Code prefers it over a subscription login and bills per token. The harness unsets `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY` and `CODEX_API_KEY` so subscription-based CLIs never bill per token. Also never use `--bare`: it ignores the subscription login.

**Second lane.** `harness/loop.sh --agent codex` runs Codex CLI on its own separate limits. Its model chain is `CODEX_MODELS` in the same file. Codex reads AGENTS.md natively.

## Where to run the loop

- **A macOS dev machine (default).** Claude Code runs in auto mode: a classifier reviews shell commands, and `harness/claude-loop-settings.json` adds allow rules for the build tools and deny rules for credentials and the protected paths. `--yolo` is refused on macOS.
- **palaven-1, once it exists (better).**
  - It has 12 GB of RAM, stays on, and is disposable, so the loop can run with `--yolo` there as a non-root user.
  - For auth on a headless box: run `claude setup-token` on a machine with a browser (it prints a one-year subscription token) and `export CLAUDE_CODE_OAUTH_TOKEN=...` on the VM.
  - Oracle cut the Always Free ARM allowance to **2 OCPU / 12 GB on June 15, 2026**, and reports disagree on whether pay-as-you-go accounts get billed above it. Stay on the pure free tier.

## The operator's part (about 5 minutes a morning)

1. `harness/report.sh`: what was kept, what was reverted, the scores.
2. **Review skip-list and ROADMAP.md edits** (the report prints the diffs). They're the only places an agent can quietly lower the bar.
3. If `STUCK.md` exists, open an interactive session (e.g. `claude --model opus --effort high`) in the repo. Unstick it, or split the milestone into smaller steps. Then delete `STUCK.md`, commit, and restart.
4. Once per milestone, run a code-review pass. The ratchet guarantees behaviour, not code quality.
5. The `Concept:` lines in PROGRESS.md are two-sentence lessons in how AWS actually works.

## Expectations

- Rung 1 (the AWS APIs) takes weeks to a few months of nightly sessions, Rung 2 (Terraform) is likely, and Rung 3 (real multi-region) is plausible. Rung 4 (self-hosting) is a long-running goal.
- Stuck nights tend to cluster around SigV4 chunked uploads, the DynamoDB expression grammar and number ordering, and replication. Those are the spots that need an interactive session.

## Layout

```
cmd/citadel/        the binary
internal/           api (front door) and bootstrap exist; services arrive milestone by milestone
harness/            loop, ratchet, conformance runners, smoke tests, model config (loop.env), agent settings (protected)
conformance/        suite pins, enabled suites, baselines (protected), skip lists (reviewed)
.github/workflows/  ci (3 platforms) and conformance (independent referee)
```
