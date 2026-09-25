# AGENTS.md

You're working on **Citadel**, a small AWS-compatible cloud (see ARCHITECTURE.md). Usually you're running unattended under `harness/loop.sh`: one session, one task, then exit. Nobody can answer questions. Make the reasonable call and write it down.

## Every session

1. Read the prompt the harness gave you (milestone, last ratchet, failing test families).
2. Read the tail of PROGRESS.md (last ~40 lines) and the ARCHITECTURE.md section your task touches. Don't read the whole repo.
3. Pick **one** step, build it, commit, write a PROGRESS.md entry, commit, exit.

## Commands

```
make check                                   # gofmt + vet + unit tests + build for darwin/arm64, linux/arm64, linux/amd64
harness/oracle.sh s3 -k test_bucket_list     # targeted oracle run: short tracebacks + server log path
harness/oracle.sh s3 --quiet                 # full suite, one-line summary (slow; the harness runs it after you anyway)
make serve                                   # dev region on 127.0.0.1:8420 (the aws CLI is preconfigured via harness/aws.config)
AWS_CONFIG_FILE=harness/aws.config AWS_SHARED_CREDENTIALS_FILE=harness/aws.credentials aws s3 ls
```

Oracle results live in `.harness/results/`:
- `<suite>.fail` and `<suite>.todo` list the failing tests.
- `<suite>.server.log` is Citadel's log for that run. Grep it rather than reading it whole.
- `targeted-<suite>.pytest.log` has the full output of your last targeted run.

## How to work

- **Oracles are the spec.** Before implementing an operation, read the failing test's source in `.harness/cache/` (`s3-tests/`, `alternator/test/alternator/`, `moto/tests/`) and the AWS API reference (docs.aws.amazon.com). Match AWS, not the test's implementation details. When AWS and a test disagree, AWS wins. Note it in PROGRESS.md and in your commit message.
- **Implement behaviour generally.** Never special-case test fixtures: bucket prefixes like `citadel-`, test names, the moto account ID, or known keys. Code that passes a test by recognising it is cheating. The human reviews for it.
- **Unimplemented operations return 501 NotImplemented** in the service's error envelope (`internal/api/errors.go`). Never 500 for "not built yet": SDKs retry 500s, and that slows every run.
- **Stream, don't buffer.** Object bodies go through `io.Reader`s to disk. The process should stay under 256 MiB.
- **Pure Go only.** `CGO_ENABLED=0` must build all three targets (`make check` verifies it). Use the standard library first. A new dependency needs a sentence in PROGRESS.md explaining why. Pre-approved: `modernc.org/sqlite`, `github.com/tetratelabs/wazero`, `github.com/miekg/dns`.
- **Tests.** Add table-driven unit tests next to the code for parsers, encoders, and anything with edge cases. They support the oracles and never replace them.
- **Schema.** Add a new numbered migration. Never edit a migration that's already committed.
- **Keep the tree flat.** Follow the package map in ARCHITECTURE.md §12. No new top-level directories without a reason written down.
- **Save tokens.** Don't print whole large files or full suite outputs. Use `grep`, `head`, `tail`, and `-k` targeted runs.

## Git

- Commit on the current branch. Use small commits with conventional messages (`feat(s3): ListObjectsV2 continuation tokens`).
- Always run `make check` before committing. Never commit a tree that fails to build.
- Never push, force, rebase, amend commits you didn't make, or switch branches. The harness owns history.

## Protected paths: the harness reverts your whole session if you change them

`harness/`, `oracle/baseline/`, `oracle/pins.env`, `.github/`, `.claude/`, `AGENTS.md`, `CLAUDE.md`, `Makefile`, and removing lines from `oracle/suites`.

If you need one of them changed (a new smoke step, a dependency in an oracle runner), write the request under **Requests for the human** in your PROGRESS.md entry.

You *may*:
- add a suite to `oracle/suites` when the milestone says to;
- tick checkboxes and mark milestones `[done]` in ROADMAP.md once the exit criteria hold;
- add entries to `oracle/skips/<suite>.txt` with a reason, for tests that check non-AWS behaviour (RGW-only error text, Scylla-only features). Skips are reviewed every morning. Skipping a test because it's hard is not a valid reason.

## Hard nos

- No network calls to real cloud providers, and no real credentials. `harness/aws.config` points every SDK at Citadel.
- Don't read or write outside this repository (except Go and pip caches). Never touch `~/.ssh`, `~/.aws`, or shell profiles.
- Don't install system software. If you need a tool, request it in PROGRESS.md.
- Don't expose ports beyond 127.0.0.1.

## PROGRESS.md entry format (append, never rewrite old entries)

```
### YYYY-MM-DD HH:MM · <agent> · M<n> · <one-line summary>
- Did: what changed, in 1–3 bullets
- Oracle: before → after (e.g. s3 112 → 131), or "groundwork, unit tests only"
- Concept: one or two plain sentences on the AWS or systems idea behind the change, for a human reader (e.g. how SigV4 derives a signing key)
- Next: the most sensible next step
- Requests for the human: (only if needed)
```

## When you're stuck

- Two attempts at the same failure without progress means stop. Revert your uncommitted changes (`git restore .`).
- Write a PROGRESS.md entry with what you tried, your best hypothesis, and what would unblock you, then exit.
- A clear "stuck" note is worth more than a flailing session. After three sessions without progress the harness stops the night and writes STUCK.md for the human.
