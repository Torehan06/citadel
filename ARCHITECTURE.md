# Citadel architecture

Citadel is a small AWS-compatible cloud with three regions on free machines, built mostly by coding agents. Real AWS clients have to accept it: the `aws` CLI, boto3, and the Terraform AWS provider. The long-term goal is that it hosts its own git server and CI, and deploys itself.

This document is the contract agents build against. Sections are self-contained, so read the one your task touches.

---

## 1. Goals and non-goals

**Goals**
- Wire compatibility with the AWS APIs we implement, so real clients and upstream test suites can judge us (§3).
- Three regions that keep serving when another region is down, with asynchronous cross-region replication.
- Runs comfortably on an 8 GB laptop next to an editor and a browser. Target: a region process under 256 MiB RSS.
- Operable like a real service: metrics, canaries, SLOs, a status page, progressive deploys with automatic rollback.

**Non-goals**
- Security against a real attacker. Citadel lives on a private tailnet with test credentials. It enforces auth so clients behave realistically, not to protect anything.
- Durability guarantees beyond "fsync, then rename" plus replication. No erasure coding (yet).
- EC2, VPC, billing, organizations, KMS-backed encryption, the thousands of other AWS APIs.
- Being LocalStack. We aim for a coherent small cloud, not the widest mock.

---

## 2. Topology

| Region | Machine | Platform | Character |
|---|---|---|---|
| `tuchanka-1` | A laptop | darwin/arm64 | Sleeps when the laptop sleeps. Dev region. |
| `palaven-1` | Oracle Cloud Always Free Ampere A1 VM | linux/arm64 | Always on. **Home region** for global control-plane state (§7). Since June 15, 2026 the free tier is 2 OCPU / 12 GB. Oracle may reclaim idle Always Free instances. |
| `thessia-1` | GitHub Codespace (free monthly core-hours) | linux/amd64 | Ephemeral. Dies after an idle timeout. The canary region for deploys (§10). |

```
                 tailnet (Tailscale, WireGuard mesh, MagicDNS)
   ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
   │ tuchanka-1 (dev) │◄───►│ palaven-1 (OCI)  │◄───►│ thessia-1 (CS)   │
   │ citadel :8420    │     │ citadel :8420    │     │ citadel :8420    │
   │                  │     │ DNS :53, home CP │     │ DNS :53          │
   └──────────────────┘     └──────────────────┘     └──────────────────┘
            ▲  aws CLI / boto3 / terraform, via *.citadel.internal (split DNS)
```

- All traffic stays on the tailnet. The one optional public surface is the read-only status page through Tailscale Funnel.
- GitHub Actions (free for public repos) is the fourth, non-region machine. It runs the conformance suites as an independent referee.

---

## 3. Principles

1. **Wire-compatible or nothing.** If AWS has an API for it, we speak that API byte for byte (status codes, error codes, XML/JSON shapes, header names). We never invent a parallel API for something AWS already does.
2. **Conformance suites decide, not opinions.** A feature is done when an upstream test suite or a real client says so (§11). Agent-written tests support the conformance suites but never replace them.
3. **One static binary per region.** `CGO_ENABLED=0`, all services in one process, cross-compiled to all three platforms. No external database, no containers required.
4. **Static stability.** A region's data plane keeps serving reads and writes when every other region, including the home region, is unreachable. Cross-region work is asynchronous and retried.
5. **Small and legible.** Standard library first. Every dependency has to justify itself in PROGRESS.md. A human should be able to open `meta.db` in DataGrip and understand the schema.

---

## 4. Process model and request routing

`citadel serve` runs every service in one HTTP server. The front door (`internal/api`) assigns a request ID, detects the target service, and dispatches.

**Service detection (decision D4).** A signed request says which service it is for: the SigV4 credential scope `AKID/20260925/us-east-1/s3/aws4_request` names `s3`. Detection order:
1. The credential scope in the `Authorization` header or the presigned `X-Amz-Credential` parameter.
2. `X-Amz-Target` (`DynamoDB_20120810.*` → dynamodb, `AmazonSQS.*` → sqs).
3. Path prefixes (`/2015-03-31/` → lambda, `/2013-04-01/` → route53).
4. Everything else is S3, the only API that accepts anonymous requests.

| Service | AWS protocol | Wire notes |
|---|---|---|
| S3 | REST-XML | Path-style first (`/bucket/key`). Virtual-host style (`bucket.s3.citadel.internal`) comes later. |
| DynamoDB | JSON 1.0 | `POST /`, `X-Amz-Target`, `application/x-amz-json-1.0` |
| SQS | JSON 1.0 (and legacy query) | Current SDKs use JSON. Accept query (`Action=`) too for old clients. |
| IAM, STS | Query (form POST, XML responses) | `Action=CreateRole&Version=2010-05-08` |
| Lambda | REST-JSON | `/2015-03-31/functions/...` |
| Route 53 | REST-XML | `/2013-04-01/hostedzone/...` |

**Errors.** Each protocol has its own error envelope (`internal/api/errors.go`), and SDKs parse these to raise typed exceptions. Operations that don't exist yet answer **501 NotImplemented** at once. SDKs don't retry 501. A 500 would trigger retries with backoff and slow every conformance run to a crawl.

**Internal endpoints** live under `/_citadel/` (not a valid bucket name): `healthz`, `metrics`, and later the replication APIs. With `--conformance`, the region also serves moto's `/moto-api/reset`. It must wipe all service state and do nothing else.

---

## 5. Identity and authentication

- **Accounts** are 12-digit IDs. Each has an S3 canonical ID (for ACL `Owner.ID`) and IAM users with access keys. `harness/bootstrap.json` seeds the test identities that every conformance suite uses.
- **SigV4 verification** (`internal/sigv4`) must handle:
  - the `Authorization` header and presigned query parameters;
  - `UNSIGNED-PAYLOAD`;
  - `aws-chunked` bodies (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, and trailer variants with trailing checksums). **The aws CLI v2 and current SDKs send chunked uploads with trailing CRC checksums by default, so `aws s3 cp` fails until this works.** Verify the checksum they send and store it for `GetObject` with `ChecksumMode=ENABLED`.
- **Region in the credential scope:** accept whatever region the client signed with (s3-tests signs as `us-east-1`). A resource's region is a property of the resource, not of the signature.
- **Clock skew:** allow ±15 minutes, as AWS does. Return `RequestTimeTooSkewed` beyond that.
- **Authorization, phased:**
  - M1: any valid key may do anything in its own account.
  - M2: bucket ACLs and bucket policies, the subset s3-tests covers.
  - M5: IAM identity policies, STS `AssumeRole` temporary credentials (`ASIA...` keys + session token), and the standard evaluation order: explicit deny, then allow from identity or resource policy, then implicit deny.

---

## 6. Storage (per region)

Everything a region owns lives under `--data`:

```
data/
  meta.db          SQLite (modernc.org/sqlite, pure Go), WAL mode
  blobs/sha256/ab/cd/<hex>   content-addressed object bytes
  blobs/tmp/                 in-flight uploads
  wasm-cache/                wazero compiled-module cache
```

**meta.db rules**
- One write connection (`SetMaxOpenConns(1)` on the writer `*sql.DB`) and a separate read pool. `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`.
- Schema migrations are numbered Go files applied at startup, never edited after merge.
- **Change log (transactional outbox).** Every mutation appends a row to `changes(seq, hlc, service, kind, resource, payload)` in the same transaction. Replication, event notifications (S3 → Lambda, S3 → SQS), and the control-plane feed all read this log. Nothing reads state and diffs it later.

**Blobs**
- Upload flow: stream the body to `blobs/tmp/<random>` while computing SHA-256 (address), MD5 (ETag), and any requested checksum. Then fsync, rename into place, and commit metadata. Never buffer a whole object in memory.
- Multipart: each part is a blob, and completion writes a manifest of part blobs, so no bytes are copied. The ETag is `md5(concat(part_md5s))-N`, as in S3.
- Deletion is reference-counted from metadata. A background sweeper removes blobs with no references after a grace period.
- Replication ships only the blob hashes the destination lacks.

**Hybrid logical clocks.** Every change carries an HLC (48-bit wall-clock ms + 16-bit counter) and the origin region ID. Cross-region conflicts resolve last-writer-wins on `(hlc, region)`. The laptop's clock drifts and sleeps, so wall-clock time alone isn't safe.

**Service data models (starting points, not handcuffs)**
- **S3:**
  - `buckets(name, account, region, created, versioning, policy, acl, ...)`
  - `objects(bucket, key, version_id, is_latest, delete_marker, size, etag, blob_or_manifest, meta_json, hlc)`
  - List operations use SQLite's ordering on `key` (byte order, which matches S3's UTF-8 binary order).
- **DynamoDB:** `items(table_id, pk BLOB, sk BLOB, item BLOB)` with keys in an **order-preserving binary encoding**, so `ORDER BY sk` gives DynamoDB order.
  - Numbers are the hard part: 38-digit decimals, where negative numbers order in reverse. Unit-test the encoding exhaustively.
  - GSIs and LSIs are maintained in the same transaction. That's stricter than AWS, which is allowed.
  - Expressions (condition, update, projection, filter, key condition) get their own parser package with table-driven tests.
- **SQS:** `messages(queue_id, seq, body, attrs, visible_at, receive_count, group_id, dedup_id)`.
  - Receive is an `UPDATE ... RETURNING` that moves `visible_at`.
  - Long polling waits on an in-process per-queue notifier (up to 20 s).
  - FIFO holds a per-group lock while a message from that group is in flight.

---

## 7. Global control plane (decision D5)

Global state covers accounts, users, keys, roles, policies, the region registry, and DNS zones. Each piece has one writer: the **home region, `palaven-1`**. The other regions keep read replicas.

- Followers pull `GET /_citadel/repl/control?since=<seq>` from the home region and apply entries in order. Requests use an HMAC over a shared region key and travel only over the tailnet.
- If the home region is down, followers keep authenticating with their replica. That's static stability. Control-plane writes (for example `CreateUser`) fail with `ServiceUnavailable` until it returns.
- This mirrors AWS itself: IAM's control plane lives in `us-east-1` and its data plane is replicated to every region. Route 53's control plane is also in `us-east-1`.

**Why not Raft?** Two of our three nodes are unreliable: the laptop sleeps and the Codespace dies. A 3-node quorum over them would be unavailable more often than one stable leader. Raft stays a stretch goal once there are three always-on machines.

---

## 8. Data-plane replication

| Service | Model | Conflict rule |
|---|---|---|
| S3 | Cross-region replication per bucket via `PutBucketReplication` (Terraform `aws_s3_bucket_replication_configuration`). Versioning is required on both sides, as in AWS. | LWW on `(hlc, region)`; delete markers replicate |
| DynamoDB | Global tables via `UpdateTable` `ReplicaUpdates` (Terraform `replica {}` blocks). Semantics of global tables version 2019.11.21. | LWW per item |
| SQS, Lambda | Regional only, as in AWS. Deploy per region with Terraform provider aliases. | n/a |

- The source region tails its change log and pushes to the destination over `/_citadel/repl/...`. It tracks a per-destination cursor and retries with backoff.
- **Anti-entropy.** Periodically compare per-bucket (per-table) Merkle digests over key ranges, then repair differences. This covers the laptop region waking up after a week asleep.
- **Promised to clients:** read-after-write within a region, eventual consistency across regions, and replication lag as a measured SLO (§9).

---

## 9. Compute: Lambda on WebAssembly (decision D3)

- **Runtime:** [wazero](https://wazero.io), pure Go, so it keeps the single static binary and needs no KVM. Neither the laptop (macOS) nor the Oracle VM offers KVM for microVMs.
- **Packaging:** a normal Lambda zip containing `bootstrap.wasm`, a WASI preview 1 command module. `Runtime` is `provided.al2023`, so the aws CLI and Terraform validation accept it unchanged.
- **Invocation contract:**
  - The event JSON arrives on stdin, and the response JSON goes to stdout.
  - Logs go to stderr and are stored as CloudWatch-style log streams under `/aws/lambda/<name>` in `meta.db`.
  - Environment variables come through WASI env.
  - `Timeout` is enforced by context cancellation (`WithCloseOnContextDone`), and `MemorySize` by `WithMemoryLimitPages`.
- **Performance:** compiled modules are cached on disk (`wazero.NewCompilationCacheWithDir`) and in memory under a size cap. Each invocation gets a fresh module instance at first. Pooling comes later.
- **Languages:** Go (`GOOS=wasip1 GOARCH=wasm`), Rust (`wasm32-wasip1`), and TinyGo. Examples live in `examples/functions/`.
- **Event sources:**
  - SQS event source mappings, where a poller in the region invokes the function.
  - S3 event notifications to Lambda or SQS, fed from the change log.
- **Stretch:** a `citadel` host module so functions can call S3/DynamoDB without network sockets (WASI p1 has none).

---

## 10. Operations: DNS, canaries, SLOs, self-deployment

**Global DNS**
- `palaven-1` and `thessia-1` run an authoritative server (`github.com/miekg/dns`) on port 53 of their tailnet IP. Use `setcap cap_net_bind_service` rather than running as root.
- Tailscale split DNS sends `citadel.internal` to them. (`.internal` is reserved for private use.)
- A Route 53 API subset (hosted zones, record sets, health checks, failover routing) manages records. Example: `s3.citadel.internal`, with `palaven-1` as primary and `tuchanka-1` as secondary.
- Each DNS server runs its own health checks, and a region counts as unhealthy when both checkers agree.

**Canaries and SLOs**
- A built-in canary runs every minute from each region against every region: put/get/delete an object, a DynamoDB write/read, SQS send/receive, and a Lambda invoke.
- Results go into `meta.db` and `/_citadel/metrics` (Prometheus text format).
- Starting SLOs, tighten later:

| SLI | Objective (7-day window) |
|---|---|
| S3 GET success, per region, from canaries | 99.0% |
| DynamoDB GetItem p99 latency, in-region | < 50 ms |
| S3 cross-region replication lag p99 | < 60 s |

- The status page shows SLO attainment and remaining error budget. It's a static site served from Citadel's own S3 website hosting.

**Self-deployment (rung 4)**
- Forgejo runs on `palaven-1` with SQLite, and stores LFS, attachments, and packages in Citadel S3 (Forgejo's `minio` storage type speaks S3). A Forgejo Actions runner builds Citadel. GitHub stays as a push mirror and as the public face.
- **Release flow:**
  1. CI uploads `citadel-releases/<sha>/citadel-<os>-<arch>` to a replicated bucket.
  2. CI sets the desired version in the control plane.
  3. A small deploy agent in each region polls the desired version.
  4. Rollout order: `thessia-1` first as the canary, then a 10-minute bake that checks canary SLOs, then `tuchanka-1`, then `palaven-1`.
  5. If the canary error rate breaches the SLO during the bake, roll back to the previous binary automatically, with no human involved.
- The acceptance test for this is automated: a build made with `-tags badrelease` fails canaries on purpose and must be rolled back unaided.

---

## 11. Conformance suites

| Suite | Upstream | What it judges | Enabled at |
|---|---|---|---|
| `s3` | [ceph/s3-tests](https://github.com/ceph/s3-tests), about 494 tests after exclusions | S3 API behaviour | M1 |
| `smoke-s3` | aws CLI v2 round trips (`harness/smoke.sh`) | Real client defaults: chunked uploads, checksums, multipart, sync, presign | M1 |
| `ddb` | [Scylla Alternator tests](https://github.com/scylladb/scylladb/tree/master/test/alternator), about 900 tests selected | DynamoDB API behaviour. DynamoDB-correct results that Scylla marks xfail count as passes. | M3 |
| `sqs` | moto's SQS tests in server mode | SQS behaviour | M4 |
| `iam` | moto's IAM tests in server mode | IAM API | M5 |
| `lambda` | moto's Lambda tests in server mode (API surface; their Docker-based invoke tests will stay red) | Lambda control plane | M6 |
| `route53` | moto's Route 53 tests in server mode | Route 53 API | M11 |
| Terraform | `examples/terraform/*`: `apply`, then `plan -detailed-exitcode` must report no changes, then `destroy` | Every resource reads back exactly as written | M7 |

Suites are pinned by commit (`conformance/pins.env`). `harness/ratchet.sh` keeps the passing set per suite in `conformance/baseline/`, and that set can only grow. See AGENTS.md for the rules and README.md for the loop.

---

## 12. Package map

```
cmd/citadel/        entrypoint, flags, signal handling
internal/api/       front door: service detection, error envelopes, dispatch     (exists)
internal/bootstrap/ seed identities from harness/bootstrap.json                  (exists)
internal/sigv4/     SigV4 verification, presigned URLs, aws-chunked, trailers
internal/store/     SQLite setup, migrations, change log, HLC, blob store
internal/s3/        S3
internal/ddb/       DynamoDB (expr/ subpackage for the expression language)
internal/sqs/       SQS
internal/iam/       IAM, STS, policy evaluation
internal/lambda/    Lambda API + wazero runtime
internal/dns/       authoritative DNS + Route 53 API
internal/region/    region registry, control-plane follower, replication
internal/canary/    probes, SLOs, status page
```

Keep this map flat: one package per service, with subpackages only when a piece (like the expression parser) has its own tests and no service dependencies.

---

## 13. Decision log

| # | Decision | Why | Revisit when |
|---|---|---|---|
| D1 | Go, `CGO_ENABLED=0`, one binary | Cross-compiles to all three regions; small memory footprint; strong stdlib HTTP | never, realistically |
| D2 | SQLite (modernc, pure Go) for metadata + content-addressed files for bytes | Transactions and ordered indexes for free; inspectable in DataGrip; no server process | metadata write throughput becomes the bottleneck |
| D3 | wazero instead of wasmtime or microVMs | Pure Go (no cgo), no KVM needed, millisecond cold starts | we need real Linux-binary Lambdas |
| D4 | Dispatch on SigV4 credential scope | Signed requests say their own service. Avoids fragile guesses between S3 and JSON/query APIs that share `POST /`. | never |
| D5 | Home-region control plane, not Raft | Two of three nodes are flaky. Same shape as AWS IAM and Route 53. | three always-on nodes exist |
| D6 | Real `hashicorp/aws` Terraform provider with custom `endpoints`, not a custom provider | The provider reads every attribute back, so "clean plan after apply" is a very strict conformance test, and we write no provider code | never |
| D7 | Conformance suites pinned, ratchet owned by the harness, not by agents | Agents optimise whatever number they can edit | never |
