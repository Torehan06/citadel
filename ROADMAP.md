# Roadmap

The harness gives agents the first milestone whose heading lacks `[done]`. Each milestone lists what to build, how it's judged, and when it's finished.

Agents may tick checkboxes, add sub-steps, and mark a milestone `[done]` once its exit criteria hold. They may add suites to `conformance/suites` when a milestone says to. Lowering an exit criterion is a human decision, and every edit to this file shows up in the morning report.

- **Rung 1, "It speaks AWS":** M0–M6
- **Rung 2, "Terraform believes it":** M7
- **Rung 3, "Three regions, one cloud":** M8–M12
- **Rung 4, "It hosts itself":** M13–M14

## M0 — Skeleton [done]
- [x] `citadel serve` with region, listen, data, bootstrap and conformance flags; `/_citadel/healthz`
- [x] Service detection (SigV4 scope, X-Amz-Target, paths) and 501 NotImplemented in each protocol's error format
- [x] Conformance runners for s3, smoke-s3, ddb, sqs, iam, lambda, route53; ratchet; night-shift loop; CI

## M1 — First bucket [done]
Goal: `aws s3 cp` works against a single region.
Start here: every s3-tests test runs **ListBuckets** in its setup fixture. Its teardown empties prefixed buckets with **ListObjectVersions**, **DeleteObjects** and **DeleteBucket**. Until SigV4 plus those four operations work, no s3 test can pass, so build them first. Unversioned buckets report versions with `VersionId` `null`.
- [x] `internal/store`: SQLite (WAL, single writer), numbered migrations, change log table, HLC
- [x] Blob store: stream to tmp while hashing (SHA-256, MD5, requested checksum), fsync, rename
- [x] `internal/sigv4`: header auth, presigned URLs, UNSIGNED-PAYLOAD, aws-chunked (signed and unsigned) with trailing checksums, clock-skew check
- [x] Load bootstrap identities into the store (accounts, canonical IDs, keys)
- [x] S3: ListBuckets, CreateBucket (incl. LocationConstraint), HeadBucket, DeleteBucket, PutObject, GetObject (+ Range), HeadObject, DeleteObject, DeleteObjects, ListObjects v1/v2 (prefix, delimiter, pagination)
- [x] S3 error codes and XML exactly as AWS: NoSuchBucket, NoSuchKey, BucketAlreadyOwnedByYou, BucketNotEmpty, InvalidBucketName, SignatureDoesNotMatch, AccessDenied...
Conformance: `smoke-s3`, `s3`.
Exit: all 12 `smoke-s3` steps pass except `put-multipart`, `get-multipart` and `sync-roundtrip` (those land in M2); `s3` ≥ 120 passing.

## M2 — Real S3
Goal: the S3 surface everyday tools touch.
- [ ] Multipart upload (create, upload part, upload part copy, list parts, complete, abort, list uploads), stored as a part manifest with no byte copying
- [ ] CopyObject (metadata directives), conditional requests (If-Match / If-None-Match / If-Modified-Since, conditional writes)
- [ ] Object metadata, content headers, response-header overrides, checksums returned with ChecksumMode
- [x] Versioning: version IDs, delete markers, ListObjectVersions
- [ ] Tagging (object, bucket), CORS config + preflight, lifecycle config storage (no expiry execution yet)
- [ ] Canned ACLs, grant headers, bucket policy evaluation for the s3-tests subset; ownership controls; public access block
- [ ] Blob garbage collection (refcounts + sweeper)
Conformance: `smoke-s3`, `s3`.
Exit: all `smoke-s3` steps pass; `s3` ≥ 300 passing (about 60% of the selection).

## M3 — DynamoDB
Goal: tables, items, and the expression language.
- [ ] JSON 1.0 dispatch and error envelope (`__type`, ValidationException, ResourceNotFoundException, ConditionalCheckFailedException...)
- [ ] Order-preserving key encoding for S/N/B (exhaustive unit tests, especially negative and 38-digit numbers)
- [ ] CreateTable / DescribeTable / DeleteTable / ListTables / UpdateTable, with table status transitions
- [ ] PutItem / GetItem / UpdateItem / DeleteItem with ReturnValues
- [ ] Expression parser (`internal/ddb/expr`): condition, update, projection, filter, key condition, with attribute names and values
- [ ] Query / Scan: pagination (ExclusiveStartKey), Limit, Select, segments (parallel scan)
- [ ] GSIs and LSIs, BatchGetItem / BatchWriteItem, TransactGetItems / TransactWriteItems, TTL config, tags
- [ ] Size and limit validation (400 KB items, key sizes, nesting depth)
Conformance: add `ddb` to `conformance/suites` when you start this milestone.
Exit: `ddb` ≥ 450 passing.

## M4 — SQS
- [ ] JSON 1.0 protocol plus query protocol fallback
- [ ] Standard queues: create, get URL, attributes, send / receive / delete (+ batch), visibility timeout, change visibility, delay, purge
- [ ] Long polling up to 20 s without busy loops; message attributes and MD5s exactly as AWS computes them
- [ ] Redrive policy / DLQ, message retention
- [ ] FIFO: dedup (content-based and explicit), message groups, ordering
- [ ] Queue URLs as `http://<host>/<account>/<name>`. moto's tests expect account 123456789012.
Conformance: add `sqs` to `conformance/suites`.
Exit: `sqs` ≥ 110 passing.

## M5 — IAM and STS
- [ ] Query protocol for IAM and STS
- [ ] Users, groups, roles, access keys, managed and inline policies, attachments, instance-profile stubs Terraform needs
- [ ] STS: GetCallerIdentity, AssumeRole (temporary `ASIA…` keys + session tokens understood by `internal/sigv4`)
- [ ] Policy evaluation (identity + resource policies, explicit deny, common condition operators), enforced for S3, DynamoDB and SQS actions
Conformance: add `iam` to `conformance/suites`.
Exit: `iam` ≥ 150 passing; no `s3` or `ddb` regressions from enforcement.

## M6 — Lambda on WebAssembly
- [ ] Lambda API: Create / Get / List / Update (code + configuration) / Delete function, versions, aliases, tags, concurrency settings
- [ ] Runtime: wazero, `provided.al2023` zips with `bootstrap.wasm`; stdin event, stdout response, stderr logs; timeout and memory limits; compiled-module cache
- [ ] Invoke: RequestResponse, Event (async queue), DryRun; error payloads (`FunctionError`)
- [ ] Log streams under `/aws/lambda/<fn>` (minimal CloudWatch Logs API: DescribeLogStreams, GetLogEvents, FilterLogEvents)
- [ ] SQS event source mappings; S3 event notifications to Lambda and SQS (from the change log)
- [ ] `examples/functions/hello-go` (GOOS=wasip1) and a smoke step: `aws lambda invoke` returns its payload
Conformance: add `lambda` to `conformance/suites`.
Exit: `lambda` ≥ 45 passing (the Docker-based invoke tests stay red, which is expected); the hello-go smoke passes; an SQS message triggers the function within 2 s.

## M7 — Terraform believes it
Goal: a real Terraform stack applies cleanly against one region.
- [ ] `examples/terraform/single-region/`: `hashicorp/aws` provider with `endpoints {}`, `skip_credentials_validation`, `skip_requesting_account_id`, `skip_metadata_api_check`, `skip_region_validation`, `s3_use_path_style`
- [ ] Resources: S3 bucket (+ versioning, policy, lifecycle), DynamoDB table (+ GSI), SQS queue (+ DLQ), IAM role + policy, Lambda function + SQS event source mapping
- [ ] Implement every read the provider performs until `terraform plan` after `apply` shows **no changes**
- [ ] `harness/smoke.sh` gains a `terraform` set (human adds the harness side; request it in PROGRESS.md)
Exit: `init`, `apply`, `plan -detailed-exitcode` (exit 0), and `destroy` pass twice in a row from fresh state.

## M8 — Local multi-region
Goal: three regions on one machine, with the global control plane replicated.
- [ ] Region registry config; three local processes on different ports and data dirs (script under `examples/multiregion-local/`)
- [ ] Control-plane change feed from the home region; followers apply in order and survive restarts
- [ ] Static stability: stop the home region (SIGSTOP) and followers keep serving data-plane requests with existing credentials
- [ ] Integration tests in Go that start real processes
Exit: a key created in the home region authenticates in both followers within 5 s; data-plane requests succeed in followers while the home region is stopped.

## M9 — Replication
- [ ] S3 cross-region replication (PutBucketReplication / GetBucketReplication), versioning required, delete markers replicated
- [ ] DynamoDB global tables (UpdateTable ReplicaUpdates), LWW on (hlc, region)
- [ ] Per-destination cursors with retry/backoff; anti-entropy Merkle digests; replication lag metric
- [ ] Terraform example `examples/terraform/multi-region/` with provider aliases; clean plan after apply
Exit: in the local 3-region setup, writes converge after a region is stopped for 10 minutes and resumed; p99 replication lag < 5 s locally.

## M10 — Real regions
- [ ] Deploy script: cross-compile, copy over Tailscale SSH, launchd (macOS) and systemd (Linux) units
- [ ] Codespace region bootstrap (devcontainer: Tailscale in userspace-networking mode with an ephemeral auth key from Codespaces secrets)
- [ ] Region keys for internal replication auth, stored outside the repo
Exit: from the dev laptop, `aws --endpoint-url http://palaven-1:8420 s3 ls` works; an object written on `tuchanka-1` appears on `palaven-1`.

## M11 — Global DNS and failover
- [ ] Authoritative DNS (miekg/dns) on the Linux regions; Route 53 API subset (hosted zones, change batches, health checks, failover routing)
- [ ] Tailscale split DNS for `citadel.internal`
Conformance: add `route53` to `conformance/suites`.
Exit: `route53` ≥ 45 passing; with `s3.citadel.internal` failover records, stopping the primary region moves resolution to the secondary within 60 s.

## M12 — Canaries and SLOs
- [ ] Canary probes from every region to every region; `/_citadel/metrics`
- [ ] SLO and error-budget computation; status page served from S3 static website hosting (also enable the s3website tests: a human widens the selection)
Exit: the status page shows 7-day SLO attainment for all three regions.

## M13 — Forgejo on Citadel
- [ ] Forgejo on `palaven-1` with LFS, attachments, and packages stored in Citadel S3; push mirror to GitHub
- [ ] Forgejo Actions runner that runs `make check` and the ratchet
Exit: a push to Forgejo triggers a green CI run, and the GitHub mirror updates.

## M14 — It deploys itself
- [ ] Release bucket, desired-version record in the control plane, per-region deploy agent
- [ ] Rollout order `thessia-1` → bake 10 min on canary SLOs → `tuchanka-1` → `palaven-1`; automatic rollback
- [ ] The night-shift loop pushes to Forgejo instead of GitHub
Exit: a `-tags badrelease` build is rolled back automatically with no human action, and a good build reaches all three regions unaided.
