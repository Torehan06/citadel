# Progress log

Append-only. Newest entries at the bottom. Format in AGENTS.md.

### 2026-09-25 18:00 · scaffold · M0 · Skeleton, oracles, harness
- Did: `citadel serve` stub with service detection and 501 NotImplemented in every protocol's error envelope; bootstrap identities; oracle runners for s3-tests, aws CLI smoke, Alternator (DynamoDB), and moto (SQS, IAM, Lambda, Route 53); ratchet; night-shift loop; CI on all three platforms.
- Oracle: against the stub, s3 0/494, smoke-s3 0/12, ddb 0 passing (about 900 selected), sqs 3/161, iam 3/310, route53 0/67. The few moto passes are tests whose assertions hold against any error.
- Concept: an "oracle" is a test suite written by someone else against the real service. Passing it is evidence of compatibility we can't fake by writing our own tests.
- Next: M1. Start with `internal/store`, `internal/sigv4`, then ListBuckets, ListObjectVersions, DeleteObjects and DeleteBucket. s3-tests' setup and teardown fixtures call those around every test, so nothing passes before they work.

### 2026-09-25 21:10 · claude-opus-5.5 (interactive) · M1 · store, sigv4 and the core S3 surface
- Did: `internal/store` (modernc SQLite: one writer connection + WAL read pool, numbered migrations, `changes` outbox, HLC, two-phase content-addressed blob writes; bootstrap identities seeded into `accounts`/`access_keys`). `internal/sigv4` (header + presigned auth, UNSIGNED-PAYLOAD, declared-hash check at EOF, aws-chunked signed/unsigned with trailers, ±15 min skew; tests use AWS's published example signatures). `internal/s3`: buckets, objects (Range, conditionals, Content-MD5, flexible checksums incl. trailers, default CRC64NVME), ListObjects v1/v2, ListObjectVersions ("null" versions), DeleteObjects. Unknown subresources answer 501.
- Oracle: s3 0 → 166 (ratchet), smoke-s3 0 → 9. Listing edge-case fixes after the ratchet are committed but not yet ratcheted.
- Decisions: LocationConstraint is accepted as given and echoed by GetBucketLocation (s3-tests sends Ceph's "default"). Re-creating your own bucket answers 409 BucketAlreadyOwnedByYou, as in every region except us-east-1, so `test_bucket_create_exists` stays red: it only passes under us-east-1's legacy 200 (its except branch reads a nonexistent `e.status`). Blobs of overwritten/deleted objects are left for the M2 sweeper.
- Known limits: `test_*_bad_expect_mismatch` gets 417 from Go's net/http, which rejects unknown `Expect` values before any handler runs. `test_object_read_unreadable` expects AWS's 400 "Couldn't parse the specified URI" for a key with C1 control characters; the exact AWS rule is unclear, so it's left red.
- Concept: SigV4 never sends the secret. Both sides derive a signing key by chaining HMACs over date → region → service → "aws4_request", then HMAC a canonical form of the request; for aws-chunked uploads each chunk's signature also covers the previous one, so a stream can't be spliced.
- Next: smoke-s3 `list-recursive` greps for `dir/big.bin`, which the multipart step uploads, so the M1 smoke exit needs a basic multipart upload (create/upload part/complete/abort) pulled forward from M2.

### 2026-09-25 22:05 · claude-opus-5.5 (interactive) · M1 · Multipart pulled forward; M1 done
- Did: multipart upload (create, upload part, complete, abort, list parts, list uploads). Parts are blobs, and completion writes a part manifest in the same transaction that retires the upload, so no bytes are copied; GET streams ranges across the manifest. Migration 0002. POST /bucket (PostObject) now answers 501 instead of 405.
- Oracle: M1 overall s3 0 → 189 (of 494), smoke-s3 0 → 12 (of 12). This session's last step: s3 166 → 189, smoke-s3 9 → 12. Final ratchet: green, 66 unit tests.
- Why multipart landed in M1: smoke-s3 `list-recursive` greps for `dir/big.bin`, which only the multipart step creates, so the M1 exit (every step except put/get-multipart and sync-roundtrip) needs it. UploadPartCopy, FULL_OBJECT multipart checksums, and delimiter/upload-id-marker paging in ListMultipartUploads are still M2.
- Concept: a multipart ETag is not an MD5 of the object. It's the MD5 of the concatenated binary part MD5s plus "-N", which is why clients can't check a multipart download against its ETag and S3 added flexible checksums.
- Next: M2. The biggest failing families are object lock (39), POST object (36, browser uploads), copy (17+), bucket policy (16+), ACLs, and versioning. Versioning changes the objects table semantics most, so start there. Blobs of overwritten/deleted objects and aborted parts are still unreferenced until the M2 sweeper exists.
- Requests for the human: none.

### 2026-09-25 22:40 · claude-opus-5.5 (interactive, human-authorized) · M1 · Rename "oracle" to "conformance"
- Did: renamed the concept repo-wide with `git mv` (history kept): `oracle/` → `conformance/`, `harness/oracle.sh` → `harness/conformance.sh`, `.github/workflows/oracle.yml` → `conformance.yml`, `make oracle` → `make conformance`, and `citadel serve --oracle` / `api.Config.Oracle` → `--conformance` / `Conformance`. The human explicitly authorized these protected-path edits for this task. Baseline files are byte-identical. Earlier PROGRESS entries keep the old word; "Oracle Cloud" (palaven-1's provider) is a company name and stays.
- Conformance: unchanged, s3 189, smoke-s3 12 (ratchet green, no change).
- Concept: a conformance suite is a test suite written by someone else against the real service (Ceph's s3-tests, Scylla's Alternator tests, moto). Passing it shows compatibility we can't fake by writing our own tests.
- Next: M2, starting with versioning (see the entry above).

### 2026-09-25 23:30 · claude-opus-5.5 (interactive) · M2 · Versioning
- Did: PutBucketVersioning; PUT/DELETE follow the bucket state (fresh version IDs when Enabled, the replaceable "null" version when unversioned or Suspended); delete markers (GET/HEAD 404 or 405 with `x-amz-delete-marker`); DELETE ?versionId promotes the next newest version; version-aware DeleteObjects and ListObjectVersions. CreateBucket on a bucket you own answers 200 for requests addressed to us-east-1 without a constraint (S3's legacy rule; s3-tests' `_create_objects` relies on it) and 409 BucketAlreadyOwnedByYou otherwise.
- Conformance: s3 189 → 210, smoke-s3 12 → 12.
- Decisions: PutObject in a Suspended bucket returns no `x-amz-version-id` (s3-tests asserts this); GET/HEAD in any versioned bucket do return it. `test_delete_marker_nonversioned` expects `x-amz-delete-marker: false` on a plain 404, which AWS doesn't document, so it's left red.
- Concept: S3 versioning never overwrites. Every write adds a version and "delete" just stacks a delete marker on top, so the key looks gone while every byte stays recoverable until someone deletes a specific version ID.
- Next: ACLs + bucket policy (~70 failing tests), then CopyObject/UploadPartCopy.
- Requests for the human: `harness/lib.sh` `start_citadel` creates `.harness/data/conformance-<port>-<pid>` per run and nothing ever deletes it. At ~200 MB per s3 run this filled the disk tonight (ratchet went RED with "no space left on device"). Please `rm -rf "$data"` in `stop_citadel` (or on EXIT in conformance.sh). Until then I clear those dirs before each ratchet.

### 2026-09-26 00:40 · claude-opus-5.5 (interactive) · M2 · ACLs, bucket policy, ownership, public access block, tagging
- Did: canned ACLs, `x-amz-grant-*` headers and ACL bodies (email grants resolve to canonical users); bucket policy storage, PolicyStatus and evaluation (`internal/s3/policy.go`: (Not)Principal/Action/Resource, String*/Arn*/Null/Bool/IpAddress with IfExists and ForAnyValue/ForAllValues); authorization in `authz.go` (explicit Deny → resource owner → policy Allow → ACL grant → implicit deny; a missing object is 403, not 404, for callers who can't list); ownership controls; all four public access block settings; object and bucket tagging including `x-amz-tagging` and the `s3:ExistingObjectTag/*` / `s3:RequestObjectTag/*` keys. Migration 0003.
- Conformance: s3 210 → 295, smoke-s3 12 → 12.
- Decision for review: new buckets default to object ownership **ObjectWriter** (ACLs enabled). AWS has defaulted new buckets to BucketOwnerEnforced since April 2023, but s3-tests' ACL suite assumes ACLs are on (e.g. `create_bucket(ACL='public-read')` must succeed). ObjectWriter is a real AWS mode (what `x-amz-object-ownership: ObjectWriter` selects), and BucketOwnerEnforced works when asked for. If you'd rather match today's AWS default, it's a one-line change in `createBucket`; it would cost most of the ~50 ACL tests.
- Concept: S3 has two layers of access control. ACLs are per-object grant lists from 2006; bucket policies are IAM-style JSON with conditions. AWS now steers everyone to policies and turns ACLs off by default, because an object can otherwise be owned by a different account than the bucket it sits in.
- Next: CopyObject + UploadPartCopy + conditional writes, then CORS/lifecycle storage, then blob GC.

### 2026-09-26 02:10 · claude-opus-5.5 (interactive) · M2 · Copy, conditional writes, multipart completion, checksums
- Did: CopyObject (metadata/tagging directives, copy-source versionId and `x-amz-copy-source-if-*`, copy-to-itself rule; the copy points at the source blob/manifest, no bytes move) and UploadPartCopy with ranges. If-Match / If-None-Match on PutObject, CopyObject and CompleteMultipartUpload, checked inside the write transaction. Completed uploads are kept (migration 0004) so a repeated Complete answers 200. Multipart checksums: FULL_OBJECT (whole-object CRC, streamed once at completion), COMPOSITE (checksum of part checksums + "-N"), default CRC64NVME; GET `?partNumber=N`; GetObjectAttributes.
- Conformance: s3 295 → 360, smoke-s3 12 → 12.
- Left red on purpose: `test_object_set_get_unicode_metadata` (expects RGW's Latin-1 round trip; AWS returns non-ASCII metadata RFC 2047-encoded) and `test_multipart_resend_first_finishes_last` (a timing-dependent race test; not investigated yet).
- Concept: a multipart object's "checksum" comes in two kinds. FULL_OBJECT is the CRC of every byte, so it matches what you'd compute on the downloaded file. COMPOSITE is a checksum of the parts' checksums, which only makes sense if you know the exact part boundaries (hence the "-N" suffix).
- Next: CORS config + preflight, lifecycle configuration storage, then blob garbage collection (the last M2 checkboxes).

### 2026-09-26 02:50 · claude-opus-5.5 (interactive) · M2 · CORS and lifecycle configuration
- Did: CORS config (Put/Get/Delete) with preflight answered before authentication and Access-Control-* headers on ordinary requests carrying Origin (errors included); lifecycle configuration storage with S3's validation rules and generated rule IDs. Tagging landed with the access-control work, so this checkbox is complete.
- Conformance: s3 360 → 383, smoke-s3 12 → 12.
- Left red: the four `test_cors_presigned_*_v2` tests sign with SigV2, which Citadel rejects (AWS stopped accepting SigV2 for new buckets in 2020).
- Concept: CORS is enforced by browsers, not by S3. S3 only answers the browser's preflight question "may a page from this origin call you with this method and these headers?", and tags ordinary responses so the browser lets the page read them.
- Next: blob garbage collection (reference counts + sweeper), the last M2 checkbox.

### 2026-09-26 03:40 · claude-opus-5.5 (interactive) · M2 · Blob GC; M2 done
- Did: blob garbage collection. Migration 0005 adds `blob_refs`, kept exact by SQLite triggers on `s3_objects` (blob + multipart manifest entries) and `s3_parts`, backfilled from existing rows. The sweeper (`internal/store/gc.go`, every 10 min by default, `--gc-interval` / `--gc-grace`) deletes unreferenced blob files older than a 1 h grace period, abandoned temp files, and day-old completed-upload records. `Pending.Commit` refreshes an existing blob's mtime and shares a lock with the sweeper, so a blob reused by a new upload can't be swept before its metadata commits. Completing an upload now releases the part rows and remembers its ETag/checksum for repeated Completes.
- Conformance, M2 overall (every enabled suite): **s3 189 → 383** (of 494; exit needs ≥ 300), **smoke-s3 12 → 12** (all steps pass). Unit tests 66 → 69. Final ratchet: green, no change; no 500s in the server log.
- Still failing (111): object lock 39 and POST-object browser uploads 36 (neither is on M2's checklist); `Expect:` mismatch 3 (Go's net/http answers 417 before any handler runs); SigV2 2; and ~31 one-offs: five skip-listed header tests, RGW-specific expectations (Latin-1 metadata, `x-amz-delete-marker: false` on plain 404s, `test_bucket_create_exists`'s bad except branch), a few policy/ACL edge cases (NotPrincipal, `RequestObjectTag` on PutObject, PolicyStatus considering ACLs, recreate-with-ACL semantics), presigned-expiry edge cases, and the resend race test.
- Concept: content-addressed storage makes deduplication free but deletion hard. Two objects may share one file, so a blob can only go when nothing references it, and a reference can appear at any moment from a new upload of identical bytes. Hence the refcount, the grace period, and the lock around "is it still unused? then delete".
- Next: M3 (DynamoDB). Enable the `ddb` suite in `conformance/suites` first and ratchet so its baseline starts from the real number.
- Requests for the human: (repeat) `harness/lib.sh` never deletes `.harness/data/conformance-<port>-<pid>`, which filled the disk during this session; please remove it in `stop_citadel`.

### 2026-09-26 05:30 · claude-opus-5.5 (interactive) · M3 · DynamoDB; M3 done
- Did (all eight M3 checkboxes):
  - JSON 1.0 dispatch with SigV4 and DynamoDB's `__type` error envelope. Unknown operation names are 400 UnknownOperationException; real operations not built yet are 501.
  - `internal/ddb/expr`: the value model and exact decimals (38 digits, 1e-130..9.99e125); an order-preserving key encoding tested against big.Rat over ~5000 random numbers; condition, update, projection, filter and key-condition expressions with placeholder, reserved-word and path-overlap rules.
  - Tables: Create/Describe/Delete/List/UpdateTable. Status transitions are instant: CreateTable answers CREATING and the next DescribeTable is ACTIVE.
  - Items: Put/Get/Update/DeleteItem with ReturnValues, the legacy Expected/AttributeUpdates/AttributesToGet parameters, and consumed capacity.
  - Query/Scan: key conditions compiled to byte ranges, filters, Select, paging, parallel segments.
  - GSIs/LSIs maintained in the write transaction; GSI create (with backfill) and delete via UpdateTable.
  - Batch and Transact operations; TTL configuration; tags.
  - Size and limit validation (400 KB items, key sizes, nesting, attribute names, 4 KB and 300-operator expressions).
  - Migration 0006.
- Conformance before → after (every enabled suite): **ddb 0 → 800** (908 selected; exit needs ≥ 450), s3 383 → 383, smoke-s3 12 → 12. Unit tests 69 → 76. No 500s.
- Decisions: TTL is configuration only; expired items aren't deleted yet. Tables become ACTIVE immediately. ClientRequestToken idempotency is kept in memory for 10 minutes (lost on restart). KeyConditions may be combined with FilterExpression, which DynamoDB accepts. Skips: 16 Alternator tests that read Scylla's internal `.scylla.alternator.system` tables.
- Still failing (~66): 25 validations the tests expect to fail (several Scylla-specific, e.g. the 222-character name limit and internal TTL tags), SerializationException vs ValidationException wording for malformed JSON/base64, 413 for oversized chunked requests, a few message formats, and 4 transaction edge cases.
- Concept: DynamoDB sorts items within a partition by sort key, so this encoding makes every key's bytes compare the way its value does. Numbers get a sign byte, a biased exponent and d+1 digits, and negatives are inverted with a terminator. Then a key condition like `BETWEEN :a AND :b` is one SQLite range scan over raw bytes.
- Next: M4 (SQS). Add `sqs` to `conformance/suites` first. On macOS, AirPlay Receiver must be off (port 5000).
- Requests for the human: (1) `harness/conformance.sh --nodes` can't rerun ddb tests: the report's node ids carry a `test/alternator/` prefix but pytest runs from inside that directory, so the ratchet's flake filter would count any flaky ddb test as a regression. Strip the prefix when reading `--nodes` for ddb. (2) (repeat) `harness/lib.sh` never deletes `.harness/data/conformance-*` run directories.
