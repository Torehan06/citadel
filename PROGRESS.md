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
