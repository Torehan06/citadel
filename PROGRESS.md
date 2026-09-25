# Progress log

Append-only. Newest entries at the bottom. Format in AGENTS.md.

### 2026-09-25 18:00 · scaffold · M0 · Skeleton, oracles, harness
- Did: `citadel serve` stub with service detection and 501 NotImplemented in every protocol's error envelope; bootstrap identities; oracle runners for s3-tests, aws CLI smoke, Alternator (DynamoDB), and moto (SQS, IAM, Lambda, Route 53); ratchet; night-shift loop; CI on all three platforms.
- Oracle: against the stub, s3 0/494, smoke-s3 0/12, ddb 0 passing (about 900 selected), sqs 3/161, iam 3/310, route53 0/67. The few moto passes are tests whose assertions hold against any error.
- Concept: an "oracle" is a test suite written by someone else against the real service. Passing it is evidence of compatibility we can't fake by writing our own tests.
- Next: M1. Start with `internal/store`, `internal/sigv4`, then ListBuckets, ListObjectVersions, DeleteObjects and DeleteBucket. s3-tests' setup and teardown fixtures call those around every test, so nothing passes before they work.
