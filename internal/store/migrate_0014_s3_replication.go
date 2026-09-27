package store

// 0014: S3 cross-region replication. A bucket keeps its replication
// configuration (JSON) next to its other configurations. An object version
// records its replication status as S3 reports it (x-amz-replication-status:
// PENDING, COMPLETED or FAILED on the source, REPLICA on the destination) and,
// on a destination, which source bucket it came from ("region/bucket"), so
// anti-entropy can compare exactly the versions one rule is responsible for.
// Per-destination replication cursors live in feed_cursors as "repl:<region>".
func init() {
	register(14, "s3_replication", `
ALTER TABLE s3_buckets ADD COLUMN replication TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_objects ADD COLUMN repl_status TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_objects ADD COLUMN repl_source TEXT NOT NULL DEFAULT '';
CREATE INDEX s3_objects_repl_source ON s3_objects(bucket, repl_source) WHERE repl_source <> '';
`)
}
