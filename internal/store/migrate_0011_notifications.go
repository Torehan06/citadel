package store

// 0011: S3 event notifications.
//
// A bucket's notification configuration is a JSON document next to its other
// settings. feed_cursors records how far each change-log consumer (the S3
// notifier first; replication later) has read, so a restart resumes where
// it stopped instead of replaying or skipping changes.
func init() {
	register(11, "notifications", `
ALTER TABLE s3_buckets ADD COLUMN notification TEXT NOT NULL DEFAULT '';

CREATE TABLE feed_cursors (
	name TEXT PRIMARY KEY,
	seq  INTEGER NOT NULL
);
`)
}
