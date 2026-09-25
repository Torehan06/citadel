package store

// SQS leases, deduplication records and receipt handles survive process restarts.
func init() {
	register(7, "sqs", `
CREATE TABLE sqs_queues (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 attrs TEXT NOT NULL, tags TEXT NOT NULL,
 created INTEGER NOT NULL, modified INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0,
 UNIQUE(account, region, name)
);
CREATE TABLE sqs_messages (
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 queue_id INTEGER NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
 message_id TEXT NOT NULL, body TEXT NOT NULL, attrs TEXT NOT NULL, system_attrs TEXT NOT NULL,
 sender TEXT NOT NULL, sent INTEGER NOT NULL, visible_at INTEGER NOT NULL,
 receive_count INTEGER NOT NULL DEFAULT 0, first_received INTEGER NOT NULL DEFAULT 0,
 received INTEGER NOT NULL DEFAULT 0, receipt TEXT NOT NULL DEFAULT '',
 group_id TEXT NOT NULL DEFAULT '', dedup_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sqs_visible ON sqs_messages(queue_id, visible_at, seq);
CREATE INDEX sqs_groups ON sqs_messages(queue_id, group_id, seq);
CREATE TABLE sqs_receipts (
 handle TEXT PRIMARY KEY, queue_id INTEGER NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
 message_seq INTEGER NOT NULL, created INTEGER NOT NULL
);
CREATE TABLE sqs_dedup (
 queue_id INTEGER NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
 scope TEXT NOT NULL, dedup_id TEXT NOT NULL, message_id TEXT NOT NULL,
 sequence INTEGER NOT NULL, expires INTEGER NOT NULL,
 PRIMARY KEY(queue_id, scope, dedup_id)
);
`)
}
