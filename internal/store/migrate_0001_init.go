package store

// 0001: change log, identities, S3 buckets and objects.
func init() {
	register(1, "init", `
-- Transactional outbox: every mutation appends here in the same transaction.
-- Replication, event notifications and the control-plane feed read this log.
CREATE TABLE changes (
	seq      INTEGER PRIMARY KEY AUTOINCREMENT,
	hlc      INTEGER NOT NULL,
	region   TEXT    NOT NULL,
	service  TEXT    NOT NULL,
	kind     TEXT    NOT NULL,
	resource TEXT    NOT NULL,
	payload  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE accounts (
	id           TEXT PRIMARY KEY,           -- 12-digit account ID
	name         TEXT NOT NULL DEFAULT '',
	canonical_id TEXT NOT NULL UNIQUE,       -- S3 Owner.ID
	display_name TEXT NOT NULL DEFAULT '',
	email        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE access_keys (
	access_key TEXT PRIMARY KEY,
	secret_key TEXT NOT NULL,
	account_id TEXT NOT NULL REFERENCES accounts(id),
	user_name  TEXT NOT NULL,
	status     TEXT NOT NULL DEFAULT 'Active',
	created    INTEGER NOT NULL              -- unix ms
);

CREATE TABLE s3_buckets (
	name                TEXT PRIMARY KEY,
	account_id          TEXT NOT NULL REFERENCES accounts(id),
	region              TEXT NOT NULL,
	location_constraint TEXT NOT NULL DEFAULT '',
	created             INTEGER NOT NULL,    -- unix ms
	versioning          TEXT NOT NULL DEFAULT '',  -- '', 'Enabled', 'Suspended'
	hlc                 INTEGER NOT NULL
);
CREATE INDEX s3_buckets_by_account ON s3_buckets(account_id, name);

-- One row per object version. Unversioned buckets store version_id 'null'.
-- key uses BINARY collation, so ORDER BY key is S3's UTF-8 byte order.
CREATE TABLE s3_objects (
	bucket        TEXT    NOT NULL REFERENCES s3_buckets(name),
	key           TEXT    NOT NULL,
	version_id    TEXT    NOT NULL,
	seq           INTEGER NOT NULL,          -- orders versions of one key, newest highest
	is_latest     INTEGER NOT NULL,
	delete_marker INTEGER NOT NULL DEFAULT 0,
	size          INTEGER NOT NULL DEFAULT 0,
	etag          TEXT    NOT NULL DEFAULT '',
	blob          TEXT    NOT NULL DEFAULT '',  -- sha256 hex of the content
	last_modified INTEGER NOT NULL,          -- unix ms
	owner         TEXT    NOT NULL,          -- account id
	meta_json     TEXT    NOT NULL DEFAULT '{}',
	hlc           INTEGER NOT NULL,
	PRIMARY KEY (bucket, key, version_id)
);
CREATE INDEX s3_objects_latest ON s3_objects(bucket, key) WHERE is_latest = 1;
`)
}
