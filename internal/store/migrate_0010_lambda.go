package store

// 0010: Lambda and CloudWatch Logs.
//
// A function is one lambda_functions row (function-level settings as a JSON
// document: tags, concurrency, resource policies, URL and async configs) and
// one lambda_versions row per version, with $LATEST as number 0. A version's
// deployment package is a blob, reference-counted by triggers like S3's, so
// the sweeper never removes code a version still uses. Aliases belong to a
// function and go with it.
//
// lambda_async is the durable queue of asynchronous invocations: a worker
// leases a due row by pushing next_at into the future, and deletes it when
// the invocation (with its retries) is done.
//
// Logs: groups, streams and events, with events indexed for reading one
// stream in order and a whole group by time.
func init() {
	register(10, "lambda", `
CREATE TABLE lambda_functions (
	account_id TEXT NOT NULL,
	region     TEXT NOT NULL,
	name       TEXT NOT NULL,
	doc        TEXT NOT NULL,
	PRIMARY KEY (account_id, region, name)
);

CREATE TABLE lambda_versions (
	account_id TEXT NOT NULL,
	region     TEXT NOT NULL,
	name       TEXT NOT NULL,
	num        INTEGER NOT NULL,
	config     TEXT NOT NULL,
	blob       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, region, name, num),
	FOREIGN KEY (account_id, region, name) REFERENCES lambda_functions(account_id, region, name) ON DELETE CASCADE
);

CREATE TRIGGER lambda_versions_refs_ins AFTER INSERT ON lambda_versions BEGIN
	INSERT INTO blob_refs(blob, refs) SELECT NEW.blob, 1 WHERE NEW.blob <> ''
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

CREATE TRIGGER lambda_versions_refs_del AFTER DELETE ON lambda_versions BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.blob AND OLD.blob <> '';
END;

CREATE TRIGGER lambda_versions_refs_upd AFTER UPDATE OF blob ON lambda_versions BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.blob AND OLD.blob <> '';
	INSERT INTO blob_refs(blob, refs) SELECT NEW.blob, 1 WHERE NEW.blob <> ''
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

CREATE TABLE lambda_aliases (
	account_id TEXT NOT NULL,
	region     TEXT NOT NULL,
	name       TEXT NOT NULL,
	alias      TEXT NOT NULL,
	doc        TEXT NOT NULL,
	PRIMARY KEY (account_id, region, name, alias),
	FOREIGN KEY (account_id, region, name) REFERENCES lambda_functions(account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE lambda_esm (
	uuid         TEXT PRIMARY KEY,
	account_id   TEXT NOT NULL,
	region       TEXT NOT NULL,
	function_arn TEXT NOT NULL,
	source_arn   TEXT NOT NULL,
	enabled      INTEGER NOT NULL,
	doc          TEXT NOT NULL
);
CREATE INDEX lambda_esm_source ON lambda_esm(account_id, source_arn);

CREATE TABLE lambda_async (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	request_id TEXT NOT NULL,
	account_id TEXT NOT NULL,
	region     TEXT NOT NULL,
	name       TEXT NOT NULL,
	qualifier  TEXT NOT NULL,
	payload    BLOB NOT NULL,
	attempts   INTEGER NOT NULL,
	next_at    INTEGER NOT NULL,
	enqueued   INTEGER NOT NULL
);
CREATE INDEX lambda_async_due ON lambda_async(next_at, id);

CREATE TABLE logs_groups (
	account_id TEXT NOT NULL,
	region     TEXT NOT NULL,
	name       TEXT NOT NULL,
	created    INTEGER NOT NULL,
	retention  INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (account_id, region, name)
);

CREATE TABLE logs_streams (
	account_id  TEXT NOT NULL,
	region      TEXT NOT NULL,
	grp         TEXT NOT NULL,
	name        TEXT NOT NULL,
	created     INTEGER NOT NULL,
	first_event INTEGER NOT NULL DEFAULT 0,
	last_event  INTEGER NOT NULL DEFAULT 0,
	last_ingest INTEGER NOT NULL DEFAULT 0,
	stored      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (account_id, region, grp, name),
	FOREIGN KEY (account_id, region, grp) REFERENCES logs_groups(account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE logs_events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	account_id TEXT NOT NULL,
	region     TEXT NOT NULL,
	grp        TEXT NOT NULL,
	stream     TEXT NOT NULL,
	ts         INTEGER NOT NULL,
	ingest     INTEGER NOT NULL,
	message    TEXT NOT NULL,
	FOREIGN KEY (account_id, region, grp, stream) REFERENCES logs_streams(account_id, region, grp, name) ON DELETE CASCADE
);
CREATE INDEX logs_events_stream ON logs_events(account_id, region, grp, stream, id);
CREATE INDEX logs_events_group ON logs_events(account_id, region, grp, ts, id);
`)
}
