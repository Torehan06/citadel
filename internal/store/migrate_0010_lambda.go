package store

// 0010: Lambda and CloudWatch Logs.
//
// A function is one row plus its versions: version 0 is $LATEST, published
// versions count up from 1. Each version's configuration is a JSON document
// in the API's own shape, and its deployment package is a blob (counted in
// blob_refs like S3 objects). Aliases, per-qualifier settings (event invoke
// and function URL configs), event source mappings and queued asynchronous
// invocations each get a table. Log groups, streams and events back the
// minimal CloudWatch Logs API that function logs are read through.
func init() {
	register(10, "lambda", `
CREATE TABLE lambda_functions (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	account      TEXT NOT NULL,
	region       TEXT NOT NULL,
	name         TEXT NOT NULL,
	created      INTEGER NOT NULL,
	last_version INTEGER NOT NULL DEFAULT 0,  -- highest published version number
	published    TEXT NOT NULL DEFAULT '',    -- $LATEST's revision when last published
	policy       TEXT NOT NULL DEFAULT '',    -- resource-based policy document
	concurrency  INTEGER,                     -- reserved concurrency; NULL = unreserved
	tags         TEXT NOT NULL DEFAULT '{}',
	code_signing TEXT NOT NULL DEFAULT '',
	UNIQUE(account, region, name)
);

CREATE TABLE lambda_versions (
	function_id INTEGER NOT NULL REFERENCES lambda_functions(id) ON DELETE CASCADE,
	version     INTEGER NOT NULL,             -- 0 = $LATEST
	config      TEXT NOT NULL,
	code_blob   TEXT NOT NULL DEFAULT '',     -- sha256 hex of the zip; '' for images
	image_uri   TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (function_id, version)
);

CREATE TABLE lambda_aliases (
	function_id INTEGER NOT NULL REFERENCES lambda_functions(id) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	config      TEXT NOT NULL,
	PRIMARY KEY (function_id, name)
);

-- kind: 'invoke' (EventInvokeConfig) or 'url' (function URL config)
CREATE TABLE lambda_settings (
	function_id INTEGER NOT NULL REFERENCES lambda_functions(id) ON DELETE CASCADE,
	qualifier   TEXT NOT NULL,
	kind        TEXT NOT NULL,
	config      TEXT NOT NULL,
	PRIMARY KEY (function_id, qualifier, kind)
);

CREATE TABLE lambda_mappings (
	uuid         TEXT PRIMARY KEY,
	account      TEXT NOT NULL,
	region       TEXT NOT NULL,
	function_arn TEXT NOT NULL,               -- as given: may carry a qualifier
	source_arn   TEXT NOT NULL,
	enabled      INTEGER NOT NULL,
	config       TEXT NOT NULL,
	tags         TEXT NOT NULL DEFAULT '{}',
	modified     INTEGER NOT NULL,
	result       TEXT NOT NULL DEFAULT 'No records processed'
);
CREATE INDEX lambda_mappings_source ON lambda_mappings(account, region, source_arn);

CREATE TABLE lambda_async (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	account    TEXT NOT NULL,
	region     TEXT NOT NULL,
	function   TEXT NOT NULL,                 -- function name
	qualifier  TEXT NOT NULL,
	payload    BLOB NOT NULL,
	request_id TEXT NOT NULL,
	attempts   INTEGER NOT NULL DEFAULT 0,
	next_at    INTEGER NOT NULL,              -- unix ms
	created    INTEGER NOT NULL
);
CREATE INDEX lambda_async_due ON lambda_async(next_at);

-- Readers of the change log remember how far they got.
CREATE TABLE change_cursors (
	name TEXT PRIMARY KEY,
	seq  INTEGER NOT NULL
);

CREATE TRIGGER lambda_versions_refs_ins AFTER INSERT ON lambda_versions WHEN NEW.code_blob <> '' BEGIN
	INSERT INTO blob_refs(blob, refs) VALUES (NEW.code_blob, 1)
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;
CREATE TRIGGER lambda_versions_refs_del AFTER DELETE ON lambda_versions WHEN OLD.code_blob <> '' BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.code_blob;
END;
CREATE TRIGGER lambda_versions_refs_upd AFTER UPDATE OF code_blob ON lambda_versions BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.code_blob AND OLD.code_blob <> '';
	INSERT INTO blob_refs(blob, refs) SELECT NEW.code_blob, 1 WHERE NEW.code_blob <> ''
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

CREATE TABLE logs_groups (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	account   TEXT NOT NULL,
	region    TEXT NOT NULL,
	name      TEXT NOT NULL,
	created   INTEGER NOT NULL,
	retention INTEGER,                        -- days; NULL = never expire
	tags      TEXT NOT NULL DEFAULT '{}',
	UNIQUE(account, region, name)
);

CREATE TABLE logs_streams (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	group_id       INTEGER NOT NULL REFERENCES logs_groups(id) ON DELETE CASCADE,
	name           TEXT NOT NULL,
	created        INTEGER NOT NULL,
	first_event    INTEGER NOT NULL DEFAULT 0,
	last_event     INTEGER NOT NULL DEFAULT 0,
	last_ingestion INTEGER NOT NULL DEFAULT 0,
	stored_bytes   INTEGER NOT NULL DEFAULT 0,
	UNIQUE(group_id, name)
);

CREATE TABLE logs_events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	stream_id INTEGER NOT NULL REFERENCES logs_streams(id) ON DELETE CASCADE,
	ts        INTEGER NOT NULL,
	ingested  INTEGER NOT NULL,
	message   TEXT NOT NULL
);
CREATE INDEX logs_events_by_time ON logs_events(stream_id, ts, id);
`)
}
