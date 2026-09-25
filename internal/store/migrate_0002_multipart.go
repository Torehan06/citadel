package store

// 0002: multipart uploads. Each part is its own blob; completing an upload
// writes the object with a manifest of part blobs, so no bytes are copied.
func init() {
	register(2, "multipart", `
CREATE TABLE s3_uploads (
	upload_id TEXT PRIMARY KEY,
	bucket    TEXT NOT NULL REFERENCES s3_buckets(name),
	key       TEXT NOT NULL,
	initiated INTEGER NOT NULL,              -- unix ms
	owner     TEXT NOT NULL,                 -- account id of the initiator
	meta_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX s3_uploads_by_key ON s3_uploads(bucket, key, initiated);

CREATE TABLE s3_parts (
	upload_id     TEXT    NOT NULL REFERENCES s3_uploads(upload_id) ON DELETE CASCADE,
	part_number   INTEGER NOT NULL,
	size          INTEGER NOT NULL,
	etag          TEXT    NOT NULL,
	blob          TEXT    NOT NULL,
	checksum      TEXT    NOT NULL DEFAULT '',  -- base64, algorithm from the upload
	last_modified INTEGER NOT NULL,
	PRIMARY KEY (upload_id, part_number)
);

-- Multipart objects keep blob = '' and list their part blobs here as JSON:
-- [{"blob": "<sha256>", "size": n}, ...]
ALTER TABLE s3_objects ADD COLUMN parts_json TEXT NOT NULL DEFAULT '';
`)
}
