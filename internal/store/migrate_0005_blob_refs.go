package store

// 0005: blob reference counts, kept by triggers so every write path counts
// (inserts, upserts, deletes, cascades). A blob is referenced by an object
// version (s3_objects.blob), by each entry of a multipart manifest
// (s3_objects.parts_json), and by an uploaded part (s3_parts.blob).
// The sweeper (gc.go) deletes blob files whose count is zero.
func init() {
	register(5, "blob_refs", `
CREATE TABLE blob_refs (
	blob TEXT PRIMARY KEY,   -- sha256 hex
	refs INTEGER NOT NULL
);

-- A manifest is parts_json read with json_each; an empty string means none.

CREATE TRIGGER s3_objects_refs_ins AFTER INSERT ON s3_objects BEGIN
	INSERT INTO blob_refs(blob, refs) SELECT NEW.blob, 1 WHERE NEW.blob <> ''
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
	INSERT INTO blob_refs(blob, refs)
		SELECT json_extract(value, '$.blob'), 1
		FROM json_each(CASE WHEN NEW.parts_json = '' THEN '[]' ELSE NEW.parts_json END) WHERE 1
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

CREATE TRIGGER s3_objects_refs_del AFTER DELETE ON s3_objects BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.blob AND OLD.blob <> '';
	UPDATE blob_refs SET refs = refs - (
		SELECT COUNT(*) FROM json_each(CASE WHEN OLD.parts_json = '' THEN '[]' ELSE OLD.parts_json END) j
		WHERE json_extract(j.value, '$.blob') = blob_refs.blob)
	WHERE blob IN (SELECT json_extract(value, '$.blob')
		FROM json_each(CASE WHEN OLD.parts_json = '' THEN '[]' ELSE OLD.parts_json END));
END;

CREATE TRIGGER s3_objects_refs_upd AFTER UPDATE OF blob, parts_json ON s3_objects BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.blob AND OLD.blob <> '';
	UPDATE blob_refs SET refs = refs - (
		SELECT COUNT(*) FROM json_each(CASE WHEN OLD.parts_json = '' THEN '[]' ELSE OLD.parts_json END) j
		WHERE json_extract(j.value, '$.blob') = blob_refs.blob)
	WHERE blob IN (SELECT json_extract(value, '$.blob')
		FROM json_each(CASE WHEN OLD.parts_json = '' THEN '[]' ELSE OLD.parts_json END));
	INSERT INTO blob_refs(blob, refs) SELECT NEW.blob, 1 WHERE NEW.blob <> ''
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
	INSERT INTO blob_refs(blob, refs)
		SELECT json_extract(value, '$.blob'), 1
		FROM json_each(CASE WHEN NEW.parts_json = '' THEN '[]' ELSE NEW.parts_json END) WHERE 1
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

CREATE TRIGGER s3_parts_refs_ins AFTER INSERT ON s3_parts BEGIN
	INSERT INTO blob_refs(blob, refs) VALUES (NEW.blob, 1)
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

CREATE TRIGGER s3_parts_refs_del AFTER DELETE ON s3_parts BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.blob;
END;

CREATE TRIGGER s3_parts_refs_upd AFTER UPDATE OF blob ON s3_parts BEGIN
	UPDATE blob_refs SET refs = refs - 1 WHERE blob = OLD.blob;
	INSERT INTO blob_refs(blob, refs) VALUES (NEW.blob, 1)
		ON CONFLICT(blob) DO UPDATE SET refs = refs + 1;
END;

-- Backfill from what exists already.
INSERT INTO blob_refs(blob, refs)
SELECT blob, COUNT(*) FROM (
	SELECT blob FROM s3_objects WHERE blob <> ''
	UNION ALL
	SELECT json_extract(j.value, '$.blob') FROM s3_objects o,
		json_each(CASE WHEN o.parts_json = '' THEN '[]' ELSE o.parts_json END) j
	UNION ALL
	SELECT blob FROM s3_parts
) GROUP BY blob;
`)
}
