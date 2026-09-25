package store

// 0003: access control and bucket/object configuration documents.
// JSON columns hold the parsed configuration; an empty string means "not set".
func init() {
	register(3, "access", `
ALTER TABLE s3_buckets ADD COLUMN acl                 TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN policy              TEXT NOT NULL DEFAULT '';  -- policy document as sent
ALTER TABLE s3_buckets ADD COLUMN ownership           TEXT NOT NULL DEFAULT 'ObjectWriter';
ALTER TABLE s3_buckets ADD COLUMN public_access_block TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN tagging             TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN cors                TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN lifecycle           TEXT NOT NULL DEFAULT '';

ALTER TABLE s3_objects ADD COLUMN acl     TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_objects ADD COLUMN tagging TEXT NOT NULL DEFAULT '';

CREATE INDEX accounts_by_email ON accounts(email);
`)
}
