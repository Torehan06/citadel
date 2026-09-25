package store

// 0004: completed multipart uploads are kept (marked by completed_etag) so a
// repeated CompleteMultipartUpload answers like the first one, as S3 does.
// Uploads also carry the tags and ACL the final object gets.
func init() {
	register(4, "upload_state", `
ALTER TABLE s3_uploads ADD COLUMN completed_etag TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_uploads ADD COLUMN tagging        TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_uploads ADD COLUMN acl            TEXT NOT NULL DEFAULT '';
`)
}
