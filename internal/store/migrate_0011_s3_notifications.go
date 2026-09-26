package store

// 0011: S3 bucket notification configurations (JSON; ” = none). Deliveries
// are driven by the change log, read from the cursor in change_cursors.
func init() {
	register(11, "s3_notifications", `
ALTER TABLE s3_buckets ADD COLUMN notification TEXT NOT NULL DEFAULT '';
`)
}
