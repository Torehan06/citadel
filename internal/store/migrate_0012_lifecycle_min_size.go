package store

// 0012: a bucket's lifecycle default minimum object size for transitions
// (x-amz-transition-default-minimum-object-size), stored next to its rules.
func init() {
	register(12, "lifecycle_min_size", `
ALTER TABLE s3_buckets ADD COLUMN lifecycle_min_size TEXT NOT NULL DEFAULT '';
`)
}
