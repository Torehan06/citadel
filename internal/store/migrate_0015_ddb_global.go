package store

// 0015: DynamoDB global tables. Every item of a global table (tombstones of
// deleted items included) carries the version of its last write: the HLC and
// the region it was written in. Replicas apply an incoming write only if its
// version is newer, so they converge last-writer-wins whatever order writes
// arrive in. Regional tables keep no versions.
func init() {
	register(15, "ddb_global", `
CREATE TABLE ddb_item_versions (
	table_id INTEGER NOT NULL,
	pk       BLOB    NOT NULL,
	sk       BLOB    NOT NULL,
	hlc      INTEGER NOT NULL,
	region   TEXT    NOT NULL,
	deleted  INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (table_id, pk, sk)
) WITHOUT ROWID;
`)
}
