package store

// 0006: DynamoDB tables and items.
// Items live in one table keyed by an order-preserving binary encoding of
// their keys, so ORDER BY gives DynamoDB order. Secondary indexes are rows
// in the same table under their own idx, maintained in the same
// transaction as the base item.
func init() {
	register(6, "ddb", `
CREATE TABLE ddb_tables (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	account_id TEXT    NOT NULL,
	name       TEXT    NOT NULL,
	created    INTEGER NOT NULL,           -- unix ms
	desc_json  TEXT    NOT NULL,           -- schema, indexes, billing, TTL, tags...
	hlc        INTEGER NOT NULL,
	UNIQUE (account_id, name)
);

CREATE TABLE ddb_items (
	table_id INTEGER NOT NULL,
	idx      INTEGER NOT NULL,             -- 0: the table; n > 0: a secondary index
	pk       BLOB    NOT NULL,             -- encoded partition key
	sk       BLOB    NOT NULL,             -- encoded sort key (empty without one)
	bk       BLOB    NOT NULL,             -- index rows: the base item's key; empty for base rows
	item     BLOB    NOT NULL,             -- JSON attribute map (index rows: projected attributes)
	size     INTEGER NOT NULL,             -- DynamoDB item size in bytes
	PRIMARY KEY (table_id, idx, pk, sk, bk)
) WITHOUT ROWID;
`)
}
