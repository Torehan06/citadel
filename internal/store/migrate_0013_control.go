package store

import (
	"fmt"
	"strings"
)

// 0013: the control-plane change feed (ARCHITECTURE.md §7).
//
// Global state (accounts, access keys, IAM entities) has one writer, the home
// region; followers replay its changes in order. Triggers on the global tables
// append a row image to control_log for every insert, update and delete, so
// every writer (IAM and STS calls, bootstrap seeding, conformance resets) is
// captured without each of them remembering to log. key is the row's primary
// key before the change (so a rename can be replayed as an update in place);
// row is the row after it, absent for deletes.
//
// While a follower applies entries it holds a row in control_applying inside
// the same transaction, which silences the triggers: replayed changes are not
// logged again. Access-key usage (last_used and friends) is regional and
// changes on every request, so it is neither logged nor replicated.
//
// control_meta holds this database's epoch, a random ID that tells a follower
// its cursor belongs to a different home database (one that was recreated).
// The migration seeds the log with the rows that already exist, so the log is
// a complete history from the start.
func init() {
	var b strings.Builder
	b.WriteString(`
CREATE TABLE control_log (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	at  INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)), -- unix ms
	tbl TEXT NOT NULL,
	op  TEXT NOT NULL,              -- 'put' or 'del'
	key TEXT NOT NULL,              -- JSON object: primary key before the change
	row TEXT NOT NULL DEFAULT ''    -- JSON object: the row after a put
);
CREATE TABLE control_applying (marker INTEGER);
CREATE TABLE control_meta (
	name  TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
INSERT INTO control_meta(name, value) VALUES ('epoch', lower(hex(randomblob(8))));
`)
	for _, t := range []struct {
		name string
		pk   []string
		cols []string // replicated columns; changes to any other column are not logged
	}{
		{"accounts", []string{"id"}, []string{"id", "name", "canonical_id", "display_name", "email"}},
		{"access_keys", []string{"access_key"},
			[]string{"access_key", "secret_key", "account_id", "user_name", "status", "created", "kind", "session_token", "expires", "principal"}},
		{"iam_entities", []string{"account_id", "kind", "key"}, []string{"account_id", "kind", "key", "doc", "created"}},
	} {
		obj := func(prefix string, cols []string) string {
			parts := make([]string, len(cols))
			for i, c := range cols {
				parts[i] = fmt.Sprintf("'%s', %s%s", c, prefix, c)
			}
			return "json_object(" + strings.Join(parts, ", ") + ")"
		}
		changed := make([]string, len(t.cols))
		for i, c := range t.cols {
			changed[i] = fmt.Sprintf("OLD.%s IS NOT NEW.%s", c, c)
		}
		quiet := `NOT EXISTS (SELECT 1 FROM control_applying)`
		fmt.Fprintf(&b, `
CREATE TRIGGER control_%[1]s_insert AFTER INSERT ON %[1]s WHEN %[2]s BEGIN
	INSERT INTO control_log(tbl, op, key, row) VALUES ('%[1]s', 'put', %[3]s, %[4]s);
END;
CREATE TRIGGER control_%[1]s_update AFTER UPDATE ON %[1]s WHEN %[2]s AND (%[5]s) BEGIN
	INSERT INTO control_log(tbl, op, key, row) VALUES ('%[1]s', 'put', %[6]s, %[4]s);
END;
CREATE TRIGGER control_%[1]s_delete AFTER DELETE ON %[1]s WHEN %[2]s BEGIN
	INSERT INTO control_log(tbl, op, key) VALUES ('%[1]s', 'del', %[6]s);
END;
INSERT INTO control_log(tbl, op, key, row) SELECT '%[1]s', 'put', %[7]s, %[8]s FROM %[1]s ORDER BY rowid;
`, t.name, quiet, obj("NEW.", t.pk), obj("NEW.", t.cols), strings.Join(changed, " OR "),
			obj("OLD.", t.pk), obj("", t.pk), obj("", t.cols))
	}
	register(13, "control", b.String())
}
