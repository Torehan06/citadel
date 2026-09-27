package store

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"citadel/internal/bootstrap"
)

// dump renders the replicated columns of every global table in rowid order.
func dump(t *testing.T, s *Store) string {
	t.Helper()
	var b strings.Builder
	for _, tbl := range []string{"accounts", "access_keys", "iam_entities"} {
		cols := controlTables[tbl].cols
		rows, err := s.DB().Query(`SELECT ` + strings.Join(cols, ", ") + ` FROM ` + tbl + ` ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&b, tbl, vals)
		}
		rows.Close()
	}
	return b.String()
}

// replicate copies the home region's feed to the follower in small batches.
func replicate(t *testing.T, home, follower *Store) {
	t.Helper()
	ctx := context.Background()
	epoch, err := home.ControlEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for {
		cur, err := follower.ControlCursor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		since := cur.Seq
		if cur.Epoch != epoch {
			since = 0
		}
		entries, _, err := home.ControlSince(ctx, since, 3)
		if err != nil {
			t.Fatal(err)
		}
		if err := follower.ApplyControl(ctx, epoch, entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			return
		}
	}
}

func controlLogLen(t *testing.T, s *Store) int {
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM control_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestControlFeedReplicatesGlobalTables(t *testing.T) {
	ctx := context.Background()
	home, follower := openTest(t), openTest(t)
	boot := &bootstrap.File{Accounts: []bootstrap.Account{{
		ID: "111122223333", CanonicalID: "c1", DisplayName: "one",
		Users: []bootstrap.User{{Name: "root", AccessKey: "ROOTKEY1", SecretKey: "s1"}},
	}}}
	if err := home.SeedIdentities(ctx, boot); err != nil {
		t.Fatal(err)
	}
	before := controlLogLen(t, home)
	if err := home.SeedIdentities(ctx, boot); err != nil { // unchanged re-seed: nothing to log
		t.Fatal(err)
	}
	if n := controlLogLen(t, home); n != before {
		t.Fatalf("re-seeding logged %d entries", n-before)
	}

	exec(t, home, `INSERT INTO access_keys(access_key, secret_key, account_id, user_name, created, kind) VALUES ('USERKEY1', 'x', '111122223333', 'alice', 5, 'user')`)
	exec(t, home, `INSERT INTO access_keys(access_key, secret_key, account_id, user_name, created, kind) VALUES ('USERKEY2', 'y', '111122223333', 'bob', 6, 'user')`)
	for i, name := range []string{"alice", "bob", "carol"} {
		exec(t, home, `INSERT INTO iam_entities(account_id, kind, key, doc, created) VALUES ('111122223333', 'user', ?, ?, ?)`, name, `{"n":"`+name+`"}`, i)
	}
	replicate(t, home, follower)
	if got, want := dump(t, follower), dump(t, home); got != want {
		t.Fatalf("after first sync:\nfollower:\n%s\nhome:\n%s", got, want)
	}

	// Usage tracking is regional: it is not logged, and a follower keeps its own.
	before = controlLogLen(t, home)
	exec(t, home, `UPDATE access_keys SET last_used = 99, last_service = 's3' WHERE access_key = 'USERKEY1'`)
	if n := controlLogLen(t, home); n != before {
		t.Fatal("last_used update was logged")
	}
	exec(t, follower, `UPDATE access_keys SET last_used = 42 WHERE access_key = 'USERKEY1'`)

	// Rename (keeps list position), update, delete, deactivate.
	exec(t, home, `UPDATE iam_entities SET key = 'alicia', doc = '{"n":"alicia"}' WHERE key = 'alice'`)
	exec(t, home, `UPDATE access_keys SET user_name = 'alicia', status = 'Inactive' WHERE access_key = 'USERKEY1'`)
	exec(t, home, `DELETE FROM iam_entities WHERE key = 'bob'`)
	exec(t, home, `DELETE FROM access_keys WHERE access_key = 'USERKEY2'`)
	followerLog := controlLogLen(t, follower)
	replicate(t, home, follower)
	if got, want := dump(t, follower), dump(t, home); got != want {
		t.Fatalf("after second sync:\nfollower:\n%s\nhome:\n%s", got, want)
	}
	if n := controlLogLen(t, follower); n != followerLog {
		t.Fatalf("applying logged %d entries on the follower", n-followerLog)
	}
	var lastUsed int64
	if err := follower.DB().QueryRow(`SELECT last_used FROM access_keys WHERE access_key = 'USERKEY1'`).Scan(&lastUsed); err != nil || lastUsed != 42 {
		t.Fatalf("follower last_used = %d, %v; want its own 42", lastUsed, err)
	}
	var keys []string
	rows, _ := follower.DB().Query(`SELECT key FROM iam_entities ORDER BY rowid`)
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		keys = append(keys, k)
	}
	rows.Close()
	if want := []string{"alicia", "carol"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("follower list order = %v, want %v", keys, want)
	}

	// Replaying from zero (a lost cursor) converges to the same state.
	cur, _ := follower.ControlCursor(ctx)
	all, head, err := home.ControlSince(ctx, 0, 1000)
	if err != nil || head != cur.Seq || cur.At == 0 {
		t.Fatalf("head %d, cursor %+v, err %v", head, cur, err)
	}
	exec(t, follower, `DELETE FROM feed_cursors`)
	if err := follower.ApplyControl(ctx, cur.Epoch, all); err != nil {
		t.Fatal(err)
	}
	// Rows re-created by the replay may sit at new list positions; compare contents.
	sorted := func(s string) string { l := strings.Split(s, "\n"); sort.Strings(l); return strings.Join(l, "\n") }
	if got, want := sorted(dump(t, follower)), sorted(dump(t, home)); got != want {
		t.Fatalf("after replay:\nfollower:\n%s\nhome:\n%s", got, want)
	}
}

func TestControlApplyRejectsUnknownTables(t *testing.T) {
	s := openTest(t)
	err := s.ApplyControl(context.Background(), "e", []ControlEntry{{Seq: 1, Table: "s3_buckets", Op: "del", Key: []byte(`{"name":"b"}`)}})
	if err == nil {
		t.Fatal("applied an entry for a regional table")
	}
	if cur, _ := s.ControlCursor(context.Background()); cur.Seq != 0 {
		t.Fatalf("cursor advanced to %d on a failed batch", cur.Seq)
	}
}
