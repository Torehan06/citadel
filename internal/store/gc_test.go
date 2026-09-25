package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func refsOf(t *testing.T, s *Store, blob string) int64 {
	t.Helper()
	var n int64
	if err := s.DB().QueryRow(`SELECT COALESCE((SELECT refs FROM blob_refs WHERE blob = ?), 0)`, blob).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func putBlob(t *testing.T, s *Store, content string) string {
	t.Helper()
	p, err := s.Blobs.Write(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Commit(); err != nil {
		t.Fatal(err)
	}
	return p.SHA256
}

func exec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if err := s.Update(context.Background(), func(tx *Tx) error {
		_, err := tx.Exec(q, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestBlobRefTriggers(t *testing.T) {
	s := openTest(t)
	a, b, c := putBlob(t, s, "a"), putBlob(t, s, "b"), putBlob(t, s, "c")
	exec(t, s, `INSERT INTO accounts(id, canonical_id) VALUES ('111111111111', 'canon')`)
	exec(t, s, `INSERT INTO s3_buckets(name, account_id, region, created, hlc) VALUES ('bk', '111111111111', 'r', 0, 0)`)
	ins := `INSERT INTO s3_objects(bucket, key, version_id, seq, is_latest, blob, parts_json, last_modified, owner, hlc)
		VALUES ('bk', ?, 'null', 1, 1, ?, ?, 0, '111111111111', 0)
		ON CONFLICT(bucket, key, version_id) DO UPDATE SET blob = excluded.blob, parts_json = excluded.parts_json`

	exec(t, s, ins, "k1", a, "")
	exec(t, s, ins, "k2", a, "") // same content twice
	if refsOf(t, s, a) != 2 {
		t.Fatalf("a refs = %d, want 2", refsOf(t, s, a))
	}
	exec(t, s, ins, "k1", b, "") // overwrite via upsert moves the reference
	if refsOf(t, s, a) != 1 || refsOf(t, s, b) != 1 {
		t.Fatalf("after overwrite: a=%d b=%d", refsOf(t, s, a), refsOf(t, s, b))
	}
	manifest := `[{"blob":"` + c + `","size":1},{"blob":"` + c + `","size":1},{"blob":"` + b + `","size":1}]`
	exec(t, s, ins, "mp", "", manifest)
	if refsOf(t, s, c) != 2 || refsOf(t, s, b) != 2 {
		t.Fatalf("manifest: c=%d b=%d", refsOf(t, s, c), refsOf(t, s, b))
	}
	exec(t, s, `DELETE FROM s3_objects WHERE key = 'mp'`)
	if refsOf(t, s, c) != 0 || refsOf(t, s, b) != 1 {
		t.Fatalf("manifest delete: c=%d b=%d", refsOf(t, s, c), refsOf(t, s, b))
	}

	// Parts: counted while the upload exists; abort cascades.
	exec(t, s, `INSERT INTO s3_uploads(upload_id, bucket, key, initiated, owner) VALUES ('u1', 'bk', 'k', 0, '111111111111')`)
	exec(t, s, `INSERT INTO s3_parts(upload_id, part_number, size, etag, blob, last_modified) VALUES ('u1', 1, 1, 'e', ?, 0)`, c)
	if refsOf(t, s, c) != 1 {
		t.Fatalf("part: c=%d", refsOf(t, s, c))
	}
	exec(t, s, `DELETE FROM s3_uploads WHERE upload_id = 'u1'`)
	if refsOf(t, s, c) != 0 {
		t.Fatalf("after abort cascade: c=%d", refsOf(t, s, c))
	}
}

func TestSweepBlobs(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	kept, orphan, fresh := putBlob(t, s, "kept"), putBlob(t, s, "orphan"), putBlob(t, s, "fresh")
	exec(t, s, `INSERT INTO blob_refs(blob, refs) VALUES (?, 1)`, kept)
	old := time.Now().Add(-2 * time.Hour)
	for _, b := range []string{kept, orphan} {
		if err := os.Chtimes(s.Blobs.Path(b), old, old); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.SweepBlobs(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Deleted != 1 {
		t.Fatalf("deleted %d, want 1 (stats %+v)", st.Deleted, st)
	}
	for b, want := range map[string]bool{kept: true, orphan: false, fresh: true} {
		_, err := os.Stat(s.Blobs.Path(b))
		if exists := err == nil; exists != want {
			t.Errorf("blob %s exists=%v, want %v", b[:8], exists, want)
		}
	}

	// Re-uploading identical content refreshes the mtime, so a blob that
	// just became referenced again is inside the grace period.
	if err := os.Chtimes(s.Blobs.Path(kept), old, old); err != nil {
		t.Fatal(err)
	}
	exec(t, s, `UPDATE blob_refs SET refs = 0 WHERE blob = ?`, kept)
	putBlob(t, s, "kept")
	if st, _ := s.SweepBlobs(ctx, time.Hour); st.Deleted != 0 {
		t.Fatalf("swept a blob that was just re-committed")
	}
}
