package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"citadel/internal/bootstrap"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir(), "test-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestHLC(t *testing.T) {
	wall := time.UnixMilli(1_000_000)
	c := NewClock(func() time.Time { return wall })

	a := c.Now()
	b := c.Now()
	if a.WallMs() != 1_000_000 || a.Counter() != 0 || b != a+1 {
		t.Fatalf("same millisecond: got %d/%d then %d/%d", a.WallMs(), a.Counter(), b.WallMs(), b.Counter())
	}

	wall = time.UnixMilli(999_000) // clock stepped backwards (laptop slept, NTP fix)
	if d := c.Now(); d <= b || d.WallMs() != 1_000_000 {
		t.Fatalf("clock went backwards: got %d/%d, want > %d", d.WallMs(), d.Counter(), b)
	}

	c.Observe(MakeHLC(2_000_000, 7)) // a remote region is ahead
	if e := c.Now(); e != MakeHLC(2_000_000, 8) {
		t.Fatalf("after observe: got %d/%d", e.WallMs(), e.Counter())
	}

	wall = time.UnixMilli(3_000_000)
	if f := c.Now(); f != MakeHLC(3_000_000, 0) {
		t.Fatalf("wall clock caught up: got %d/%d", f.WallMs(), f.Counter())
	}
}

func TestHLCCounterOverflow(t *testing.T) {
	c := NewClock(func() time.Time { return time.UnixMilli(5) })
	c.Observe(MakeHLC(5, 0xffff))
	if h := c.Now(); h != MakeHLC(6, 0) {
		t.Fatalf("got %d/%d, want 6/0", h.WallMs(), h.Counter())
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		s, err := Open(context.Background(), dir, "test-1")
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != len(migrations) {
			t.Fatalf("open %d: %d migrations recorded, want %d", i, n, len(migrations))
		}
		var mode string
		if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("journal_mode = %q, %v", mode, err)
		}
		_ = s.Close()
	}
}

func TestUpdateWritesChangeLog(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.Update(ctx, func(tx *Tx) error {
			return tx.Change("s3", "Test", "r", map[string]int{"i": i})
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A failing transaction leaves no trace.
	boom := errors.New("boom")
	if err := s.Update(ctx, func(tx *Tx) error {
		_ = tx.Change("s3", "Test", "rolled-back", nil)
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	ch, err := s.ChangesSince(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 3 {
		t.Fatalf("%d changes, want 3", len(ch))
	}
	for i := 1; i < len(ch); i++ {
		if ch[i].Seq <= ch[i-1].Seq || ch[i].HLC <= ch[i-1].HLC {
			t.Fatalf("change %d not ordered after %d", i, i-1)
		}
	}
	if ch[2].Payload != `{"i":2}` || ch[2].Region != "test-1" {
		t.Fatalf("unexpected change row %+v", ch[2])
	}
}

func TestConcurrentWritersSerialize(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Update(ctx, func(tx *Tx) error { return tx.Change("s3", "Test", "x", nil) })
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	ch, _ := s.ChangesSince(ctx, 0, 1000)
	if len(ch) != 50 {
		t.Fatalf("%d changes, want 50", len(ch))
	}
}

func TestSeedIdentities(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	f := &bootstrap.File{Accounts: []bootstrap.Account{{
		ID: "123456789012", CanonicalID: "canon", DisplayName: "Tester",
		Users: []bootstrap.User{{Name: "u", AccessKey: "AK", SecretKey: "SK"}},
	}}}
	for i := 0; i < 2; i++ { // seeding twice is fine
		if err := s.SeedIdentities(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	secret, p, err := s.LookupKey(ctx, "AK")
	if err != nil || secret != "SK" || p.Account.ID != "123456789012" || p.Account.CanonicalID != "canon" {
		t.Fatalf("LookupKey = %q %+v %v", secret, p, err)
	}
	if _, _, err := s.LookupKey(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestBlobWriteCommit(t *testing.T) {
	s := openTest(t)
	body := bytes.Repeat([]byte("citadel "), 100_000)
	crc := crc32.NewIEEE()
	p, err := s.Blobs.Write(bytes.NewReader(body), crc)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(body)
	if p.SHA256 != hex.EncodeToString(want[:]) || p.Size != int64(len(body)) {
		t.Fatalf("pending = %s/%d", p.SHA256, p.Size)
	}
	if crc.Sum32() != crc32.ChecksumIEEE(body) {
		t.Fatal("extra hash not fed")
	}
	if _, err := os.Stat(s.Blobs.Path(p.SHA256)); !os.IsNotExist(err) {
		t.Fatal("blob visible before commit")
	}
	if err := p.Commit(); err != nil {
		t.Fatal(err)
	}
	p.Abort() // no-op after commit
	f, err := s.Blobs.Open(p.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, body) {
		t.Fatal("content mismatch")
	}

	// Same content again: dedups onto the existing address.
	p2, err := s.Blobs.Write(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := p2.Commit(); err != nil {
		t.Fatal(err)
	}
	assertTmpEmpty(t, s)
}

type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(p), r.n)
	r.n -= n
	return n, nil
}

func TestBlobWriteErrorAndAbort(t *testing.T) {
	s := openTest(t)
	if _, err := s.Blobs.Write(&failingReader{n: 1000}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want the reader's error", err)
	}
	p, err := s.Blobs.Write(bytes.NewReader([]byte("rejected")))
	if err != nil {
		t.Fatal(err)
	}
	p.Abort()
	if _, err := os.Stat(s.Blobs.Path(p.SHA256)); !os.IsNotExist(err) {
		t.Fatal("aborted blob was committed")
	}
	assertTmpEmpty(t, s)
}

func assertTmpEmpty(t *testing.T, s *Store) {
	t.Helper()
	left, _ := os.ReadDir(filepath.Join(s.Blobs.root, "tmp"))
	if len(left) != 0 {
		t.Fatalf("%d temp files left behind", len(left))
	}
}
