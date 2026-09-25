package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Blob garbage collection (ARCHITECTURE.md §6): blob_refs counts references
// (kept by triggers, migration 0005), and the sweeper deletes blob files that
// nothing references once they are older than a grace period. The grace
// period covers the gap between a blob being committed to disk and the
// metadata transaction that references it.

// SweepStats reports one sweep.
type SweepStats struct {
	Scanned, Deleted int
	Bytes            int64
	TmpDeleted       int
}

// SweepBlobs deletes unreferenced blobs last modified before now-grace, and
// abandoned temp files older than a day.
func (s *Store) SweepBlobs(ctx context.Context, grace time.Duration) (SweepStats, error) {
	var st SweepStats
	cutoff := time.Now().Add(-grace)
	root := filepath.Join(s.Blobs.root, "sha256")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // a directory vanishing mid-walk is fine
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st.Scanned++
		info, err := d.Info()
		if err != nil || info.ModTime().After(cutoff) {
			return nil
		}
		sha := d.Name()
		var refs int64
		err = s.r.QueryRowContext(ctx, `SELECT refs FROM blob_refs WHERE blob = ?`, sha).Scan(&refs)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if refs > 0 {
			return nil
		}
		deleted, size, err := s.removeIfUnreferenced(ctx, sha, cutoff)
		if err != nil {
			return err
		}
		if deleted {
			st.Deleted++
			st.Bytes += size
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	st.TmpDeleted = s.sweepTmp(time.Now().Add(-24 * time.Hour))
	// Completed multipart uploads are kept only so a retried Complete gets
	// the same answer; after a day they can go.
	err = s.Update(ctx, func(tx *Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM s3_uploads WHERE completed_etag <> '' AND initiated < ?`,
			time.Now().Add(-24*time.Hour).UnixMilli())
		return err
	})
	return st, err
}

// removeIfUnreferenced re-checks the count inside a write transaction and,
// holding the blob lock so no Commit can reuse the file meanwhile, removes it.
func (s *Store) removeIfUnreferenced(ctx context.Context, sha string, cutoff time.Time) (bool, int64, error) {
	var deleted bool
	var size int64
	err := s.Update(ctx, func(tx *Tx) error {
		var refs int64
		err := tx.QueryRowContext(ctx, `SELECT refs FROM blob_refs WHERE blob = ?`, sha).Scan(&refs)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if refs > 0 {
			return nil
		}
		s.Blobs.mu.Lock()
		defer s.Blobs.mu.Unlock()
		path := s.Blobs.Path(sha)
		info, err := os.Stat(path)
		if err != nil || info.ModTime().After(cutoff) {
			return nil // gone already, or just reused by a new upload
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		deleted, size = true, info.Size()
		if _, err := tx.ExecContext(ctx, `DELETE FROM blob_refs WHERE blob = ?`, sha); err != nil {
			return err
		}
		return tx.Change("store", "DeleteBlob", sha, map[string]int64{"size": size})
	})
	return deleted, size, err
}

// sweepTmp removes in-flight uploads abandoned by a crash.
func (s *Store) sweepTmp(before time.Time) int {
	dir := filepath.Join(s.Blobs.root, "tmp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().Before(before) {
			if os.Remove(filepath.Join(dir, e.Name())) == nil {
				n++
			}
		}
	}
	return n
}

// StartSweeper runs SweepBlobs every interval until ctx is done.
func (s *Store) StartSweeper(ctx context.Context, interval, grace time.Duration, log *slog.Logger) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st, err := s.SweepBlobs(ctx, grace)
				if err != nil && ctx.Err() == nil {
					log.Error("blob sweep failed", "err", err)
				} else if st.Deleted > 0 || st.TmpDeleted > 0 {
					log.Info("blob sweep", "scanned", st.Scanned, "deleted", st.Deleted, "bytes", st.Bytes, "tmp", st.TmpDeleted)
				}
			}
		}
	}()
}
