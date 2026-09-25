// Package store owns a region's durable state: the SQLite metadata database
// (meta.db) and the content-addressed blob store (see ARCHITECTURE.md §6).
//
// meta.db has exactly one write connection, so writers queue in Go instead of
// fighting over SQLite's lock, and a separate pool of read connections that
// WAL mode lets run alongside the writer.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go)
)

// Store is one region's metadata database plus its blob store.
type Store struct {
	Region string
	Clock  *Clock
	Blobs  *Blobs

	w *sql.DB // single writer connection
	r *sql.DB // read pool
}

// Open opens (creating if needed) the store under dir and applies migrations.
func Open(ctx context.Context, dir, region string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	blobs, err := OpenBlobs(filepath.Join(dir, "blobs"))
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "meta.db")
	w, err := openDB(path, 1)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, w); err != nil {
		_ = w.Close()
		return nil, err
	}
	r, err := openDB(path, max(4, runtime.GOMAXPROCS(0)))
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return &Store{Region: region, Clock: NewClock(nil), Blobs: blobs, w: w, r: r}, nil
}

func openDB(path string, conns int) (*sql.DB, error) {
	q := url.Values{}
	for _, p := range []string{
		"journal_mode(WAL)",
		"synchronous(NORMAL)",
		"busy_timeout(5000)",
		"foreign_keys(ON)",
	} {
		q.Add("_pragma", p)
	}
	// _txlock=immediate: a write transaction takes the write lock at BEGIN,
	// so it can never fail halfway with SQLITE_BUSY on lock upgrade.
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	db.SetMaxOpenConns(conns)
	db.SetMaxIdleConns(conns)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return db, nil
}

// Close closes both database handles.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

// DB returns the read pool. Use it for queries only; all writes go through Update.
func (s *Store) DB() *sql.DB { return s.r }

// Tx is a write transaction. Every mutation made through it should be recorded
// with Change, so the change log stays a complete history of the region.
type Tx struct {
	*sql.Tx
	s   *Store
	hlc HLC
}

// HLC returns the timestamp stamped on every change in this transaction.
func (tx *Tx) HLC() HLC { return tx.hlc }

// Change appends a row to the change log. payload is marshalled as JSON.
func (tx *Tx) Change(service, kind, resource string, payload any) error {
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return fmt.Errorf("change payload: %w", err)
		}
	}
	_, err := tx.ExecContext(context.Background(),
		`INSERT INTO changes(hlc, region, service, kind, resource, payload) VALUES (?, ?, ?, ?, ?, ?)`,
		int64(tx.hlc), tx.s.Region, service, kind, resource, string(body))
	return err
}

// Update runs fn in a write transaction on the single writer connection and
// commits if fn returns nil.
func (s *Store) Update(ctx context.Context, fn func(tx *Tx) error) error {
	sqlTx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	tx := &Tx{Tx: sqlTx, s: s, hlc: s.Clock.Now()}
	if err := fn(tx); err != nil {
		_ = sqlTx.Rollback()
		return err
	}
	return sqlTx.Commit()
}

// Change is one row of the change log.
type Change struct {
	Seq      int64
	HLC      HLC
	Region   string
	Service  string
	Kind     string
	Resource string
	Payload  string
}

// ChangesSince returns up to limit changes with seq > since, oldest first.
func (s *Store) ChangesSince(ctx context.Context, since int64, limit int) ([]Change, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT seq, hlc, region, service, kind, resource, payload FROM changes WHERE seq > ? ORDER BY seq LIMIT ?`,
		since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var c Change
		var h int64
		if err := rows.Scan(&c.Seq, &h, &c.Region, &c.Service, &c.Kind, &c.Resource, &c.Payload); err != nil {
			return nil, err
		}
		c.HLC = HLC(h)
		out = append(out, c)
	}
	return out, rows.Err()
}
