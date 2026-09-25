package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

// A migration is one numbered, append-only schema step. Each lives in its own
// migrate_NNNN_*.go file and registers itself in init(). Never edit a
// migration once it is committed: add a new one.
type migration struct {
	version int
	name    string
	sql     string
}

var migrations []migration

func register(version int, name, sql string) {
	migrations = append(migrations, migration{version: version, name: name, sql: sql})
}

// migrate applies every migration newer than the database's recorded version,
// each in its own transaction.
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name    TEXT NOT NULL,
		applied INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	var current int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	ms := append([]migration(nil), migrations...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return fmt.Errorf("migrations must be numbered 1..n without gaps; found %d at position %d", m.version, i+1)
		}
		if m.version <= current {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, name, applied) VALUES (?, ?, strftime('%s','now'))`,
			m.version, m.name); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %04d_%s: commit: %w", m.version, m.name, err)
		}
	}
	return nil
}
