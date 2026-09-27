package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ControlEntry is one row of the control-plane change feed (migration 0013):
// a put (insert or update) or delete of one row of a global table.
type ControlEntry struct {
	Seq   int64           `json:"seq"`
	At    int64           `json:"at"` // unix ms when the home region wrote it
	Table string          `json:"table"`
	Op    string          `json:"op"`
	Key   json.RawMessage `json:"key"`
	Row   json.RawMessage `json:"row,omitempty"`
}

// controlTable describes a replicated global table: its primary key and the
// columns a follower writes. Other columns (access-key usage) stay regional.
type controlTable struct {
	pk, cols []string
}

var controlTables = map[string]controlTable{
	"accounts":     {[]string{"id"}, []string{"id", "name", "canonical_id", "display_name", "email"}},
	"access_keys":  {[]string{"access_key"}, []string{"access_key", "secret_key", "account_id", "user_name", "status", "created", "kind", "session_token", "expires", "principal"}},
	"iam_entities": {[]string{"account_id", "kind", "key"}, []string{"account_id", "kind", "key", "doc", "created"}},
}

// ControlEpoch returns this database's epoch (see migration 0013).
func (s *Store) ControlEpoch(ctx context.Context) (string, error) {
	return s.controlMeta(ctx, "epoch")
}

// ControlSince returns up to limit feed entries with seq > since, oldest
// first, and the newest seq in the log.
func (s *Store) ControlSince(ctx context.Context, since int64, limit int) ([]ControlEntry, int64, error) {
	var head int64
	if err := s.r.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM control_log`).Scan(&head); err != nil {
		return nil, 0, err
	}
	rows, err := s.r.QueryContext(ctx,
		`SELECT seq, at, tbl, op, key, row FROM control_log WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?`,
		since, head, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ControlEntry
	for rows.Next() {
		var e ControlEntry
		var key, row string
		if err := rows.Scan(&e.Seq, &e.At, &e.Table, &e.Op, &key, &row); err != nil {
			return nil, 0, err
		}
		e.Key = json.RawMessage(key)
		if row != "" {
			e.Row = json.RawMessage(row)
		}
		out = append(out, e)
	}
	return out, head, rows.Err()
}

// ControlCursor is how far a follower has applied the home region's feed.
type ControlCursor struct {
	Epoch string // the home database's epoch the cursor belongs to
	Seq   int64  // last applied entry
	At    int64  // unix ms the home region wrote that entry
}

const controlCursorName = "control"

// ControlCursor returns the follower's position in the feed (zero if it
// never applied anything).
func (s *Store) ControlCursor(ctx context.Context) (ControlCursor, error) {
	var c ControlCursor
	err := s.r.QueryRowContext(ctx, `SELECT seq FROM feed_cursors WHERE name = ?`, controlCursorName).Scan(&c.Seq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return c, err
	}
	if c.Epoch, err = s.controlMeta(ctx, "follow_epoch"); err != nil {
		return c, err
	}
	at, err := s.controlMeta(ctx, "follow_at")
	if err != nil {
		return c, err
	}
	_, _ = fmt.Sscan(at, &c.At)
	return c, nil
}

// controlMeta returns a control_meta value, "" when unset.
func (s *Store) controlMeta(ctx context.Context, name string) (string, error) {
	var v string
	err := s.r.QueryRowContext(ctx, `SELECT value FROM control_meta WHERE name = ?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// ApplyControl applies feed entries from the home database with this epoch,
// in order, and advances the cursor in the same transaction, so a crash
// either applies a batch and its cursor or neither. A different epoch than
// the cursor's restarts the cursor: the caller then fetches from seq 0.
// Entries at or below the cursor are skipped, so a replayed batch is harmless.
func (s *Store) ApplyControl(ctx context.Context, epoch string, entries []ControlEntry) error {
	cur, err := s.ControlCursor(ctx)
	if err != nil {
		return err
	}
	if cur.Epoch != epoch {
		cur = ControlCursor{Epoch: epoch}
	}
	return s.Update(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO control_applying(marker) VALUES (1)`); err != nil {
			return err
		}
		for _, e := range entries {
			if e.Seq <= cur.Seq {
				continue
			}
			if err := applyControlEntry(ctx, tx, e); err != nil {
				return fmt.Errorf("control entry %d (%s %s): %w", e.Seq, e.Op, e.Table, err)
			}
			cur.Seq, cur.At = e.Seq, e.At
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM control_applying`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feed_cursors(name, seq) VALUES (?, ?)
			ON CONFLICT(name) DO UPDATE SET seq = excluded.seq`, controlCursorName, cur.Seq); err != nil {
			return err
		}
		for name, v := range map[string]string{"follow_epoch": cur.Epoch, "follow_at": fmt.Sprint(cur.At)} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO control_meta(name, value) VALUES (?, ?)
				ON CONFLICT(name) DO UPDATE SET value = excluded.value`, name, v); err != nil {
				return err
			}
		}
		return nil
	})
}

func applyControlEntry(ctx context.Context, tx *Tx, e ControlEntry) error {
	t, ok := controlTables[e.Table]
	if !ok {
		return fmt.Errorf("unknown table")
	}
	key, err := decodeRow(e.Key)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	where := make([]string, len(t.pk))
	keyArgs := make([]any, len(t.pk))
	for i, c := range t.pk {
		v, ok := key[c]
		if !ok {
			return fmt.Errorf("key lacks %s", c)
		}
		where[i] = c + " = ?"
		keyArgs[i] = v
	}
	switch e.Op {
	case "del":
		_, err := tx.ExecContext(ctx, `DELETE FROM `+e.Table+` WHERE `+strings.Join(where, " AND "), keyArgs...)
		return err
	case "put":
		row, err := decodeRow(e.Row)
		if err != nil {
			return fmt.Errorf("row: %w", err)
		}
		set := make([]string, len(t.cols))
		args := make([]any, len(t.cols))
		for i, c := range t.cols {
			v, ok := row[c]
			if !ok {
				return fmt.Errorf("row lacks %s", c)
			}
			set[i] = c + " = ?"
			args[i] = v
		}
		// A rename's new key was free on the home region at this point in its
		// history; a row there now is left over from an earlier replay.
		renamed := false
		newKey := make([]any, len(t.pk))
		for i, c := range t.pk {
			newKey[i] = row[c]
			renamed = renamed || row[c] != keyArgs[i]
		}
		if renamed {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+e.Table+` WHERE `+strings.Join(where, " AND "), newKey...); err != nil {
				return err
			}
		}
		// Update in place first: it keeps the row's rowid, which IAM lists
		// are ordered by, also when the change renamed the row's key.
		res, err := tx.ExecContext(ctx, `UPDATE `+e.Table+` SET `+strings.Join(set, ", ")+
			` WHERE `+strings.Join(where, " AND "), append(args, keyArgs...)...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(t.cols)), ", ")
		_, err = tx.ExecContext(ctx, `INSERT INTO `+e.Table+`(`+strings.Join(t.cols, ", ")+`) VALUES (`+marks+`)
			ON CONFLICT(`+strings.Join(t.pk, ", ")+`) DO UPDATE SET `+excludedSet(t.cols), args...)
		return err
	default:
		return fmt.Errorf("unknown op")
	}
}

func excludedSet(cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = c + " = excluded." + c
	}
	return strings.Join(parts, ", ")
}

// decodeRow turns a JSON object from json_object() into column values:
// integers stay int64, strings stay strings, null stays nil.
func decodeRow(raw json.RawMessage) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	for k, v := range m {
		switch x := v.(type) {
		case json.Number:
			if i, err := x.Int64(); err == nil {
				m[k] = i
			} else if f, err := x.Float64(); err == nil {
				m[k] = f
			} else {
				return nil, fmt.Errorf("%s: bad number %q", k, x)
			}
		case string, nil:
		default:
			return nil, fmt.Errorf("%s: unexpected %T", k, v)
		}
	}
	return m, nil
}
