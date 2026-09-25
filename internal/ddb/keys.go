package ddb

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"

	"citadel/internal/ddb/expr"
	"citadel/internal/store"
)

// Keys and item storage. A key attribute value is encoded so that bytewise
// order is DynamoDB order: S as its UTF-8 bytes, B as-is, N with
// expr.Number.KeyBytes. The partition and sort keys sit in separate
// columns, so no escaping is needed.

const (
	maxItemSize     = 400 * 1024
	maxHashKeySize  = 2048
	maxRangeKeySize = 1024
)

// itemKey is an item's encoded primary key.
type itemKey struct{ pk, sk []byte }

// baseKey packs a primary key for index rows: 4-byte pk length, pk, sk.
func (k itemKey) baseKey() []byte {
	b := make([]byte, 4, 4+len(k.pk)+len(k.sk))
	binary.BigEndian.PutUint32(b, uint32(len(k.pk)))
	return append(append(b, k.pk...), k.sk...)
}

func keyBytes(v *expr.Value) []byte {
	switch v.Kind {
	case expr.S:
		return []byte(v.S)
	case expr.B:
		return v.B
	case expr.N:
		return v.N.KeyBytes()
	}
	return nil
}

// keyValue validates one key attribute value.
func keyValue(name, want string, v *expr.Value, max int, index string) ([]byte, error) {
	if string(v.Kind) != want {
		if index != "" {
			return nil, validation("One or more parameter values were invalid: Type mismatch for Index Key %s Expected: %s Actual: %s IndexName: %s", name, want, v.Kind, index)
		}
		return nil, validation("One or more parameter values were invalid: Type mismatch for key %s expected: %s actual: %s", name, want, v.Kind)
	}
	b := keyBytes(v)
	if v.Kind == expr.S && v.S == "" || v.Kind == expr.B && len(v.B) == 0 {
		kind := "string"
		if v.Kind == expr.B {
			kind = "binary"
		}
		if index != "" {
			return nil, validation("One or more parameter values are not valid. A value specified for a secondary index key is not supported. The AttributeValue for a key attribute cannot contain an empty %s value. IndexName: %s, IndexKey: %s", kind, index, name)
		}
		return nil, validation("One or more parameter values are not valid. The AttributeValue for a key attribute cannot contain an empty %s value. Key: %s", kind, name)
	}
	size := len(b)
	if v.Kind == expr.N {
		size = 0 // numbers are always small enough
	}
	if size > max {
		if max == maxHashKeySize {
			return nil, validation("One or more parameter values were invalid: Size of hashkey has exceeded the maximum size limit of2048 bytes")
		}
		return nil, validation("One or more parameter values were invalid: Aggregated size of all range keys has exceeded the size limit of 1024 bytes")
	}
	return b, nil
}

// keyFromItem extracts the primary key of a full item (PutItem).
func (t *table) keyFromItem(it expr.Item) (itemKey, error) {
	var k itemKey
	var err error
	hk, rk := t.hashKey(), t.rangeKey()
	hv := it[hk]
	if hv == nil {
		return k, validation("One or more parameter values were invalid: Missing the key %s in the item", hk)
	}
	if k.pk, err = keyValue(hk, t.attrType(hk), hv, maxHashKeySize, ""); err != nil {
		return k, err
	}
	if rk != "" {
		rv := it[rk]
		if rv == nil {
			return k, validation("One or more parameter values were invalid: Missing the key %s in the item", rk)
		}
		if k.sk, err = keyValue(rk, t.attrType(rk), rv, maxRangeKeySize, ""); err != nil {
			return k, err
		}
	}
	return k, nil
}

// keyFromKey validates a Key parameter: exactly the key attributes.
func (t *table) keyFromKey(key expr.Item) (itemKey, error) {
	want := 1
	if t.rangeKey() != "" {
		want = 2
	}
	if len(key) != want || key[t.hashKey()] == nil || t.rangeKey() != "" && key[t.rangeKey()] == nil {
		return itemKey{}, validation("The provided key element does not match the schema")
	}
	for name, v := range key {
		if string(v.Kind) != t.attrType(name) {
			return itemKey{}, validation("The provided key element does not match the schema")
		}
	}
	return t.keyFromItem(key)
}

// keyItem returns just the key attributes of an item.
func (t *table) keyItem(it expr.Item) expr.Item {
	out := expr.Item{t.hashKey(): it[t.hashKey()]}
	if rk := t.rangeKey(); rk != "" {
		out[rk] = it[rk]
	}
	return out
}

// validateItem checks an item's size and shape before it is stored.
func validateItem(it expr.Item) error {
	for name, v := range it {
		if name == "" {
			return validation("One or more parameter values were invalid: An attribute name cannot be empty")
		}
		if depth(v) > 32 {
			return validation("Nesting Levels have exceeded supported limits")
		}
	}
	if it.Size() > maxItemSize {
		return validation("Item size has exceeded the maximum allowed size")
	}
	return nil
}

func depth(v *expr.Value) int {
	d := 0
	switch v.Kind {
	case expr.M:
		for _, e := range v.M {
			d = max(d, depth(e))
		}
		return d + 1
	case expr.L:
		for _, e := range v.L {
			d = max(d, depth(e))
		}
		return d + 1
	}
	return 0
}

// queryer is a *sql.DB or a transaction.
type queryer interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// getItem reads the item with key k (nil when absent).
func getItem(ctx context.Context, q queryer, t *table, k itemKey) (expr.Item, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT item FROM ddb_items WHERE table_id = ? AND idx = 0 AND pk = ? AND sk = ? AND bk = X''`,
		t.id, k.pk, nonNil(k.sk)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var it expr.Item
	return it, json.Unmarshal(raw, &it)
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// index is a secondary index resolved against its table.
type index struct {
	def    indexDef
	global bool
}

func (t *table) indexes() []index {
	var out []index
	for _, g := range t.desc.GSIs {
		out = append(out, index{g, true})
	}
	for _, l := range t.desc.LSIs {
		out = append(out, index{l, false})
	}
	return out
}

func (t *table) findIndex(name string) (index, bool) {
	for _, ix := range t.indexes() {
		if ix.def.IndexName == name {
			return ix, true
		}
	}
	return index{}, false
}

// indexKey extracts an item's key in an index; ok is false when the item
// lacks an index key attribute (it is then not in the index).
func (t *table) indexKey(ix index, it expr.Item) (k itemKey, ok bool, err error) {
	h := ix.def.KeySchema[0].AttributeName
	hv := it[h]
	if hv == nil {
		return k, false, nil
	}
	if k.pk, err = keyValue(h, t.attrType(h), hv, maxHashKeySize, ix.def.IndexName); err != nil {
		return k, false, err
	}
	if len(ix.def.KeySchema) > 1 {
		r := ix.def.KeySchema[1].AttributeName
		rv := it[r]
		if rv == nil {
			return k, false, nil
		}
		if k.sk, err = keyValue(r, t.attrType(r), rv, maxRangeKeySize, ix.def.IndexName); err != nil {
			return k, false, err
		}
	}
	return k, true, nil
}

// projectForIndex keeps the attributes an index projects.
func (t *table) projectForIndex(ix index, it expr.Item) expr.Item {
	if ix.def.Projection.ProjectionType == "ALL" {
		return it
	}
	out := t.keyItem(it)
	for _, k := range ix.def.KeySchema {
		if v := it[k.AttributeName]; v != nil {
			out[k.AttributeName] = v
		}
	}
	for _, name := range ix.def.Projection.NonKeyAttributes {
		if v := it[name]; v != nil {
			out[name] = v
		}
	}
	return out
}

// validateIndexKeys checks an item's index key attributes before a write.
func (t *table) validateIndexKeys(it expr.Item) error {
	for _, ix := range t.indexes() {
		if _, _, err := t.indexKey(ix, it); err != nil {
			return err
		}
	}
	return nil
}

// writeItem replaces the item at k (old → new; new nil deletes), keeping
// every secondary index in step within the same transaction.
func writeItem(ctx context.Context, tx *store.Tx, t *table, k itemKey, old, new expr.Item) error {
	bk := k.baseKey()
	for _, ix := range t.indexes() {
		if old != nil {
			if ik, ok, _ := t.indexKey(ix, old); ok {
				if _, err := tx.ExecContext(ctx, `DELETE FROM ddb_items WHERE table_id = ? AND idx = ? AND pk = ? AND sk = ? AND bk = ?`,
					t.id, ix.def.ID, ik.pk, nonNil(ik.sk), bk); err != nil {
					return err
				}
			}
		}
		if new != nil {
			ik, ok, err := t.indexKey(ix, new)
			if err != nil {
				return err
			}
			if ok {
				proj := t.projectForIndex(ix, new)
				raw, _ := json.Marshal(proj)
				if _, err := tx.ExecContext(ctx, `INSERT INTO ddb_items(table_id, idx, pk, sk, bk, item, size) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					t.id, ix.def.ID, ik.pk, nonNil(ik.sk), bk, raw, proj.Size()); err != nil {
					return err
				}
			}
		}
	}
	if new == nil {
		_, err := tx.ExecContext(ctx, `DELETE FROM ddb_items WHERE table_id = ? AND idx = 0 AND pk = ? AND sk = ? AND bk = X''`,
			t.id, k.pk, nonNil(k.sk))
		return err
	}
	raw, _ := json.Marshal(new)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ddb_items(table_id, idx, pk, sk, bk, item, size) VALUES (?, 0, ?, ?, X'', ?, ?)
		ON CONFLICT(table_id, idx, pk, sk, bk) DO UPDATE SET item = excluded.item, size = excluded.size`,
		t.id, k.pk, nonNil(k.sk), raw, new.Size())
	return err
}
