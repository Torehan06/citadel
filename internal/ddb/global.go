package ddb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"citadel/internal/ddb/expr"
	"citadel/internal/region"
	"citadel/internal/store"
)

// Global tables, version 2019.11.21 (ARCHITECTURE.md §8). UpdateTable's
// ReplicaUpdates adds or removes regions. Every region holding a replica
// accepts writes; each write records the item's version, (HLC, origin
// region), in ddb_item_versions and a change the replicator ships to every
// other replica. A replica applies an incoming item only if its version is
// newer than the one it holds, so all replicas converge on the last writer
// whatever order the writes arrive in. Deletes leave a versioned tombstone
// for the same reason.
//
// The replica set itself travels as a "ReplicaSync" change carrying the
// table's description, ordered by ReplicaSetHLC: a region that is added
// creates its replica from it, a region that is dropped deletes its replica.
//
// Internal endpoints (region-authenticated):
//
//	POST /_citadel/repl/ddb/table    apply a replica set (create/update/delete the replica)
//	POST /_citadel/repl/ddb/items    apply item versions (last writer wins)
//	GET  /_citadel/repl/ddb/digest?account=&table=         anti-entropy leaf digests
//	GET  /_citadel/repl/ddb/leaf?account=&table=&leaf=     one leaf's versions

const (
	globalTableVersion = "2019.11.21"

	replTablePath  = "/_citadel/repl/ddb/table"
	replItemsPath  = "/_citadel/repl/ddb/items"
	replDigestPath = "/_citadel/repl/ddb/digest"
	replLeafPath   = "/_citadel/repl/ddb/leaf"

	replItemBatch = 100
)

// replica is one region holding a global table, as this region knows it.
// Status is CREATING until the region acknowledged the replica set (or
// CREATION_FAILED); every region reports the others ACTIVE once it knows
// they have the table.
type replica struct {
	RegionName string `json:"RegionName"`
	Status     string `json:"Status,omitempty"`
}

func (t *table) global() bool { return len(t.desc.Replicas) > 0 }

func (t *table) replicaIndex(region string) int {
	return slices.IndexFunc(t.desc.Replicas, func(r replica) bool { return r.RegionName == region })
}

type replicaUpdate struct {
	Create *struct {
		RegionName string `json:"RegionName"`
	} `json:"Create"`
	Update *struct {
		RegionName string `json:"RegionName"`
	} `json:"Update"`
	Delete *struct {
		RegionName string `json:"RegionName"`
	} `json:"Delete"`
}

// applyReplicaUpdates changes t's replica set in memory and returns the
// resulting replica set and whether the table just became global.
func (h *Handler) applyReplicaUpdates(t *table, ups []replicaUpdate) (set replicaSet, converted bool, err error) {
	if len(ups) == 0 {
		return set, false, validation("1 validation error detected: Value '[]' at 'replicaUpdates' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	known := map[string]bool{}
	if h.Regions != nil {
		for _, r := range h.Regions() {
			known[r] = true
		}
	}
	notify := map[string]bool{}
	for _, r := range t.desc.Replicas {
		notify[r.RegionName] = true
	}
	for _, u := range ups {
		n := 0
		for _, set := range []bool{u.Create != nil, u.Update != nil, u.Delete != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			return set, false, validation("One or more parameter values were invalid: One of Create, Update, or Delete must be specified in a ReplicationGroupUpdate")
		}
		switch {
		case u.Create != nil:
			name := u.Create.RegionName
			switch {
			case name == h.region:
				return set, false, validation("One or more parameter values were invalid: Cannot add replica in the region of the table: %s", name)
			case !known[name]:
				return set, false, validation("One or more parameter values were invalid: Region %s is not a region of this cloud", name)
			case t.replicaIndex(name) >= 0:
				return set, false, validation("One or more parameter values were invalid: Replica already exists in region %s", name)
			}
			if !t.global() {
				t.desc.Replicas = []replica{{RegionName: h.region, Status: "ACTIVE"}}
				converted = true
			}
			t.desc.Replicas = append(t.desc.Replicas, replica{RegionName: name, Status: "CREATING"})
			notify[name] = true
		case u.Update != nil:
			if t.replicaIndex(u.Update.RegionName) < 0 {
				return set, false, validation("One or more parameter values were invalid: Replica does not exist in region %s", u.Update.RegionName)
			}
		case u.Delete != nil:
			name := u.Delete.RegionName
			i := t.replicaIndex(name)
			if i < 0 || name == h.region {
				return set, false, validation("One or more parameter values were invalid: Replica does not exist in region %s", name)
			}
			t.desc.Replicas = slices.Delete(t.desc.Replicas, i, i+1)
		}
	}
	for _, r := range t.desc.Replicas {
		set.Members = append(set.Members, r.RegionName)
	}
	if len(t.desc.Replicas) == 1 {
		t.desc.Replicas = nil // only this region is left: a regional table again
	}
	delete(notify, h.region)
	for r := range notify {
		set.Targets = append(set.Targets, r)
	}
	slices.Sort(set.Targets)
	return set, converted, nil
}

// replicaSet is a change of a table's replicas: the regions holding one
// afterwards, and the regions to tell (members old and new, except this one).
type replicaSet struct {
	Members []string
	Targets []string
}

// replicaSync is the payload of a ReplicaSync change.
type replicaSync struct {
	Account string    `json:"account"`
	Desc    tableDesc `json:"desc"`
	Members []string  `json:"members"`
	Targets []string  `json:"targets"`
}

// syncReplicasTx records a replica-set change in the write transaction.
func syncReplicasTx(ctx context.Context, tx *store.Tx, t *table, set replicaSet) error {
	if len(set.Targets) == 0 {
		return nil
	}
	return tx.Change("dynamodb", "ReplicaSync", t.desc.TableName,
		replicaSync{Account: t.account, Desc: t.desc, Members: set.Members, Targets: set.Targets})
}

// makeGlobalTx gives every existing item a version, so anti-entropy can
// copy them to the new replicas.
func makeGlobalTx(ctx context.Context, tx *store.Tx, t *table) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ddb_item_versions(table_id, pk, sk, hlc, region, deleted)
		SELECT table_id, pk, sk, ?, ?, 0 FROM ddb_items WHERE table_id = ? AND idx = 0
		ON CONFLICT DO NOTHING`, int64(tx.HLC()), tx.Region(), t.id)
	return err
}

// itemVersion is (HLC, origin region) plus a tombstone flag.
type itemVersion struct {
	HLC     int64  `json:"hlc"`
	Region  string `json:"region"`
	Deleted bool   `json:"deleted,omitempty"`
}

// newer orders versions last-writer-wins on (hlc, region).
func (v itemVersion) newer(than itemVersion) bool {
	if v.HLC != than.HLC {
		return v.HLC > than.HLC
	}
	return v.Region > than.Region
}

func (v itemVersion) String() string {
	return fmt.Sprintf("%d/%s/%t", v.HLC, v.Region, v.Deleted)
}

func recordVersionTx(ctx context.Context, tx *store.Tx, t *table, k itemKey, v itemVersion) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ddb_item_versions(table_id, pk, sk, hlc, region, deleted) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(table_id, pk, sk) DO UPDATE SET hlc = excluded.hlc, region = excluded.region, deleted = excluded.deleted`,
		t.id, k.pk, nonNil(k.sk), v.HLC, v.Region, v.Deleted)
	return err
}

// itemChange is the payload of an ItemVersion change.
type itemChange struct {
	Account string `json:"account"`
	PK      []byte `json:"pk"`
	SK      []byte `json:"sk"`
}

// recordLocalWriteTx versions a local write to a global table and queues it
// for the other replicas.
func recordLocalWriteTx(ctx context.Context, tx *store.Tx, t *table, k itemKey, deleted bool) error {
	if err := recordVersionTx(ctx, tx, t, k, itemVersion{HLC: int64(tx.HLC()), Region: tx.Region(), Deleted: deleted}); err != nil {
		return err
	}
	return tx.Change("dynamodb", "ItemVersion", t.desc.TableName, itemChange{Account: t.account, PK: k.pk, SK: nonNil(k.sk)})
}

// tableByName loads a table outside a request.
func (h *Handler) tableByName(ctx context.Context, q queryer, account, name string) (*table, error) {
	var t table
	var created int64
	var desc string
	err := q.QueryRowContext(ctx, `SELECT id, account_id, created, desc_json, hlc FROM ddb_tables WHERE account_id = ? AND name = ?`,
		account, name).Scan(&t.id, &t.account, &created, &desc, &t.hlc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.created = time.UnixMilli(created)
	return &t, json.Unmarshal([]byte(desc), &t.desc)
}

// ---- shipping (source side) ----------------------------------------------

// replItem is one item version on the wire (Item nil for a tombstone).
type replItem struct {
	PK []byte          `json:"pk"`
	SK []byte          `json:"sk"`
	V  itemVersion     `json:"v"`
	It json.RawMessage `json:"item,omitempty"`
}

type replItems struct {
	Account string     `json:"account"`
	Table   string     `json:"table"`
	Items   []replItem `json:"items"`
}

// Ship implements region.Shipper for global tables.
func (h *Handler) Ship(ctx context.Context, peer *region.Peer, changes []store.Change) ([]store.Change, error) {
	var delivered, batch []store.Change
	var batchAccount, batchTable string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		ok, err := h.shipItems(ctx, peer, batchAccount, batchTable, batch)
		if err != nil {
			return err
		}
		if ok {
			delivered = append(delivered, batch...)
		}
		batch = nil
		return nil
	}
	for _, c := range changes {
		if c.Service != "dynamodb" {
			continue
		}
		switch c.Kind {
		case "ItemVersion":
			var p itemChange
			if json.Unmarshal([]byte(c.Payload), &p) != nil {
				continue
			}
			if len(batch) > 0 && (p.Account != batchAccount || c.Resource != batchTable || len(batch) >= replItemBatch) {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			batchAccount, batchTable = p.Account, c.Resource
			batch = append(batch, c)
		case "ReplicaSync":
			if err := flush(); err != nil {
				return nil, err
			}
			ok, err := h.shipReplicaSet(ctx, peer, c)
			if err != nil {
				return nil, err
			}
			if ok {
				delivered = append(delivered, c)
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return delivered, nil
}

// currentItems reads the current version and content of the given keys.
func (h *Handler) currentItems(ctx context.Context, t *table, keys []itemKey) ([]replItem, error) {
	out := make([]replItem, 0, len(keys))
	for _, k := range keys {
		var v itemVersion
		var deleted int
		err := h.st.DB().QueryRowContext(ctx, `SELECT hlc, region, deleted FROM ddb_item_versions WHERE table_id = ? AND pk = ? AND sk = ?`,
			t.id, k.pk, nonNil(k.sk)).Scan(&v.HLC, &v.Region, &deleted)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		v.Deleted = deleted == 1
		ri := replItem{PK: k.pk, SK: nonNil(k.sk), V: v}
		if !v.Deleted {
			var raw []byte
			err := h.st.DB().QueryRowContext(ctx, `SELECT item FROM ddb_items WHERE table_id = ? AND idx = 0 AND pk = ? AND sk = ? AND bk = X''`,
				t.id, k.pk, nonNil(k.sk)).Scan(&raw)
			if errors.Is(err, sql.ErrNoRows) {
				continue // a write is in flight; its own change will ship it
			}
			if err != nil {
				return nil, err
			}
			ri.It = raw
		}
		out = append(out, ri)
	}
	return out, nil
}

// shipItems sends the current state of the items the changes touched.
// ok is false when the peer doesn't (or no longer) hold the table.
func (h *Handler) shipItems(ctx context.Context, peer *region.Peer, account, name string, changes []store.Change) (bool, error) {
	t, err := h.tableByName(ctx, h.st.DB(), account, name)
	if err != nil || t == nil || t.replicaIndex(peer.Region()) < 0 {
		return false, err
	}
	seen := map[string]bool{}
	var keys []itemKey
	for _, c := range changes {
		var p itemChange
		if json.Unmarshal([]byte(c.Payload), &p) != nil {
			continue
		}
		id := string(p.PK) + "\x00" + string(p.SK)
		if !seen[id] {
			seen[id] = true
			keys = append(keys, itemKey{pk: p.PK, sk: p.SK})
		}
	}
	items, err := h.currentItems(ctx, t, keys)
	if err != nil || len(items) == 0 {
		return err == nil, err
	}
	return h.pushItems(ctx, peer, account, name, items)
}

func (h *Handler) pushItems(ctx context.Context, peer *region.Peer, account, name string, items []replItem) (bool, error) {
	body, _ := json.Marshal(replItems{Account: account, Table: name, Items: items})
	resp, err := peer.Do(ctx, http.MethodPost, replItemsPath, nil, bytes.NewReader(body), http.Header{"Content-Type": {"application/json"}})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		// The replica is gone there (or not created yet: the replica set
		// travels ahead of items on the same stream, so it was dropped).
		return false, nil
	}
	return false, fmt.Errorf("apply items in %s: %s", peer.Region(), resp.Status)
}

// shipReplicaSet delivers a replica-set change to one of its targets and
// records the outcome in this region's view of the replica.
func (h *Handler) shipReplicaSet(ctx context.Context, peer *region.Peer, c store.Change) (bool, error) {
	var p replicaSync
	if err := json.Unmarshal([]byte(c.Payload), &p); err != nil || !slices.Contains(p.Targets, peer.Region()) {
		return false, nil
	}
	body, _ := json.Marshal(p)
	resp, err := peer.Do(ctx, http.MethodPost, replTablePath, nil, bytes.NewReader(body), http.Header{"Content-Type": {"application/json"}})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	status := ""
	switch resp.StatusCode {
	case http.StatusOK:
		status = "ACTIVE"
	case http.StatusConflict:
		status = "CREATION_FAILED"
		h.log.Warn("global table replica not created", "table", c.Resource, "region", peer.Region(), "reason", string(bytes.TrimSpace(msg)))
	default:
		return false, fmt.Errorf("replica set of %s in %s: %s", c.Resource, peer.Region(), resp.Status)
	}
	if err := h.markReplica(ctx, p.Account, c.Resource, peer.Region(), p.Desc.ReplicaSetHLC, status); err != nil {
		return false, err
	}
	if status == "ACTIVE" && h.ReplicaReady != nil {
		h.ReplicaReady(peer.Region()) // backfill existing items now
	}
	return status == "ACTIVE", nil
}

// markReplica sets this region's view of one replica's status, if the replica
// set is still the one that was shipped.
func (h *Handler) markReplica(ctx context.Context, account, name, regionName string, setHLC int64, status string) error {
	return h.st.Update(ctx, func(tx *store.Tx) error {
		t, err := h.tableByName(ctx, tx, account, name)
		if err != nil || t == nil || t.desc.ReplicaSetHLC != setHLC {
			return err
		}
		i := t.replicaIndex(regionName)
		if i < 0 || t.desc.Replicas[i].Status == status {
			return nil
		}
		t.desc.Replicas[i].Status = status
		raw, _ := json.Marshal(t.desc)
		_, err = tx.ExecContext(ctx, `UPDATE ddb_tables SET desc_json = ?, hlc = ? WHERE id = ?`, string(raw), int64(tx.HLC()), t.id)
		return err
	})
}

// ---- applying (destination side) -----------------------------------------

// InternalHandlers returns the region-to-region endpoints DynamoDB serves.
func (h *Handler) InternalHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		replTablePath:  http.HandlerFunc(h.serveReplTable),
		replItemsPath:  http.HandlerFunc(h.serveReplItems),
		replDigestPath: http.HandlerFunc(h.serveReplDigest),
		replLeafPath:   http.HandlerFunc(h.serveReplLeaf),
	}
}

func writeReplJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var errReplicaConflict = errors.New("a regional table with this name already exists in this region")

func (h *Handler) serveReplTable(w http.ResponseWriter, r *http.Request) {
	var in replicaSync
	if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in) != nil || in.Desc.TableName == "" {
		http.Error(w, "bad replica set", http.StatusBadRequest)
		return
	}
	err := h.applyReplicaSet(r.Context(), in)
	switch {
	case errors.Is(err, errReplicaConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		h.log.Error("apply replica set", "table", in.Desc.TableName, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeReplJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// applyReplicaSet creates, updates or deletes this region's replica to match
// a newer replica set. A set of just this region makes the table regional.
func (h *Handler) applyReplicaSet(ctx context.Context, in replicaSync) error {
	selfIn := slices.Contains(in.Members, h.region)
	global := selfIn && len(in.Members) > 1
	desc := in.Desc
	desc.Replicas = nil
	if global {
		for _, m := range in.Members {
			desc.Replicas = append(desc.Replicas, replica{RegionName: m, Status: "ACTIVE"})
		}
	}
	return h.st.Update(ctx, func(tx *store.Tx) error {
		h.st.Clock.Observe(store.HLC(in.Desc.ReplicaSetHLC))
		t, err := h.tableByName(ctx, tx, in.Account, desc.TableName)
		if err != nil {
			return err
		}
		switch {
		case t != nil && desc.ReplicaSetHLC <= t.desc.ReplicaSetHLC:
			return nil // already have this replica set or a newer one
		case t == nil && !global:
			return nil
		case t == nil:
			raw, _ := json.Marshal(desc)
			_, err := tx.ExecContext(ctx, `INSERT INTO ddb_tables(account_id, name, created, desc_json, hlc) VALUES (?, ?, ?, ?, ?)`,
				in.Account, desc.TableName, tx.HLC().WallMs(), string(raw), desc.ReplicaSetHLC)
			if err != nil {
				return err
			}
			return tx.Change("dynamodb", "CreateTable", desc.TableName, map[string]any{"account": in.Account, "replica": true})
		case !t.global():
			if global {
				return errReplicaConflict
			}
			return nil
		case !selfIn:
			if err := dropTableTx(ctx, tx, t); err != nil {
				return err
			}
			return tx.Change("dynamodb", "DeleteTable", desc.TableName, map[string]any{"account": in.Account, "replica": true})
		case !global:
			if _, err := tx.ExecContext(ctx, `DELETE FROM ddb_item_versions WHERE table_id = ?`, t.id); err != nil {
				return err
			}
		}
		t.desc.Replicas, t.desc.ReplicaSetHLC = desc.Replicas, desc.ReplicaSetHLC
		raw, _ := json.Marshal(t.desc)
		_, err = tx.ExecContext(ctx, `UPDATE ddb_tables SET desc_json = ?, hlc = ? WHERE id = ?`, string(raw), int64(tx.HLC()), t.id)
		return err
	})
}

// dropTableTx deletes a table with its items and item versions.
func dropTableTx(ctx context.Context, tx *store.Tx, t *table) error {
	for _, q := range []string{
		`DELETE FROM ddb_items WHERE table_id = ?`,
		`DELETE FROM ddb_item_versions WHERE table_id = ?`,
		`DELETE FROM ddb_tables WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, t.id); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) serveReplItems(w http.ResponseWriter, r *http.Request) {
	var in replItems
	if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 128<<20)).Decode(&in) != nil {
		http.Error(w, "bad items", http.StatusBadRequest)
		return
	}
	applied, err := h.applyItems(r.Context(), in)
	switch {
	case errors.Is(err, errNoReplica):
		writeReplJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case err != nil:
		h.log.Error("apply replicated items", "table", in.Table, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeReplJSON(w, http.StatusOK, map[string]int{"applied": applied})
	}
}

var errNoReplica = errors.New("no replica of this table in this region")

// applyItems applies each item version that is newer than the one held.
func (h *Handler) applyItems(ctx context.Context, in replItems) (int, error) {
	applied := 0
	err := h.st.Update(ctx, func(tx *store.Tx) error {
		t, err := h.tableByName(ctx, tx, in.Account, in.Table)
		if err != nil {
			return err
		}
		if t == nil || !t.global() {
			return errNoReplica
		}
		var newest int64
		for _, ri := range in.Items {
			k := itemKey{pk: ri.PK, sk: ri.SK}
			var cur itemVersion
			var deleted int
			err := tx.QueryRowContext(ctx, `SELECT hlc, region, deleted FROM ddb_item_versions WHERE table_id = ? AND pk = ? AND sk = ?`,
				t.id, k.pk, nonNil(k.sk)).Scan(&cur.HLC, &cur.Region, &deleted)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil && !ri.V.newer(cur) {
				continue
			}
			old, err := getItem(ctx, tx, t, k)
			if err != nil {
				return err
			}
			var item expr.Item
			if !ri.V.Deleted {
				if err := json.Unmarshal(ri.It, &item); err != nil || item == nil {
					return fmt.Errorf("item in %s: %v", in.Table, err)
				}
			}
			if err := writeItemRows(ctx, tx, t, k, old, item); err != nil {
				return err
			}
			if err := recordVersionTx(ctx, tx, t, k, ri.V); err != nil {
				return err
			}
			applied++
			newest = max(newest, ri.V.HLC)
		}
		if applied > 0 {
			// Writes made here from now on must order after what was applied.
			h.st.Clock.Observe(store.HLC(newest))
			return tx.Change("dynamodb", "ReplicatedItems", in.Table, map[string]any{"account": in.Account, "items": applied})
		}
		return nil
	})
	return applied, err
}

// ---- anti-entropy ----------------------------------------------------------

func versionID(pk, sk []byte) string { return hex.EncodeToString(pk) + "/" + hex.EncodeToString(sk) }

// scanVersions visits every item version of a table.
func (h *Handler) scanVersions(ctx context.Context, tableID int64, visit func(pk, sk []byte, v itemVersion)) error {
	rows, err := h.st.DB().QueryContext(ctx, `SELECT pk, sk, hlc, region, deleted FROM ddb_item_versions WHERE table_id = ?`, tableID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var pk, sk []byte
		var v itemVersion
		var deleted int
		if err := rows.Scan(&pk, &sk, &v.HLC, &v.Region, &deleted); err != nil {
			return err
		}
		v.Deleted = deleted == 1
		visit(pk, sk, v)
	}
	return rows.Err()
}

// Repair implements region.Repairer: for every global table replicated to
// peer, compare item-version digests and push every item whose version here
// is newer than (or missing from) the peer's. The peer does the same in the
// other direction, so both converge. This also copies a table's existing
// items to a replica that was just added.
func (h *Handler) Repair(ctx context.Context, peer *region.Peer) error {
	rows, err := h.st.DB().QueryContext(ctx, `SELECT account_id, name FROM ddb_tables`)
	if err != nil {
		return err
	}
	var names [][2]string
	for rows.Next() {
		var a, n string
		if err := rows.Scan(&a, &n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, [2]string{a, n})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, an := range names {
		t, err := h.tableByName(ctx, h.st.DB(), an[0], an[1])
		if err != nil {
			return err
		}
		if t == nil || !t.global() {
			continue
		}
		if i := t.replicaIndex(peer.Region()); i < 0 || t.desc.Replicas[i].Status != "ACTIVE" {
			continue
		}
		if err := h.repairTable(ctx, peer, t); err != nil {
			return fmt.Errorf("anti-entropy %s -> %s: %w", t.desc.TableName, peer.Region(), err)
		}
	}
	return nil
}

func (h *Handler) repairTable(ctx context.Context, peer *region.Peer, t *table) error {
	var local region.Digest
	if err := h.scanVersions(ctx, t.id, func(pk, sk []byte, v itemVersion) { local.Add(versionID(pk, sk), v.String()) }); err != nil {
		return err
	}
	q := url.Values{"account": {t.account}, "table": {t.desc.TableName}}
	var remote struct{ Leaves []string }
	found, err := getReplJSON(ctx, peer, replDigestPath, q, &remote)
	if err != nil || !found {
		return err
	}
	diff := region.DiffLeaves(&local, remote.Leaves)
	if len(diff) == 0 {
		return nil
	}
	theirs := map[string]itemVersion{}
	want := map[int]bool{}
	for _, leaf := range diff {
		want[leaf] = true
		lq := url.Values{"account": {t.account}, "table": {t.desc.TableName}, "leaf": {strconv.Itoa(leaf)}}
		var entries struct {
			Entries map[string]itemVersion
		}
		if _, err := getReplJSON(ctx, peer, replLeafPath, lq, &entries); err != nil {
			return err
		}
		for id, v := range entries.Entries {
			theirs[id] = v
		}
	}
	var keys []itemKey
	if err := h.scanVersions(ctx, t.id, func(pk, sk []byte, v itemVersion) {
		id := versionID(pk, sk)
		if !want[region.LeafOf(id)] {
			return
		}
		if tv, ok := theirs[id]; !ok || v.newer(tv) {
			keys = append(keys, itemKey{pk: pk, sk: sk})
		}
	}); err != nil {
		return err
	}
	if len(keys) > 0 {
		h.log.Info("anti-entropy repair", "table", t.desc.TableName, "dest", peer.Region(), "items", len(keys))
	}
	for start := 0; start < len(keys); start += replItemBatch {
		items, err := h.currentItems(ctx, t, keys[start:min(start+replItemBatch, len(keys))])
		if err != nil {
			return err
		}
		if len(items) == 0 {
			continue
		}
		if _, err := h.pushItems(ctx, peer, t.account, t.desc.TableName, items); err != nil {
			return err
		}
	}
	return nil
}

// getReplJSON GETs an internal endpoint; found is false on 404.
func getReplJSON(ctx context.Context, peer *region.Peer, path string, q url.Values, dst any) (found bool, err error) {
	resp, err := peer.Do(ctx, http.MethodGet, path, q, nil, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, json.NewDecoder(resp.Body).Decode(dst)
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("%s in %s: %s", path, peer.Region(), resp.Status)
}

func (h *Handler) replTable(w http.ResponseWriter, r *http.Request) *table {
	q := r.URL.Query()
	t, err := h.tableByName(r.Context(), h.st.DB(), q.Get("account"), q.Get("table"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	if t == nil || !t.global() {
		http.Error(w, "no replica", http.StatusNotFound)
		return nil
	}
	return t
}

func (h *Handler) serveReplDigest(w http.ResponseWriter, r *http.Request) {
	t := h.replTable(w, r)
	if t == nil {
		return
	}
	var d region.Digest
	if err := h.scanVersions(r.Context(), t.id, func(pk, sk []byte, v itemVersion) { d.Add(versionID(pk, sk), v.String()) }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeReplJSON(w, http.StatusOK, map[string]any{"Leaves": d.Hex()})
}

func (h *Handler) serveReplLeaf(w http.ResponseWriter, r *http.Request) {
	t := h.replTable(w, r)
	if t == nil {
		return
	}
	leaf, err := strconv.Atoi(r.URL.Query().Get("leaf"))
	if err != nil || leaf < 0 || leaf >= region.Leaves {
		http.Error(w, "bad leaf", http.StatusBadRequest)
		return
	}
	entries := map[string]itemVersion{}
	if err := h.scanVersions(r.Context(), t.id, func(pk, sk []byte, v itemVersion) {
		if id := versionID(pk, sk); region.LeafOf(id) == leaf {
			entries[id] = v
		}
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeReplJSON(w, http.StatusOK, map[string]any{"Entries": entries})
}

// describeReplicas adds the global-table fields to a table description.
func (h *Handler) describeReplicas(t *table, d map[string]any) {
	if !t.global() {
		return
	}
	d["GlobalTableVersion"] = globalTableVersion
	class := t.desc.TableClass
	if class == "" {
		class = "STANDARD"
	}
	var reps []map[string]any
	for _, r := range t.desc.Replicas {
		if r.RegionName == h.region {
			continue
		}
		st := r.Status
		if st == "" {
			st = "ACTIVE"
		}
		reps = append(reps, map[string]any{
			"RegionName": r.RegionName, "ReplicaStatus": st,
			"ReplicaTableClassSummary": map[string]any{"TableClass": class},
		})
	}
	if len(reps) > 0 {
		d["Replicas"] = reps
	}
}
