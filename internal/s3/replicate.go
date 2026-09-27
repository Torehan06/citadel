package s3

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"citadel/internal/region"
	"citadel/internal/store"
)

// Cross-region replication, the moving part (ARCHITECTURE.md §8). The
// region package runs one worker per destination region over the change log;
// Ship picks out the object versions that a bucket's replication rules send
// to a bucket in that region and pushes them. Blobs are content-addressed,
// so the destination first answers which of a batch's blobs it lacks and
// only those travel. The destination inserts each version under its own
// version ID and ordering key, so replicas keep the source's history and the
// newest version wins wherever it was written.
//
// Internal endpoints (region-authenticated, see region.Registry.Authenticate):
//
//	GET  /_citadel/repl/s3/bucket?name=      does this region hold the bucket?
//	POST /_citadel/repl/s3/versions          apply a batch of versions
//	PUT  /_citadel/repl/blob?sha=            store one blob
//	GET  /_citadel/repl/s3/digest?bucket=&source=      anti-entropy leaf digests
//	GET  /_citadel/repl/s3/leaf?bucket=&source=&leaf=  one leaf's entries

const (
	replBucketPath   = "/_citadel/repl/s3/bucket"
	replVersionsPath = "/_citadel/repl/s3/versions"
	replBlobPath     = "/_citadel/repl/blob"
	replDigestPath   = "/_citadel/repl/s3/digest"
	replLeafPath     = "/_citadel/repl/s3/leaf"

	replPushBatch = 100
)

// replVersion is one object version on the wire. JSON columns travel as
// stored.
type replVersion struct {
	Key          string `json:"key"`
	VersionID    string `json:"version"`
	DeleteMarker bool   `json:"dm,omitempty"`
	Seq          int64  `json:"seq"`
	HLC          int64  `json:"hlc"`
	Size         int64  `json:"size"`
	ETag         string `json:"etag,omitempty"`
	Blob         string `json:"blob,omitempty"`
	PartsJSON    string `json:"parts,omitempty"`
	LastModified int64  `json:"lm"`
	Owner        string `json:"owner"`
	MetaJSON     string `json:"meta"`
	ACL          string `json:"acl,omitempty"`
	Tagging      string `json:"tagging,omitempty"`

	status string // source replication status, not sent
}

// blobs lists every blob the version's content needs.
func (v *replVersion) blobs() []string {
	var out []string
	if v.Blob != "" {
		out = append(out, v.Blob)
	}
	if v.PartsJSON != "" {
		var parts []partRef
		if json.Unmarshal([]byte(v.PartsJSON), &parts) == nil {
			for _, p := range parts {
				out = append(out, p.Blob)
			}
		}
	}
	return out
}

type replPush struct {
	Source   string        `json:"source"` // "region/bucket"
	Bucket   string        `json:"bucket"`
	Versions []replVersion `json:"versions"`
}

type replPushResult struct {
	Missing []string `json:"missing,omitempty"`
	Applied int      `json:"applied"`
}

// replState caches where destination buckets live.
type replState struct {
	mu  sync.Mutex
	loc map[string]bucketLoc // "peer/bucket"
}

type bucketLoc struct {
	exists     bool
	versioning string
	until      time.Time
}

const replVersionCols = `key, version_id, delete_marker, seq, hlc, size, etag, blob, parts_json, last_modified, owner, meta_json, acl, tagging, repl_status`

func scanReplVersion(sc interface{ Scan(...any) error }) (replVersion, error) {
	var v replVersion
	var dm int
	err := sc.Scan(&v.Key, &v.VersionID, &dm, &v.Seq, &v.HLC, &v.Size, &v.ETag, &v.Blob, &v.PartsJSON, &v.LastModified,
		&v.Owner, &v.MetaJSON, &v.ACL, &v.Tagging, &v.status)
	v.DeleteMarker = dm == 1
	return v, err
}

// locate reports whether peer holds bucket, and its versioning state.
func (h *Handler) locate(ctx context.Context, peer *region.Peer, bucket string) (bucketLoc, error) {
	id := peer.Region() + "/" + bucket
	h.repl.mu.Lock()
	if l, ok := h.repl.loc[id]; ok && time.Now().Before(l.until) {
		h.repl.mu.Unlock()
		return l, nil
	}
	h.repl.mu.Unlock()
	resp, err := peer.Do(ctx, http.MethodGet, replBucketPath, url.Values{"name": {bucket}}, nil, nil)
	if err != nil {
		return bucketLoc{}, err
	}
	defer resp.Body.Close()
	var l bucketLoc
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct{ Versioning string }
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return bucketLoc{}, err
		}
		l = bucketLoc{exists: true, versioning: body.Versioning, until: time.Now().Add(30 * time.Second)}
	case http.StatusNotFound:
		l = bucketLoc{until: time.Now().Add(10 * time.Second)}
	default:
		return bucketLoc{}, fmt.Errorf("locate bucket %s in %s: %s", bucket, peer.Region(), resp.Status)
	}
	h.repl.mu.Lock()
	if h.repl.loc == nil {
		h.repl.loc = map[string]bucketLoc{}
	}
	h.repl.loc[id] = l
	h.repl.mu.Unlock()
	return l, nil
}

func (h *Handler) forget(peer *region.Peer, bucket string) {
	h.repl.mu.Lock()
	delete(h.repl.loc, peer.Region()+"/"+bucket)
	h.repl.mu.Unlock()
}

// Ship implements region.Shipper for S3 cross-region replication.
func (h *Handler) Ship(ctx context.Context, peer *region.Peer, changes []store.Change) ([]store.Change, error) {
	type pending struct {
		v    replVersion
		c    store.Change
		rule *replRule
	}
	configs := map[string]*replicationConfiguration{}
	batches := map[string][]pending{} // destination bucket -> versions, in change order
	var order []string
	for _, c := range changes {
		if c.Service != "s3" || c.Kind != "PutObject" && c.Kind != "PutDeleteMarker" {
			continue
		}
		bucket, key, ok := strings.Cut(c.Resource, "/")
		if !ok {
			continue
		}
		cfg, seen := configs[bucket]
		if !seen {
			var raw string
			err := h.st.DB().QueryRowContext(ctx, `SELECT replication FROM s3_buckets WHERE name = ?`, bucket).Scan(&raw)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			cfg = loadReplication(raw)
			configs[bucket] = cfg
		}
		if cfg == nil {
			continue
		}
		var p struct{ Version string }
		_ = json.Unmarshal([]byte(c.Payload), &p)
		v, err := scanReplVersion(h.st.DB().QueryRowContext(ctx,
			`SELECT `+replVersionCols+` FROM s3_objects WHERE bucket = ? AND key = ? AND version_id = ?`, bucket, key, p.Version))
		if errors.Is(err, sql.ErrNoRows) {
			continue // the version was deleted before it could ship
		}
		if err != nil {
			return nil, err
		}
		if v.status == "" || v.status == replReplica {
			continue // not selected when written, or itself a replica
		}
		for dest, rule := range cfg.destinations(key, parseStoredTags(v.Tagging), v.DeleteMarker) {
			loc, err := h.locate(ctx, peer, dest)
			if err != nil {
				return nil, err
			}
			if !loc.exists {
				continue
			}
			id := bucket + "\x00" + dest
			if _, ok := batches[id]; !ok {
				order = append(order, id)
			}
			batches[id] = append(batches[id], pending{v, c, rule})
		}
	}
	var delivered []store.Change
	for _, id := range order {
		bucket, dest, _ := strings.Cut(id, "\x00")
		list := batches[id]
		for start := 0; start < len(list); start += replPushBatch {
			chunk := list[start:min(start+replPushBatch, len(list))]
			vs := make([]replVersion, len(chunk))
			for i, p := range chunk {
				vs[i] = withStorageClass(p.v, p.rule)
			}
			status, err := h.push(ctx, peer, bucket, dest, vs)
			if err != nil {
				return nil, err
			}
			if err := h.setReplStatus(ctx, bucket, vs, status); err != nil {
				return nil, err
			}
			if status == replCompleted {
				for _, p := range chunk {
					delivered = append(delivered, p.c)
				}
			}
		}
	}
	return delivered, nil
}

// withStorageClass applies the rule's destination storage class.
func withStorageClass(v replVersion, r *replRule) replVersion {
	if r == nil || r.Destination.StorageClass == "" || v.DeleteMarker {
		return v
	}
	var m objectMeta
	if json.Unmarshal([]byte(v.MetaJSON), &m) == nil {
		m.StorageClass = r.Destination.StorageClass
		if m.StorageClass == "STANDARD" {
			m.StorageClass = ""
		}
		b, _ := json.Marshal(m)
		v.MetaJSON = string(b)
	}
	return v
}

// push sends versions to bucket dest in peer, uploading the blobs it lacks,
// and returns the replication status they end in. Errors are transient.
func (h *Handler) push(ctx context.Context, peer *region.Peer, source, dest string, vs []replVersion) (string, error) {
	body, _ := json.Marshal(replPush{Source: h.region + "/" + source, Bucket: dest, Versions: vs})
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := peer.Do(ctx, http.MethodPost, replVersionsPath, nil, bytes.NewReader(body),
			http.Header{"Content-Type": {"application/json"}})
		if err != nil {
			return "", err
		}
		var res replPushResult
		derr := json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict:
			// The destination bucket is gone or no longer versioned: S3
			// reports FAILED and moves on.
			h.forget(peer, dest)
			h.log.Warn("replication failed", "bucket", source, "dest", peer.Region()+"/"+dest, "status", resp.Status)
			return replFailed, nil
		case resp.StatusCode != http.StatusOK:
			return "", fmt.Errorf("apply versions in %s: %s", peer.Region(), resp.Status)
		case derr != nil:
			return "", derr
		case len(res.Missing) == 0:
			return replCompleted, nil
		}
		for _, sha := range res.Missing {
			if err := h.sendBlob(ctx, peer, sha); err != nil {
				return "", err
			}
		}
	}
	return "", fmt.Errorf("apply versions in %s: blobs still missing after upload", peer.Region())
}

func (h *Handler) sendBlob(ctx context.Context, peer *region.Peer, sha string) error {
	f, err := h.st.Blobs.Open(sha)
	if err != nil {
		return fmt.Errorf("blob %s: %w", sha, err)
	}
	defer f.Close()
	resp, err := peer.Do(ctx, http.MethodPut, replBlobPath, url.Values{"sha": {sha}}, f, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("send blob to %s: %s %s", peer.Region(), resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

// setReplStatus records the outcome on the source versions. Delete markers
// keep their status: S3 never reports one for them.
func (h *Handler) setReplStatus(ctx context.Context, bucket string, vs []replVersion, status string) error {
	return h.st.Update(ctx, func(tx *store.Tx) error {
		for _, v := range vs {
			if _, err := tx.ExecContext(ctx, `UPDATE s3_objects SET repl_status = ? WHERE bucket = ? AND key = ? AND version_id = ? AND repl_status IN (?, ?)`,
				status, bucket, v.Key, v.VersionID, replPending, replFailed); err != nil {
				return err
			}
		}
		return nil
	})
}

// InternalHandlers returns the region-to-region endpoints S3 serves.
func (h *Handler) InternalHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		replBucketPath:   http.HandlerFunc(h.serveReplBucket),
		replVersionsPath: http.HandlerFunc(h.serveReplVersions),
		replBlobPath:     http.HandlerFunc(h.serveReplBlob),
		replDigestPath:   http.HandlerFunc(h.serveReplDigest),
		replLeafPath:     http.HandlerFunc(h.serveReplLeaf),
	}
}

func writeReplJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) serveReplBucket(w http.ResponseWriter, r *http.Request) {
	var versioning string
	err := h.st.DB().QueryRowContext(r.Context(), `SELECT versioning FROM s3_buckets WHERE name = ?`, r.URL.Query().Get("name")).Scan(&versioning)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeReplJSON(w, http.StatusNotFound, map[string]string{"error": "NoSuchBucket"})
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeReplJSON(w, http.StatusOK, map[string]string{"Versioning": versioning})
	}
}

func (h *Handler) serveReplBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sha := r.URL.Query().Get("sha")
	p, err := h.st.Blobs.Write(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer p.Abort()
	if p.SHA256 != sha {
		http.Error(w, "content does not match sha "+sha, http.StatusBadRequest)
		return
	}
	if err := p.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// haveBlob reports whether a blob is stored, and refreshes its mtime so the
// sweeper's grace period covers it until the version referencing it commits.
func (h *Handler) haveBlob(sha string) bool {
	path := h.st.Blobs.Path(sha)
	if _, err := os.Stat(path); err != nil {
		return false
	}
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	return true
}

func (h *Handler) serveReplVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in replPush
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var missing []string
	seen := map[string]bool{}
	for _, v := range in.Versions {
		for _, sha := range v.blobs() {
			if !seen[sha] && !h.haveBlob(sha) {
				missing = append(missing, sha)
			}
			seen[sha] = true
		}
	}
	if len(missing) > 0 {
		writeReplJSON(w, http.StatusOK, replPushResult{Missing: missing})
		return
	}
	applied, err := h.applyVersions(r.Context(), in)
	var e *Error
	switch {
	case errors.As(err, &e):
		writeReplJSON(w, e.Status, map[string]string{"error": e.Code, "message": e.Message})
	case err != nil:
		h.log.Error("apply replicated versions", "bucket", in.Bucket, "source", in.Source, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeReplJSON(w, http.StatusOK, replPushResult{Applied: applied})
	}
}

// applyVersions inserts replicated versions into bucket. A version already
// present is left alone, so re-sent batches change nothing. The latest
// version of each key is the one with the highest ordering key (the source's
// HLC-based seq), whichever region wrote it.
func (h *Handler) applyVersions(ctx context.Context, in replPush) (int, error) {
	applied := 0
	var newest int64
	err := h.st.Update(ctx, func(tx *store.Tx) error {
		var versioning string
		err := tx.QueryRowContext(ctx, `SELECT versioning FROM s3_buckets WHERE name = ?`, in.Bucket).Scan(&versioning)
		if errors.Is(err, sql.ErrNoRows) {
			return errNoSuchBucket(in.Bucket)
		}
		if err != nil {
			return err
		}
		if versioning != versioningEnabled {
			return errf(409, "InvalidBucketState", "Destination bucket must have versioning enabled.")
		}
		for _, v := range in.Versions {
			res, err := tx.ExecContext(ctx, `
				INSERT INTO s3_objects(bucket, key, version_id, seq, is_latest, delete_marker, size, etag, blob, parts_json,
					last_modified, owner, meta_json, acl, tagging, hlc, repl_status, repl_source)
				SELECT ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, COALESCE((SELECT id FROM accounts WHERE id = ?), b.account_id), ?, ?, ?, ?, ?, ?
				FROM s3_buckets b WHERE b.name = ?
				ON CONFLICT(bucket, key, version_id) DO NOTHING`,
				in.Bucket, v.Key, v.VersionID, v.Seq, boolInt(v.DeleteMarker), v.Size, v.ETag, v.Blob, v.PartsJSON,
				v.LastModified, v.Owner, v.MetaJSON, v.ACL, v.Tagging, v.HLC, replReplica, in.Source, in.Bucket)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			applied++
			newest = max(newest, v.HLC)
			if _, err := tx.ExecContext(ctx, `UPDATE s3_objects SET is_latest = 0 WHERE bucket = ? AND key = ? AND is_latest = 1`, in.Bucket, v.Key); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE s3_objects SET is_latest = 1 WHERE rowid = (
					SELECT rowid FROM s3_objects WHERE bucket = ? AND key = ? ORDER BY seq DESC, version_id DESC LIMIT 1)`,
				in.Bucket, v.Key); err != nil {
				return err
			}
			kind, payload := "PutObject", map[string]any{"version": v.VersionID, "size": v.Size, "etag": v.ETag, "event": "Put", "replica": true}
			if v.DeleteMarker {
				kind, payload = "PutDeleteMarker", map[string]any{"version": v.VersionID, "replica": true}
			}
			if err := tx.Change("s3", kind, in.Bucket+"/"+v.Key, payload); err != nil {
				return err
			}
		}
		return nil
	})
	if newest > 0 {
		h.st.Clock.Observe(store.HLC(newest))
	}
	return applied, err
}

// ---- anti-entropy --------------------------------------------------------

// Repair implements region.Repairer: for every bucket that replicates into a
// bucket held by peer, compare the versions the rules are responsible for
// with what the destination holds from this source, and push what's missing.
// The stream normally delivers everything; this covers a destination that
// lost data or a version whose shipment failed permanently at the time.
// Versions deleted at the source are not deleted at the destination, as in
// S3, so a destination may hold more than the source: only missing versions
// are repaired.
func (h *Handler) Repair(ctx context.Context, peer *region.Peer) error {
	rows, err := h.st.DB().QueryContext(ctx, `SELECT name, replication FROM s3_buckets WHERE replication <> ''`)
	if err != nil {
		return err
	}
	type src struct {
		bucket string
		cfg    *replicationConfiguration
	}
	var srcs []src
	for rows.Next() {
		var s src
		var raw string
		if err := rows.Scan(&s.bucket, &raw); err != nil {
			rows.Close()
			return err
		}
		if s.cfg = loadReplication(raw); s.cfg != nil {
			srcs = append(srcs, s)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range srcs {
		dests := map[string]bool{}
		for _, r := range s.cfg.Rules {
			if r.Status == "Enabled" {
				dests[destBucketName(r.Destination.Bucket)] = true
			}
		}
		for dest := range dests {
			loc, err := h.locate(ctx, peer, dest)
			if err != nil {
				return err
			}
			if !loc.exists || loc.versioning != versioningEnabled {
				continue
			}
			if err := h.repairBucket(ctx, peer, s.bucket, dest, s.cfg); err != nil {
				return fmt.Errorf("anti-entropy %s -> %s/%s: %w", s.bucket, peer.Region(), dest, err)
			}
		}
	}
	return nil
}

func replEntryID(key, version string) string { return key + "\x00" + version }

// scanSelected visits the source versions of bucket that the configuration
// sends to dest (only those marked for replication when written: S3 doesn't
// replicate objects that existed before the configuration).
func (h *Handler) scanSelected(ctx context.Context, bucket, dest string, cfg *replicationConfiguration, visit func(replVersion) error) error {
	rows, err := h.st.DB().QueryContext(ctx, `SELECT `+replVersionCols+` FROM s3_objects WHERE bucket = ? AND repl_status IN (?, ?, ?)`,
		bucket, replPending, replCompleted, replFailed)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanReplVersion(rows)
		if err != nil {
			return err
		}
		if r, ok := cfg.destinations(v.Key, parseStoredTags(v.Tagging), v.DeleteMarker)[dest]; ok {
			if err := visit(withStorageClass(v, r)); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (h *Handler) repairBucket(ctx context.Context, peer *region.Peer, bucket, dest string, cfg *replicationConfiguration) error {
	var local region.Digest
	if err := h.scanSelected(ctx, bucket, dest, cfg, func(v replVersion) error {
		local.Add(replEntryID(v.Key, v.VersionID), "")
		return nil
	}); err != nil {
		return err
	}
	source := h.region + "/" + bucket
	q := url.Values{"bucket": {dest}, "source": {source}}
	var remote struct{ Leaves []string }
	if err := getReplJSON(ctx, peer, replDigestPath, q, &remote); err != nil {
		return err
	}
	diff := region.DiffLeaves(&local, remote.Leaves)
	if len(diff) == 0 {
		return nil
	}
	have := map[string]bool{}
	want := map[int]bool{}
	for _, leaf := range diff {
		want[leaf] = true
		lq := url.Values{"bucket": {dest}, "source": {source}, "leaf": {strconv.Itoa(leaf)}}
		var entries struct{ Entries []string }
		if err := getReplJSON(ctx, peer, replLeafPath, lq, &entries); err != nil {
			return err
		}
		for _, e := range entries.Entries {
			have[e] = true
		}
	}
	var missing []replVersion
	if err := h.scanSelected(ctx, bucket, dest, cfg, func(v replVersion) error {
		id := replEntryID(v.Key, v.VersionID)
		if want[region.LeafOf(id)] && !have[id] {
			missing = append(missing, v)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(missing) > 0 {
		h.log.Info("anti-entropy repair", "bucket", bucket, "dest", peer.Region()+"/"+dest, "versions", len(missing))
	}
	for start := 0; start < len(missing); start += replPushBatch {
		chunk := missing[start:min(start+replPushBatch, len(missing))]
		status, err := h.push(ctx, peer, bucket, dest, chunk)
		if err != nil {
			return err
		}
		if err := h.setReplStatus(ctx, bucket, chunk, status); err != nil {
			return err
		}
	}
	return nil
}

func getReplJSON(ctx context.Context, peer *region.Peer, path string, q url.Values, dst any) error {
	resp, err := peer.Do(ctx, http.MethodGet, path, q, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s in %s: %s", path, peer.Region(), resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// scanReplicas visits the (key, version) of every version in bucket that was
// replicated from source.
func (h *Handler) scanReplicas(ctx context.Context, bucket, source string, visit func(id string)) error {
	rows, err := h.st.DB().QueryContext(ctx, `SELECT key, version_id FROM s3_objects WHERE bucket = ? AND repl_source = ?`, bucket, source)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		visit(replEntryID(k, v))
	}
	return rows.Err()
}

func (h *Handler) serveReplDigest(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var d region.Digest
	if err := h.scanReplicas(r.Context(), q.Get("bucket"), q.Get("source"), func(id string) { d.Add(id, "") }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeReplJSON(w, http.StatusOK, map[string]any{"Leaves": d.Hex()})
}

func (h *Handler) serveReplLeaf(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	leaf, err := strconv.Atoi(q.Get("leaf"))
	if err != nil || leaf < 0 || leaf >= region.Leaves {
		http.Error(w, "bad leaf", http.StatusBadRequest)
		return
	}
	entries := []string{}
	if err := h.scanReplicas(r.Context(), q.Get("bucket"), q.Get("source"), func(id string) {
		if region.LeafOf(id) == leaf {
			entries = append(entries, id)
		}
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeReplJSON(w, http.StatusOK, map[string]any{"Entries": entries})
}
