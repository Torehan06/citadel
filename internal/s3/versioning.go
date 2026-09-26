package s3

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"

	"citadel/internal/store"
)

// Versioning: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
//
// A bucket is unversioned (never enabled), Enabled or Suspended. Every row in
// s3_objects is one version; is_latest marks the current one, and seq orders
// the versions of a key, newest highest.
//   - Unversioned and Suspended buckets write the version "null", replacing
//     any existing null version.
//   - Enabled buckets give every write a fresh version ID.
//   - A DELETE without a version ID adds a delete marker (Enabled: new ID,
//     Suspended: "null") instead of removing data; in an unversioned bucket it
//     removes the null version.
//   - A DELETE with a version ID removes exactly that version.

const (
	versioningEnabled   = "Enabled"
	versioningSuspended = "Suspended"
	versionIDLen        = 32
)

func newVersionID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]) // 32 chars
}

// validVersionID accepts "null" and IDs in the shape this region issues.
func validVersionID(v string) bool {
	if v == nullVersion {
		return true
	}
	if len(v) != versionIDLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// versionParam returns ?versionId when present ("" when absent).
func versionParam(req *request) (string, error) {
	q := req.r.URL.Query()
	if _, ok := q["versionId"]; !ok {
		return "", nil
	}
	v := q.Get("versionId")
	if v == "" {
		return "", errInvalidArgument("Version id cannot be the empty string")
	}
	if !validVersionID(v) {
		return "", errInvalidArgument("Invalid version id specified")
	}
	return v, nil
}

func errNoSuchVersion(b, k string) *Error {
	return &Error{Status: 404, Code: "NoSuchVersion", Message: "The specified version does not exist.", Bucket: b, Key: k}
}

func (h *Handler) putBucketVersioning(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketVersioning", ""); err != nil {
		return err
	}
	body, err := readSmallBody(req, 64<<10, false)
	if err != nil {
		return err
	}
	var cfg versioningConfiguration
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return errMalformedXML()
	}
	if cfg.Status != versioningEnabled && cfg.Status != versioningSuspended {
		return errMalformedXML()
	}
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx, `UPDATE s3_buckets SET versioning = ?, hlc = ? WHERE name = ?`,
			cfg.Status, int64(tx.HLC()), req.bucket); err != nil {
			return err
		}
		return tx.Change("s3", "PutBucketVersioning", req.bucket, map[string]string{"status": cfg.Status})
	})
	if err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

// bucketVersioningTx reads the bucket's versioning state inside a write
// transaction, failing with NoSuchBucket if it has gone.
func bucketVersioningTx(req *request, tx *store.Tx) (string, error) {
	var v string
	err := tx.QueryRowContext(req.ctx, `SELECT versioning FROM s3_buckets WHERE name = ?`, req.bucket).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNoSuchBucket(req.bucket)
	}
	return v, err
}

// nextSeq orders a new version after every existing version of the key.
const nextSeq = `MAX(?, COALESCE((SELECT MAX(seq) FROM s3_objects WHERE bucket = ? AND key = ?), 0) + 1)`

// insertVersionTx makes row the latest version of its key. With a "null"
// version ID it replaces any existing null version.
func insertVersionTx(req *request, tx *store.Tx, o objectRow, deleteMarker bool) error {
	metaJSON, _ := json.Marshal(o.Meta)
	partsJSON := ""
	if len(o.Parts) > 0 {
		b, _ := json.Marshal(o.Parts)
		partsJSON = string(b)
	}
	if _, err := tx.ExecContext(req.ctx, `UPDATE s3_objects SET is_latest = 0 WHERE bucket = ? AND key = ? AND is_latest = 1`,
		req.bucket, o.Key); err != nil {
		return err
	}
	owner := o.Owner
	if owner == "" {
		owner = req.account()
	}
	aclJSON := ""
	if o.ACL != nil {
		aclJSON = o.ACL.json()
	}
	_, err := tx.ExecContext(req.ctx, `
		INSERT INTO s3_objects(bucket, key, version_id, seq, is_latest, delete_marker, size, etag, blob, parts_json, last_modified, owner, meta_json, acl, tagging, hlc)
		VALUES (?, ?, ?, `+nextSeq+`, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket, key, version_id) DO UPDATE SET
			seq=excluded.seq, is_latest=1, delete_marker=excluded.delete_marker, size=excluded.size, etag=excluded.etag,
			blob=excluded.blob, parts_json=excluded.parts_json, last_modified=excluded.last_modified, owner=excluded.owner,
			meta_json=excluded.meta_json, acl=excluded.acl, tagging=excluded.tagging, hlc=excluded.hlc`,
		req.bucket, o.Key, o.VersionID, int64(tx.HLC()), req.bucket, o.Key, boolInt(deleteMarker), o.Size, o.ETag, o.Blob,
		partsJSON, tx.HLC().WallMs(), owner, string(metaJSON), aclJSON, tagsJSON(o.Tags), int64(tx.HLC()))
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// writeObjectTx records o as the new current version of its key, following
// the bucket's versioning state, and returns the version ID it got. The
// caller has already committed the blob(s) o points to.
func writeObjectTx(req *request, tx *store.Tx, o objectRow) (string, error) {
	state, err := bucketVersioningTx(req, tx)
	if err != nil {
		return "", err
	}
	if err := checkWriteConditions(req, tx, o.Key); err != nil {
		return "", err
	}
	o.VersionID = nullVersion
	if state == versioningEnabled {
		o.VersionID = newVersionID()
	}
	if err := insertVersionTx(req, tx, o, false); err != nil {
		return "", err
	}
	payload := eventMeta(req)
	for k, val := range map[string]any{
		"version": o.VersionID, "blob": o.Blob, "parts": len(o.Parts), "size": o.Size, "etag": o.ETag, "event": createEvent(req),
	} {
		payload[k] = val
	}
	return o.VersionID, tx.Change("s3", "PutObject", req.bucket+"/"+o.Key, payload)
}

// writeObject is writeObjectTx in its own transaction.
func (h *Handler) writeObject(req *request, o objectRow) (vid string, err error) {
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		vid, err = writeObjectTx(req, tx, o)
		return err
	})
	return vid, err
}

// deleteOutcome is what a delete did, for the response headers.
type deleteOutcome struct {
	VersionID    string // version removed or delete marker created ("" when nothing versioned happened)
	DeleteMarker bool   // a delete marker was created or removed
}

// deleteObjectTx deletes key (or one version of it) as S3 does.
func deleteObjectTx(req *request, tx *store.Tx, key, versionID string) (deleteOutcome, error) {
	state, err := bucketVersioningTx(req, tx)
	if err != nil {
		return deleteOutcome{}, err
	}
	resource := req.bucket + "/" + key
	if versionID != "" {
		var marker, latest int
		err := tx.QueryRowContext(req.ctx, `SELECT delete_marker, is_latest FROM s3_objects WHERE bucket = ? AND key = ? AND version_id = ?`,
			req.bucket, key, versionID).Scan(&marker, &latest)
		if errors.Is(err, sql.ErrNoRows) {
			return deleteOutcome{VersionID: versionID}, nil // deleting a missing version succeeds
		}
		if err != nil {
			return deleteOutcome{}, err
		}
		if _, err := tx.ExecContext(req.ctx, `DELETE FROM s3_objects WHERE bucket = ? AND key = ? AND version_id = ?`,
			req.bucket, key, versionID); err != nil {
			return deleteOutcome{}, err
		}
		if latest == 1 {
			// The next newest version (if any) becomes current.
			if _, err := tx.ExecContext(req.ctx, `
				UPDATE s3_objects SET is_latest = 1 WHERE rowid = (
					SELECT rowid FROM s3_objects WHERE bucket = ? AND key = ? ORDER BY seq DESC LIMIT 1)`,
				req.bucket, key); err != nil {
				return deleteOutcome{}, err
			}
		}
		return deleteOutcome{VersionID: versionID, DeleteMarker: marker == 1},
			tx.Change("s3", "DeleteObjectVersion", resource, withMeta(req, map[string]any{"version": versionID, "marker": marker == 1}))
	}

	if state == "" {
		res, err := tx.ExecContext(req.ctx, `DELETE FROM s3_objects WHERE bucket = ? AND key = ? AND version_id = ?`,
			req.bucket, key, nullVersion)
		if err != nil {
			return deleteOutcome{}, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return deleteOutcome{}, tx.Change("s3", "DeleteObject", resource, withMeta(req, map[string]any{"version": nullVersion}))
		}
		return deleteOutcome{}, nil
	}
	vid := nullVersion
	if state == versioningEnabled {
		vid = newVersionID()
	}
	m := objectRow{Key: key, VersionID: vid, Meta: objectMeta{}}
	if err := insertVersionTx(req, tx, m, true); err != nil {
		return deleteOutcome{}, err
	}
	return deleteOutcome{VersionID: vid, DeleteMarker: true},
		tx.Change("s3", "PutDeleteMarker", resource, withMeta(req, map[string]any{"version": vid}))
}

func (h *Handler) deleteObject(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	vid, err := versionParam(req)
	if err != nil {
		return err
	}
	action := "s3:DeleteObject"
	if vid != "" {
		action = "s3:DeleteObjectVersion"
	}
	if err := h.authorizeWrite(req, b, req.key, action); err != nil {
		return err
	}
	var out deleteOutcome
	if err := h.st.Update(req.ctx, func(tx *store.Tx) error {
		out, err = deleteObjectTx(req, tx, req.key, vid)
		return err
	}); err != nil {
		return err
	}
	if out.VersionID != "" {
		req.w.Header().Set("x-amz-version-id", out.VersionID)
	}
	if out.DeleteMarker {
		req.w.Header().Set("x-amz-delete-marker", "true")
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- ListObjectVersions --------------------------------------------------

type versionRow struct {
	objectRow
	IsLatest     bool
	DeleteMarker bool
	Seq          int64
}

type versionPage struct {
	Rows      []versionRow
	Prefixes  []string
	Truncated bool
	NextKey   string
	NextVID   string // only when the page ended on a version, not a prefix
}

// scanVersions lists every version and delete marker in (key asc, newest
// first) order, starting after (keyMarker, versionIDMarker).
func (h *Handler) scanVersions(ctx context.Context, bucket, prefix, delimiter, keyMarker, vidMarker string, maxKeys int) (*versionPage, error) {
	page := &versionPage{}
	if maxKeys == 0 {
		return page, nil
	}
	// Cursor: rows strictly after (curKey, curSeq) in listing order.
	curKey, curSeq := keyMarker, int64(-1)
	if keyMarker != "" && vidMarker != "" {
		err := h.st.DB().QueryRowContext(ctx, `SELECT seq FROM s3_objects WHERE bucket = ? AND key = ? AND version_id = ?`,
			bucket, keyMarker, vidMarker).Scan(&curSeq)
		if errors.Is(err, sql.ErrNoRows) {
			curSeq = -1 // unknown version: continue with the next key
		} else if err != nil {
			return nil, err
		}
	}
	from, upper := prefix, successor(prefix)
	const batch = 500
	count, lastPrefix := 0, ""
	for {
		q := `SELECT key, version_id, seq, is_latest, delete_marker, size, etag, last_modified, owner, meta_json FROM s3_objects
			WHERE bucket = ? AND key >= ? AND (key > ? OR (key = ? AND seq < ?))`
		args := []any{bucket, from, curKey, curKey, curSeq}
		if upper != "" {
			q += ` AND key < ?`
			args = append(args, upper)
		}
		q += ` ORDER BY key, seq DESC LIMIT ?`
		args = append(args, batch)
		rows, err := h.st.DB().QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		var got []versionRow
		for rows.Next() {
			var v versionRow
			var lm int64
			var latest, marker int
			var meta string
			if err := rows.Scan(&v.Key, &v.VersionID, &v.Seq, &latest, &marker, &v.Size, &v.ETag, &lm, &v.Owner, &meta); err != nil {
				rows.Close()
				return nil, err
			}
			v.IsLatest, v.DeleteMarker, v.LastModified = latest == 1, marker == 1, msTime(lm)
			if err := json.Unmarshal([]byte(meta), &v.Meta); err != nil {
				rows.Close()
				return nil, err
			}
			got = append(got, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, v := range got {
			curKey, curSeq = v.Key, v.Seq
			if delimiter != "" {
				if i := strings.Index(v.Key[len(prefix):], delimiter); i >= 0 {
					cp := v.Key[:len(prefix)+i+len(delimiter)]
					if cp == lastPrefix || cp <= keyMarker {
						continue
					}
					if count == maxKeys {
						page.Truncated = true
						return page, nil
					}
					page.Prefixes = append(page.Prefixes, cp)
					page.NextKey, page.NextVID, lastPrefix = cp, "", cp
					count++
					continue
				}
			}
			if count == maxKeys {
				page.Truncated = true
				return page, nil
			}
			page.Rows = append(page.Rows, v)
			page.NextKey, page.NextVID = v.Key, v.VersionID
			count++
		}
		if len(got) < batch {
			return page, nil
		}
	}
}

type listVersionsResult struct {
	XMLName             xml.Name           `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
	Name                string             `xml:"Name"`
	Prefix              string             `xml:"Prefix"`
	KeyMarker           string             `xml:"KeyMarker"`
	VersionIDMarker     string             `xml:"VersionIdMarker"`
	NextKeyMarker       string             `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string             `xml:"NextVersionIdMarker,omitempty"`
	MaxKeys             int                `xml:"MaxKeys"`
	Delimiter           string             `xml:"Delimiter,omitempty"`
	IsTruncated         bool               `xml:"IsTruncated"`
	Versions            []versionEntry     `xml:"Version"`
	DeleteMarkers       []deleteMarkerItem `xml:"DeleteMarker"`
	CommonPrefixes      []commonPrefix     `xml:"CommonPrefixes"`
	EncodingType        string             `xml:"EncodingType,omitempty"`
}

type versionEntry struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	Owner        *owner `xml:"Owner"`
}

type deleteMarkerItem struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	Owner        *owner `xml:"Owner"`
}

func (h *Handler) listObjectVersions(req *request) error {
	if _, err := h.bucketAccess(req, "s3:ListBucketVersions", permRead); err != nil {
		return err
	}
	q := req.r.URL.Query()
	p, err := parseListParams(q)
	if err != nil {
		return err
	}
	keyMarker, vidMarker := q.Get("key-marker"), q.Get("version-id-marker")
	if vidMarker != "" && keyMarker == "" {
		return errInvalidArgument("A version-id marker cannot be specified without a key marker.")
	}
	page, err := h.scanVersions(req.ctx, req.bucket, p.prefix, p.delimiter, keyMarker, vidMarker, p.maxKeys)
	if err != nil {
		return err
	}
	res := listVersionsResult{
		Name: req.bucket, Prefix: p.enc(p.prefix), KeyMarker: p.enc(keyMarker), VersionIDMarker: vidMarker,
		MaxKeys: p.maxKeys, Delimiter: p.enc(p.delimiter), IsTruncated: page.Truncated,
	}
	if p.urlEncode {
		res.EncodingType = "url"
	}
	if page.Truncated {
		res.NextKeyMarker, res.NextVersionIDMarker = p.enc(page.NextKey), page.NextVID
	}
	ow := &owners{h: h, ctx: req.ctx}
	for _, v := range page.Rows {
		if v.DeleteMarker {
			res.DeleteMarkers = append(res.DeleteMarkers, deleteMarkerItem{
				Key: p.enc(v.Key), VersionID: v.VersionID, IsLatest: v.IsLatest,
				LastModified: isoTime(v.LastModified), Owner: ow.get(v.Owner),
			})
			continue
		}
		res.Versions = append(res.Versions, versionEntry{
			Key: p.enc(v.Key), VersionID: v.VersionID, IsLatest: v.IsLatest, LastModified: isoTime(v.LastModified),
			ETag: v.ETag, Size: v.Size, StorageClass: storageClass(v.objectRow), Owner: ow.get(v.Owner),
		})
	}
	for _, c := range page.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefix{Prefix: p.enc(c)})
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}
