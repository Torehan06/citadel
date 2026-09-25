package s3

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"citadel/internal/store"
)

// listPage is one page of a listing: objects and common prefixes interleaved
// in key order, as S3 counts them against max-keys.
type listPage struct {
	Objects   []objectRow
	Prefixes  []string
	Truncated bool
	Next      string // last key or common prefix returned (the next marker)
}

// successor returns the smallest string greater than every string with
// prefix p, or "" when there is none (p is empty or all 0xff).
func successor(p string) string {
	b := []byte(p)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return ""
}

// scan lists the latest, non-deleted objects of bucket after marker.
// With a delimiter, keys that contain it past the prefix roll up into common
// prefixes; a common prefix at or before the marker has already been
// returned on an earlier page and is skipped.
func (h *Handler) scan(ctx context.Context, bucket, prefix, delimiter, marker string, maxKeys int) (*listPage, error) {
	page := &listPage{}
	if maxKeys == 0 {
		return page, nil // S3 answers an empty, untruncated page
	}
	from := prefix // inclusive lower bound
	after := marker
	upper := successor(prefix)
	const batch = 500
	count := 0
	lastPrefix := ""
	for {
		q := `SELECT key, version_id, size, etag, last_modified, owner, meta_json FROM s3_objects
			WHERE bucket = ? AND is_latest = 1 AND delete_marker = 0 AND key >= ? AND key > ?`
		args := []any{bucket, from, after}
		if upper != "" {
			q += ` AND key < ?`
			args = append(args, upper)
		}
		q += ` ORDER BY key LIMIT ?`
		args = append(args, batch)
		rows, err := h.st.DB().QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		n := 0
		var rowsOut []objectRow
		for rows.Next() {
			var o objectRow
			var lm int64
			var meta string
			if err := rows.Scan(&o.Key, &o.VersionID, &o.Size, &o.ETag, &lm, &o.Owner, &meta); err != nil {
				rows.Close()
				return nil, err
			}
			o.LastModified = msTime(lm)
			if err := json.Unmarshal([]byte(meta), &o.Meta); err != nil {
				rows.Close()
				return nil, err
			}
			rowsOut = append(rowsOut, o)
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, o := range rowsOut {
			after = o.Key
			if delimiter != "" {
				if i := strings.Index(o.Key[len(prefix):], delimiter); i >= 0 {
					cp := o.Key[:len(prefix)+i+len(delimiter)]
					if cp == lastPrefix || cp <= marker {
						if s := successor(cp); s != "" && s > from {
							from = s
						}
						continue
					}
					if count == maxKeys {
						page.Truncated = true
						return page, nil
					}
					page.Prefixes = append(page.Prefixes, cp)
					page.Next, lastPrefix = cp, cp
					count++
					if s := successor(cp); s != "" && s > from {
						from = s // skip the rest of this group without reading it
					}
					continue
				}
			}
			if count == maxKeys {
				page.Truncated = true
				return page, nil
			}
			page.Objects = append(page.Objects, o)
			page.Next = o.Key
			count++
		}
		if n < batch {
			return page, nil
		}
	}
}

func storageClass(o objectRow) string {
	if o.Meta.StorageClass != "" {
		return o.Meta.StorageClass
	}
	return "STANDARD"
}

// listParams are the parameters shared by all three list operations.
type listParams struct {
	prefix, delimiter string
	maxKeys           int
	urlEncode         bool
}

func parseListParams(q url.Values) (listParams, error) {
	p := listParams{prefix: q.Get("prefix"), delimiter: q.Get("delimiter"), maxKeys: 1000}
	if s, ok := q["max-keys"]; ok {
		n, err := strconv.Atoi(strings.Join(s, ""))
		if err != nil || n < 0 {
			return p, errInvalidArgument("Provided max-keys not an integer or within integer range")
		}
		p.maxKeys = min(n, 1000)
	}
	switch e := q.Get("encoding-type"); e {
	case "":
	case "url":
		p.urlEncode = true
	default:
		return p, errInvalidArgument("Invalid Encoding Method specified in Request")
	}
	return p, nil
}

// enc applies encoding-type=url to a key-like field in a listing response:
// URI encoding with '/' left as is ("quux ab/" -> "quux%20ab/").
func (p listParams) enc(s string) string {
	if !p.urlEncode {
		return s
	}
	const hexdig = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '/' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexdig[c>>4])
		b.WriteByte(hexdig[c&15])
	}
	return b.String()
}

type listEntry struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	Owner        *owner `xml:"Owner,omitempty"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// owners resolves object owner account IDs to Owner elements, cached per request.
type owners struct {
	h     *Handler
	ctx   context.Context
	cache map[string]*owner
}

func (o *owners) get(accountID string) *owner {
	if v, ok := o.cache[accountID]; ok {
		return v
	}
	var ow *owner
	if a, err := o.h.st.AccountByID(o.ctx, accountID); err == nil {
		ow = ownerOf(a)
	} else {
		ow = &owner{ID: accountID}
	}
	if o.cache == nil {
		o.cache = map[string]*owner{}
	}
	o.cache[accountID] = ow
	return ow
}

func (p listParams) entries(page *listPage, ow *owners) ([]listEntry, []commonPrefix) {
	var es []listEntry
	for _, o := range page.Objects {
		e := listEntry{Key: p.enc(o.Key), LastModified: isoTime(o.LastModified), ETag: o.ETag, Size: o.Size, StorageClass: storageClass(o)}
		if ow != nil {
			e.Owner = ow.get(o.Owner)
		}
		es = append(es, e)
	}
	var cps []commonPrefix
	for _, c := range page.Prefixes {
		cps = append(cps, commonPrefix{Prefix: p.enc(c)})
	}
	return es, cps
}

type listBucketResultV1 struct {
	XMLName        xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Marker         string         `xml:"Marker"`
	NextMarker     string         `xml:"NextMarker,omitempty"`
	MaxKeys        int            `xml:"MaxKeys"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	IsTruncated    bool           `xml:"IsTruncated"`
	Contents       []listEntry    `xml:"Contents"`
	CommonPrefixes []commonPrefix `xml:"CommonPrefixes"`
	EncodingType   string         `xml:"EncodingType,omitempty"`
}

func (h *Handler) listObjectsV1(req *request) error {
	if _, err := h.bucketAccess(req, "s3:ListBucket", permRead); err != nil {
		return err
	}
	q := req.r.URL.Query()
	p, err := parseListParams(q)
	if err != nil {
		return err
	}
	marker := q.Get("marker")
	page, err := h.scan(req.ctx, req.bucket, p.prefix, p.delimiter, marker, p.maxKeys)
	if err != nil {
		return err
	}
	res := listBucketResultV1{
		// V1 returns Prefix as sent: SDKs only URL-decode Delimiter, Marker and NextMarker.
		Name: req.bucket, Prefix: p.prefix, Marker: p.enc(marker), MaxKeys: p.maxKeys,
		Delimiter: p.enc(p.delimiter), IsTruncated: page.Truncated,
	}
	if p.urlEncode {
		res.EncodingType = "url"
	}
	// NextMarker is only returned when a delimiter was given; otherwise
	// clients continue from the last key.
	if page.Truncated && p.delimiter != "" {
		res.NextMarker = p.enc(page.Next)
	}
	res.Contents, res.CommonPrefixes = p.entries(page, &owners{h: h, ctx: req.ctx})
	writeXML(req.w, http.StatusOK, res)
	return nil
}

type listBucketResultV2 struct {
	XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	MaxKeys               int            `xml:"MaxKeys"`
	KeyCount              int            `xml:"KeyCount"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	IsTruncated           bool           `xml:"IsTruncated"`
	ContinuationToken     *string        `xml:"ContinuationToken"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	Contents              []listEntry    `xml:"Contents"`
	CommonPrefixes        []commonPrefix `xml:"CommonPrefixes"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
}

func (h *Handler) listObjectsV2(req *request) error {
	if _, err := h.bucketAccess(req, "s3:ListBucket", permRead); err != nil {
		return err
	}
	q := req.r.URL.Query()
	p, err := parseListParams(q)
	if err != nil {
		return err
	}
	startAfter := q.Get("start-after")
	marker := startAfter
	token, hasToken := q["continuation-token"]
	if hasToken && strings.Join(token, "") != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.Join(token, ""))
		if err != nil {
			return errInvalidArgument("The continuation token provided is incorrect")
		}
		marker = string(raw)
	}
	page, err := h.scan(req.ctx, req.bucket, p.prefix, p.delimiter, marker, p.maxKeys)
	if err != nil {
		return err
	}
	res := listBucketResultV2{
		Name: req.bucket, Prefix: p.enc(p.prefix), MaxKeys: p.maxKeys, Delimiter: p.enc(p.delimiter),
		IsTruncated: page.Truncated, StartAfter: p.enc(startAfter),
		KeyCount: len(page.Objects) + len(page.Prefixes),
	}
	if hasToken {
		t := strings.Join(token, "")
		res.ContinuationToken = &t
	}
	if page.Truncated {
		res.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(page.Next))
	}
	if p.urlEncode {
		res.EncodingType = "url"
	}
	var ow *owners
	if q.Get("fetch-owner") == "true" {
		ow = &owners{h: h, ctx: req.ctx}
	}
	res.Contents, res.CommonPrefixes = p.entries(page, ow)
	writeXML(req.w, http.StatusOK, res)
	return nil
}

// ---- DeleteObjects ----------------------------------------------------------

type deleteRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Quiet   bool     `xml:"Quiet"`
	Objects []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	} `xml:"Object"`
}

type deleteResult struct {
	XMLName xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []deletedEntry  `xml:"Deleted"`
	Errors  []deleteErrItem `xml:"Error"`
}

type deletedEntry struct {
	Key                   string `xml:"Key"`
	VersionID             string `xml:"VersionId,omitempty"`
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
}

type deleteErrItem struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
}

const maxDeleteObjects = 1000

func (h *Handler) deleteObjects(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	body, err := readSmallBody(req, 2<<20, true)
	if err != nil {
		return err
	}
	var d deleteRequest
	if err := xml.Unmarshal(body, &d); err != nil || len(d.Objects) == 0 || len(d.Objects) > maxDeleteObjects {
		return errMalformedXML()
	}
	res := deleteResult{}
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		for _, o := range d.Objects {
			if o.VersionID != "" && !validVersionID(o.VersionID) {
				res.Errors = append(res.Errors, deleteErrItem{Key: o.Key, VersionID: o.VersionID,
					Code: "NoSuchVersion", Message: "The specified version does not exist."})
				continue
			}
			action := "s3:DeleteObject"
			if o.VersionID != "" {
				action = "s3:DeleteObjectVersion"
			}
			if h.authorizeWrite(req, b, o.Key, action) != nil {
				res.Errors = append(res.Errors, deleteErrItem{Key: o.Key, VersionID: o.VersionID,
					Code: "AccessDenied", Message: "Access Denied"})
				continue
			}
			out, err := deleteObjectTx(req, tx, o.Key, o.VersionID)
			if err != nil {
				return err
			}
			if !d.Quiet {
				e := deletedEntry{Key: o.Key, VersionID: o.VersionID, DeleteMarker: out.DeleteMarker}
				if out.DeleteMarker {
					e.DeleteMarkerVersionID = out.VersionID
				}
				res.Deleted = append(res.Deleted, e)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}
