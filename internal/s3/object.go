package s3

import (
	"bytes"
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"citadel/internal/sigv4"
	"citadel/internal/store"
)

var errNoRows = sql.ErrNoRows

func msTime(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

const (
	maxObjectSize   = 5 << 30 // single PUT limit
	maxKeyLength    = 1024
	maxUserMetaSize = 2 << 10
	nullVersion     = "null"
)

// objectMeta is stored as meta_json: the headers S3 echoes back on GET/HEAD.
type objectMeta struct {
	Headers      map[string]string `json:"headers,omitempty"` // canonical header name -> value
	User         map[string]string `json:"user,omitempty"`    // x-amz-meta-* (lowercase suffix)
	ChecksumAlgo string            `json:"checksum_algo,omitempty"`
	Checksum     string            `json:"checksum,omitempty"`      // base64
	ChecksumType string            `json:"checksum_type,omitempty"` // FULL_OBJECT or COMPOSITE
	StorageClass string            `json:"storage_class,omitempty"`
}

// storedHeaders are the standard headers PutObject records and GetObject returns.
var storedHeaders = []string{"Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Type", "Expires"}

type objectRow struct {
	Key          string
	VersionID    string
	Size         int64
	ETag         string
	Blob         string
	Parts        []partRef // multipart objects: the part blobs, in order
	LastModified time.Time
	Owner        string // account ID
	Meta         objectMeta
	ACL          *acl
	Tags         []tag
}

// loadObject returns the current version of req.key, or the given version.
// A delete marker answers like S3: 404 NoSuchKey when it is the current
// version, 405 MethodNotAllowed when addressed by version ID, both with
// x-amz-delete-marker set.
func (h *Handler) loadObject(req *request, versionID string) (*objectRow, error) {
	const cols = `SELECT o.key, o.version_id, o.delete_marker, o.size, o.etag, o.blob, o.parts_json, o.last_modified, o.owner,
		o.meta_json, o.acl, o.tagging, COALESCE(a.canonical_id, o.owner)
		FROM s3_objects o LEFT JOIN accounts a ON a.id = o.owner`
	q := cols + ` WHERE o.bucket = ? AND o.key = ? AND o.is_latest = 1`
	args := []any{req.bucket, req.key}
	if versionID != "" {
		q = cols + ` WHERE o.bucket = ? AND o.key = ? AND o.version_id = ?`
		args = append(args, versionID)
	}
	var o objectRow
	var lm int64
	var marker int
	var meta, parts, aclJSON, tagJSON, ownerCanonical string
	err := h.st.DB().QueryRowContext(req.ctx, q, args...).
		Scan(&o.Key, &o.VersionID, &marker, &o.Size, &o.ETag, &o.Blob, &parts, &lm, &o.Owner, &meta, &aclJSON, &tagJSON, &ownerCanonical)
	if errors.Is(err, sql.ErrNoRows) {
		if versionID != "" {
			return nil, errNoSuchVersion(req.bucket, req.key)
		}
		return nil, errNoSuchKey(req.bucket, req.key)
	}
	if err != nil {
		return nil, err
	}
	if marker == 1 {
		hdr := http.Header{"X-Amz-Delete-Marker": {"true"}, "X-Amz-Version-Id": {o.VersionID}}
		if versionID != "" {
			return nil, &Error{Status: 405, Code: "MethodNotAllowed", Message: "The specified method is not allowed against this resource.",
				Bucket: req.bucket, Key: req.key, Header: hdr}
		}
		e := errNoSuchKey(req.bucket, req.key)
		e.Header = hdr
		return nil, e
	}
	o.LastModified = msTime(lm)
	o.ACL = parseStoredACL(aclJSON, ownerCanonical)
	o.Tags = parseStoredTags(tagJSON)
	if err := json.Unmarshal([]byte(meta), &o.Meta); err != nil {
		return nil, err
	}
	if parts != "" {
		if err := json.Unmarshal([]byte(parts), &o.Parts); err != nil {
			return nil, err
		}
	}
	return &o, nil
}

// ingested is a request body that has been streamed to a pending blob and
// had every digest the client sent checked.
type ingested struct {
	pending  *store.Pending
	algo     string // checksum algorithm computed ("" if none)
	checksum string // base64 value of algo over the body
	echo     bool   // client asked for the checksum: echo it in the response
}

// ingest streams the request body into the blob store, enforcing the length
// rules and verifying Content-MD5 and any flexible checksum. defaultAlgo is
// computed when the client names none ("" for no default). The caller must
// Commit or Abort the pending blob.
func (h *Handler) ingest(req *request, defaultAlgo string) (*ingested, error) {
	r := req.r
	size := r.ContentLength
	if req.auth.Streaming {
		size = req.auth.DecodedLength
	}
	// HTTP/1.1 chunked transfer encoding carries no length up front; the
	// body is then read to EOF, capped at the single-PUT limit.
	chunkedTE := size < 0 && len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked"
	if size < 0 && !chunkedTE {
		return nil, errf(411, "MissingContentLength", "You must provide the Content-Length HTTP header.")
	}
	if size > maxObjectSize {
		return nil, errf(400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
	}

	var wantMD5 []byte
	if s, ok := r.Header["Content-Md5"]; ok {
		raw, err := base64.StdEncoding.DecodeString(strings.Join(s, ""))
		if err != nil || len(raw) != md5.Size {
			return nil, errf(400, "InvalidDigest", "The Content-MD5 you specified was invalid.")
		}
		wantMD5 = raw
	}
	rc, cerr := parseRequestedChecksum(r)
	if cerr != nil {
		return nil, cerr
	}
	algo := rc.Algo
	if algo == "" {
		algo = defaultAlgo
	}
	var extra []hash.Hash
	sum := newChecksum(algo)
	if sum != nil {
		extra = append(extra, sum)
	}

	body := io.Reader(http.NoBody)
	if r.Body != nil {
		body = r.Body
	}
	src := io.Reader(&exactReader{r: body, remaining: size})
	if chunkedTE {
		src = http.MaxBytesReader(req.w, r.Body, maxObjectSize)
	}
	pending, err := h.st.Blobs.Write(src, extra...)
	if err != nil {
		return nil, bodyError(err)
	}
	fail := func(e error) (*ingested, error) {
		pending.Abort()
		return nil, e
	}
	if wantMD5 != nil && !bytes.Equal(wantMD5, pending.MD5) {
		return fail(errf(400, "BadDigest", "The Content-MD5 you specified did not match what we received."))
	}
	in := &ingested{pending: pending, algo: algo, echo: rc.Algo != ""}
	if sum != nil {
		in.checksum = encodeChecksum(sum)
	}
	want := rc.Value
	if rc.Trailer {
		want = r.Trailer.Get(checksumHeader(rc.Algo))
		if want == "" {
			return fail(errf(400, "InvalidRequest", "x-amz-trailer header was specified but no trailer was received"))
		}
	}
	if want != "" && want != in.checksum {
		return fail(checksumMismatch(rc.Algo))
	}
	return in, nil
}

func (h *Handler) putObject(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	if err := h.authorizeWrite(req, b, req.key, "s3:PutObject"); err != nil {
		return err
	}
	if len(req.key) > maxKeyLength {
		return errf(400, "KeyTooLongError", "Your key is too long")
	}
	meta, merr := metaFromRequest(req.r)
	if merr != nil {
		return merr
	}
	owner, objACL, err := h.newObjectOwnership(req, b)
	if err != nil {
		return err
	}
	tags, err := tagsFromHeader(req.r)
	if err != nil {
		return err
	}
	in, err := h.ingest(req, "CRC64NVME") // S3's default integrity checksum
	if err != nil {
		return err
	}
	defer in.pending.Abort()
	meta.ChecksumAlgo, meta.Checksum, meta.ChecksumType = in.algo, in.checksum, "FULL_OBJECT"
	if err := in.pending.Commit(); err != nil {
		return err
	}
	etag := `"` + hex.EncodeToString(in.pending.MD5) + `"`
	vid, err := h.writeObject(req, objectRow{
		Key: req.key, Size: in.pending.Size, ETag: etag, Blob: in.pending.SHA256, Meta: meta,
		Owner: owner, ACL: objACL, Tags: tags,
	})
	if err != nil {
		return err
	}
	if b.Versioning == versioningEnabled {
		req.w.Header().Set("x-amz-version-id", vid)
	}
	req.w.Header().Set("ETag", etag)
	if in.echo {
		req.w.Header().Set(checksumHeader(in.algo), in.checksum)
		req.w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

// metaFromRequest collects the headers S3 stores with an object.
func metaFromRequest(r *http.Request) (objectMeta, *Error) {
	m := objectMeta{Headers: map[string]string{}, User: map[string]string{}}
	for _, name := range storedHeaders {
		if v, ok := r.Header[name]; ok {
			m.Headers[name] = strings.Join(v, ",")
		}
	}
	// aws-chunked is a transfer detail, not part of the object's encoding.
	if ce, ok := m.Headers["Content-Encoding"]; ok && strings.Contains(strings.ToLower(ce), "aws-chunked") {
		var keep []string
		for _, p := range strings.Split(ce, ",") {
			if p = strings.TrimSpace(p); p != "" && !strings.EqualFold(p, "aws-chunked") {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			delete(m.Headers, "Content-Encoding")
		} else {
			m.Headers["Content-Encoding"] = strings.Join(keep, ", ")
		}
	}
	total := 0
	for name, vals := range r.Header {
		lower := strings.ToLower(name)
		if suffix, ok := strings.CutPrefix(lower, "x-amz-meta-"); ok {
			v := strings.Join(vals, ",")
			m.User[suffix] = v
			total += len(suffix) + len(v)
		}
	}
	if total > maxUserMetaSize {
		return m, errf(400, "MetadataTooLarge", "Your metadata headers exceed the maximum allowed metadata size.")
	}
	if sc := r.Header.Get("X-Amz-Storage-Class"); sc != "" && sc != "STANDARD" {
		m.StorageClass = sc
	}
	return m, nil
}

// exactReader delivers exactly the declared Content-Length: fewer bytes is an
// IncompleteBody error, not a short object.
type exactReader struct {
	r         io.Reader
	remaining int64
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.remaining <= 0 {
		// Read on to EOF so checks that run there (payload hash, aws-chunked
		// trailers) still happen.
		var one [1]byte
		for {
			n, err := e.r.Read(one[:])
			if n > 0 {
				return 0, errf(400, "IncompleteBody", "The request body is longer than Content-Length")
			}
			if err != nil {
				return 0, err
			}
		}
	}
	if int64(len(p)) > e.remaining {
		p = p[:e.remaining]
	}
	n, err := e.r.Read(p)
	e.remaining -= int64(n)
	if err == io.EOF {
		if e.remaining > 0 {
			return n, errf(400, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.")
		}
		return n, nil
	}
	return n, err
}

// bodyError maps a failure while reading the request body to an S3 error.
func bodyError(err error) error {
	var e *Error
	var se *sigv4.Error
	if errors.As(err, &e) || errors.As(err, &se) {
		return err
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return errf(400, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.")
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return errf(400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
	}
	return errf(400, "IncompleteBody", "The request body terminated unexpectedly")
}

// ---- GET / HEAD ----------------------------------------------------------

// responseOverrides are the query parameters that override response headers
// on GetObject; only signed requests may use them.
var responseOverrides = map[string]string{
	"response-cache-control":       "Cache-Control",
	"response-content-disposition": "Content-Disposition",
	"response-content-encoding":    "Content-Encoding",
	"response-content-language":    "Content-Language",
	"response-content-type":        "Content-Type",
	"response-expires":             "Expires",
}

func (h *Handler) getObject(req *request, head bool) error {
	b, o, err := h.objectForRead(req, "s3:GetObject", permRead)
	if err != nil {
		return err
	}
	vid, _ := versionParam(req)
	r, w := req.r, req.w
	q := r.URL.Query()
	if _, ok := q["partNumber"]; ok {
		return errNotImplemented("GetObject partNumber")
	}

	// Conditional requests (RFC 7232 as S3 applies it).
	if status := evalConditions(r, o); status != 0 {
		setETagAndModified(w, o)
		if status == http.StatusPreconditionFailed {
			return errf(412, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
		}
		w.WriteHeader(status)
		return nil
	}

	start, length, partial, rerr := parseRange(r.Header.Get("Range"), o.Size)
	if rerr != nil {
		return rerr
	}

	hdr := w.Header()
	setETagAndModified(w, o)
	hdr.Set("Accept-Ranges", "bytes")
	hdr.Set("Content-Type", "binary/octet-stream")
	for k, v := range o.Meta.Headers {
		hdr.Set(k, v)
	}
	for k, v := range o.Meta.User {
		hdr["x-amz-meta-"+k] = []string{v}
	}
	if o.Meta.StorageClass != "" {
		hdr.Set("x-amz-storage-class", o.Meta.StorageClass)
	}
	if len(o.Tags) > 0 {
		hdr.Set("x-amz-tagging-count", strconv.Itoa(len(o.Tags)))
	}
	for param, header := range responseOverrides {
		if v, ok := q[param]; ok {
			if req.who == nil {
				return errf(400, "InvalidRequest", "Request specific response headers cannot be used for anonymous GET requests.")
			}
			hdr.Set(header, strings.Join(v, ","))
		}
	}
	if vid != "" || b.Versioning != "" {
		hdr.Set("x-amz-version-id", o.VersionID)
	}
	if strings.EqualFold(r.Header.Get("X-Amz-Checksum-Mode"), "ENABLED") && !partial && o.Meta.ChecksumAlgo != "" {
		hdr.Set(checksumHeader(o.Meta.ChecksumAlgo), o.Meta.Checksum)
		ct := o.Meta.ChecksumType
		if ct == "" {
			ct = "FULL_OBJECT"
		}
		hdr.Set("x-amz-checksum-type", ct)
	}
	hdr.Set("Content-Length", strconv.FormatInt(length, 10))
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		hdr.Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(start+length-1, 10)+"/"+strconv.FormatInt(o.Size, 10))
	}

	if head || length == 0 {
		w.WriteHeader(status)
		return nil
	}
	body, err := h.openRange(o, start, length)
	if err != nil {
		return err
	}
	defer body.Close()
	w.WriteHeader(status)
	_, _ = io.Copy(w, body)
	return nil
}

func setETagAndModified(w http.ResponseWriter, o *objectRow) {
	w.Header().Set("ETag", o.ETag)
	w.Header().Set("Last-Modified", o.LastModified.Format(http.TimeFormat))
}

// evalConditions returns 0 to proceed, 304 or 412.
func evalConditions(r *http.Request, o *objectRow) int {
	ifMatch := r.Header.Get("If-Match")
	ifNoneMatch := r.Header.Get("If-None-Match")
	// Last-Modified has second precision on the wire.
	lm := o.LastModified.Truncate(time.Second)

	if ifMatch != "" {
		if !etagMatches(ifMatch, o.ETag) {
			return http.StatusPreconditionFailed
		}
	} else if s := r.Header.Get("If-Unmodified-Since"); s != "" {
		if t, err := http.ParseTime(s); err == nil && lm.After(t) {
			return http.StatusPreconditionFailed
		}
	}
	if ifNoneMatch != "" {
		if etagMatches(ifNoneMatch, o.ETag) {
			return http.StatusNotModified
		}
	} else if s := r.Header.Get("If-Modified-Since"); s != "" {
		if t, err := http.ParseTime(s); err == nil && !lm.After(t) {
			return http.StatusNotModified
		}
	}
	return 0
}

func etagMatches(header, etag string) bool {
	for _, c := range strings.Split(header, ",") {
		c = strings.TrimSpace(c)
		if c == "*" || strings.Trim(c, `"`) == strings.Trim(etag, `"`) {
			return true
		}
	}
	return false
}

// parseRange handles a single "bytes=" range. Anything S3 would ignore
// (other units, several ranges, syntax errors) yields the whole object.
func parseRange(h string, size int64) (start, length int64, partial bool, err error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(h), "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return 0, size, false, nil
	}
	a, b, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return 0, size, false, nil
	}
	unsatisfiable := func() error {
		return &Error{Status: 416, Code: "InvalidRange", Message: "The requested range is not satisfiable",
			Header: http.Header{"Content-Range": {"bytes */" + strconv.FormatInt(size, 10)}}}
	}
	if a == "" { // suffix: last N bytes
		n, perr := strconv.ParseInt(b, 10, 64)
		if perr != nil || n < 0 {
			return 0, size, false, nil
		}
		if n == 0 || size == 0 {
			return 0, 0, false, unsatisfiable()
		}
		n = min(n, size)
		return size - n, n, true, nil
	}
	first, perr := strconv.ParseInt(a, 10, 64)
	if perr != nil || first < 0 {
		return 0, size, false, nil
	}
	last := size - 1
	if b != "" {
		l, perr := strconv.ParseInt(b, 10, 64)
		if perr != nil || l < first {
			return 0, size, false, nil
		}
		last = min(l, size-1)
	}
	if first >= size {
		return 0, 0, false, unsatisfiable()
	}
	return first, last - first + 1, true, nil
}

// readSmallBody reads a small XML request body (DeleteObjects and friends),
// verifying Content-MD5 or a flexible checksum when present. S3 requires one
// of them for DeleteObjects.
func readSmallBody(req *request, limit int64, requireIntegrity bool) ([]byte, error) {
	r := req.r
	rc, cerr := parseRequestedChecksum(r)
	if cerr != nil {
		return nil, cerr
	}
	md5s, hasMD5 := r.Header["Content-Md5"]
	if requireIntegrity && !hasMD5 && rc.Algo == "" {
		return nil, errf(400, "InvalidRequest", "Missing required header for this request: Content-MD5")
	}
	var sum hash.Hash
	if rc.Algo != "" {
		sum = newChecksum(rc.Algo)
	}
	var buf bytes.Buffer
	src := io.Reader(http.NoBody)
	if r.Body != nil {
		src = r.Body
	}
	if _, err := io.Copy(&buf, io.LimitReader(src, limit+1)); err != nil {
		return nil, bodyError(err)
	}
	if int64(buf.Len()) > limit {
		return nil, errf(400, "MaxMessageLengthExceeded", "Your request was too big.")
	}
	body := buf.Bytes()
	if hasMD5 {
		raw, err := base64.StdEncoding.DecodeString(strings.Join(md5s, ""))
		if err != nil || len(raw) != md5.Size {
			return nil, errf(400, "InvalidDigest", "The Content-MD5 you specified was invalid.")
		}
		if got := md5.Sum(body); !bytes.Equal(raw, got[:]) {
			return nil, errf(400, "BadDigest", "The Content-MD5 you specified did not match what we received.")
		}
	}
	if sum != nil {
		sum.Write(body)
		want := rc.Value
		if rc.Trailer {
			want = r.Trailer.Get(checksumHeader(rc.Algo))
		}
		if want != "" && want != encodeChecksum(sum) {
			return nil, checksumMismatch(rc.Algo)
		}
	}
	return body, nil
}

// newObjectOwnership decides who owns an object being written and its ACL,
// following the bucket's object ownership setting and public access block.
func (h *Handler) newObjectOwnership(req *request, b *bucketInfo) (ownerAcct string, a *acl, err error) {
	ownerAcct, ownerCanon := req.account(), req.canonical()
	canned := req.r.Header.Get("X-Amz-Acl")
	switch {
	case b.Ownership == ownershipOwnerEnforced,
		b.Ownership == ownershipOwnerPreferred && canned == cannedBucketOwnerFullCtl:
		ownerAcct, ownerCanon = b.Account, b.OwnerCanonical
	}
	a, err = h.aclFromRequest(req.ctx, req.r, ownerCanon, b.OwnerCanonical)
	if err != nil {
		return "", nil, err
	}
	if a == nil {
		return ownerAcct, nil, nil // default: private to the owner
	}
	if b.Ownership == ownershipOwnerEnforced && !a.onlyOwner() {
		return "", nil, errACLNotSupported()
	}
	if a.isPublic() && b.PAB.BlockPublicAcls {
		return "", nil, errAccessDenied()
	}
	return ownerAcct, a, nil
}
