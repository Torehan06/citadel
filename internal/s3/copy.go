package s3

import (
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"citadel/internal/store"
)

// CopyObject and UploadPartCopy: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
// A whole-object copy points the new version at the source's blob (or part
// manifest), so no bytes move. A ranged part copy streams the range into a
// new part blob.

type copySource struct {
	Bucket, Key, VersionID string
}

// parseCopySource reads x-amz-copy-source: "[/]bucket/key[?versionId=v]",
// URL-encoded.
func parseCopySource(h string) (copySource, error) {
	var cs copySource
	raw, query, _ := strings.Cut(h, "?")
	p, err := url.PathUnescape(strings.TrimPrefix(raw, "/"))
	if err != nil {
		return cs, errInvalidArgument("Invalid copy source encoding")
	}
	var ok bool
	cs.Bucket, cs.Key, ok = strings.Cut(p, "/")
	if !ok || cs.Bucket == "" || cs.Key == "" {
		return cs, errInvalidArgument("Invalid copy source object key")
	}
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return cs, errInvalidArgument("Invalid copy source")
		}
		if v, ok := q["versionId"]; ok {
			cs.VersionID = strings.Join(v, "")
			if !validVersionID(cs.VersionID) {
				return cs, errInvalidArgument("Invalid version id specified")
			}
		}
	}
	return cs, nil
}

// loadCopySource authorizes and loads the source object and applies the
// x-amz-copy-source-if-* conditions.
func (h *Handler) loadCopySource(req *request) (*copySource, *objectRow, error) {
	cs, err := parseCopySource(req.r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		return nil, nil, err
	}
	src := &request{w: req.w, r: req.r, ctx: req.ctx, auth: req.auth, who: req.who, bucket: cs.Bucket, key: cs.Key, hasKey: true}
	sb, err := h.loadBucket(req.ctx, cs.Bucket)
	if err != nil {
		return nil, nil, err
	}
	o, err := h.loadObject(src, cs.VersionID)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			e.Header = nil // delete-marker headers describe the source, not this response
			if e.Code == "MethodNotAllowed" {
				return nil, nil, errInvalidArgument("The source of a copy request may not specifically refer to a delete marker by version id.")
			}
		}
		return nil, nil, err
	}
	action := "s3:GetObject"
	if cs.VersionID != "" {
		action = "s3:GetObjectVersion"
	}
	if err := h.authorizeObject(src, sb, o, action, permRead); err != nil {
		return nil, nil, err
	}
	if !copyConditionsHold(req.r, o) {
		return nil, nil, errf(412, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
	}
	if sb.Versioning != "" || cs.VersionID != "" {
		req.w.Header().Set("x-amz-copy-source-version-id", o.VersionID)
	}
	return &cs, o, nil
}

func copyConditionsHold(r *http.Request, o *objectRow) bool {
	lm := o.LastModified.Truncate(time.Second)
	if v := r.Header.Get("X-Amz-Copy-Source-If-Match"); v != "" && !etagMatches(v, o.ETag) {
		return false
	}
	if v := r.Header.Get("X-Amz-Copy-Source-If-None-Match"); v != "" && etagMatches(v, o.ETag) {
		return false
	}
	if v := r.Header.Get("X-Amz-Copy-Source-If-Unmodified-Since"); v != "" && r.Header.Get("X-Amz-Copy-Source-If-Match") == "" {
		if t, err := http.ParseTime(v); err == nil && lm.After(t) {
			return false
		}
	}
	if v := r.Header.Get("X-Amz-Copy-Source-If-Modified-Since"); v != "" && r.Header.Get("X-Amz-Copy-Source-If-None-Match") == "" {
		if t, err := http.ParseTime(v); err == nil && !lm.After(t) {
			return false
		}
	}
	return true
}

type copyObjectResult struct {
	XMLName           xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	ETag              string   `xml:"ETag"`
	LastModified      string   `xml:"LastModified"`
	ChecksumCRC32     string   `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string   `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string   `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string   `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string   `xml:"ChecksumSHA256,omitempty"`
}

func (h *Handler) copyObject(req *request) error {
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
	cs, src, err := h.loadCopySource(req)
	if err != nil {
		return err
	}
	if src.Size > maxObjectSize {
		return errf(400, "InvalidRequest", "The specified copy source is larger than the maximum allowable size for a copy source: 5368709120")
	}
	r := req.r
	metaDirective := strings.ToUpper(r.Header.Get("X-Amz-Metadata-Directive"))
	tagDirective := strings.ToUpper(r.Header.Get("X-Amz-Tagging-Directive"))
	for _, d := range []string{metaDirective, tagDirective} {
		if d != "" && d != "COPY" && d != "REPLACE" {
			return errInvalidArgument("Unknown metadata directive.")
		}
	}
	if cs.Bucket == req.bucket && cs.Key == req.key && cs.VersionID == "" && metaDirective != "REPLACE" &&
		r.Header.Get("X-Amz-Storage-Class") == "" && r.Header.Get("X-Amz-Website-Redirect-Location") == "" &&
		r.Header.Get("X-Amz-Server-Side-Encryption") == "" {
		return errf(400, "InvalidRequest", "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.")
	}

	meta := src.Meta
	if metaDirective == "REPLACE" {
		m, merr := metaFromRequest(r)
		if merr != nil {
			return merr
		}
		m.ChecksumAlgo, m.Checksum, m.ChecksumType = src.Meta.ChecksumAlgo, src.Meta.Checksum, src.Meta.ChecksumType
		meta = m
	} else if sc := r.Header.Get("X-Amz-Storage-Class"); sc != "" {
		meta.StorageClass = sc
		if sc == "STANDARD" {
			meta.StorageClass = ""
		}
	}
	tags := src.Tags
	if tagDirective == "REPLACE" {
		if tags, err = tagsFromHeader(r); err != nil {
			return err
		}
	}
	owner, objACL, err := h.newObjectOwnership(req, b)
	if err != nil {
		return err
	}

	o := objectRow{Key: req.key, Size: src.Size, ETag: src.ETag, Blob: src.Blob, Parts: src.Parts,
		Meta: meta, Owner: owner, ACL: objACL, Tags: tags}
	vid, err := h.writeObject(req, o)
	if err != nil {
		return err
	}
	if b.Versioning == versioningEnabled {
		req.w.Header().Set("x-amz-version-id", vid)
	}
	res := copyObjectResult{ETag: src.ETag, LastModified: isoTime(time.Now())}
	if meta.ChecksumAlgo != "" && meta.ChecksumType != "COMPOSITE" {
		setCopyChecksum(&res, meta.ChecksumAlgo, meta.Checksum)
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}

func setCopyChecksum(r *copyObjectResult, algo, v string) {
	switch algo {
	case "CRC32":
		r.ChecksumCRC32 = v
	case "CRC32C":
		r.ChecksumCRC32C = v
	case "CRC64NVME":
		r.ChecksumCRC64NVME = v
	case "SHA1":
		r.ChecksumSHA1 = v
	case "SHA256":
		r.ChecksumSHA256 = v
	}
}

type copyPartResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// uploadPartCopy fills a part from (a range of) an existing object.
func (h *Handler) uploadPartCopy(req *request, u *upload, partNumber int) error {
	_, src, err := h.loadCopySource(req)
	if err != nil {
		return err
	}
	start, length := int64(0), src.Size
	if rng := req.r.Header.Get("X-Amz-Copy-Source-Range"); rng != "" {
		spec, ok := strings.CutPrefix(rng, "bytes=")
		a, bb, ok2 := strings.Cut(spec, "-")
		first, err1 := strconv.ParseInt(a, 10, 64)
		last, err2 := strconv.ParseInt(bb, 10, 64)
		if !ok || !ok2 || err1 != nil || err2 != nil || first < 0 || last < first {
			return errInvalidArgument("The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy")
		}
		if last >= src.Size {
			return errf(416, "InvalidRange", "The requested range is not satisfiable")
		}
		start, length = first, last-first+1
	}
	if length > maxObjectSize {
		return errf(400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
	}
	body, err := h.openRange(src, start, length)
	if err != nil {
		return err
	}
	defer body.Close()
	sum := newChecksum(u.Meta.ChecksumAlgo)
	var pending *store.Pending
	if sum != nil {
		pending, err = h.st.Blobs.Write(body, sum)
	} else {
		pending, err = h.st.Blobs.Write(body)
	}
	if err != nil {
		return err
	}
	defer pending.Abort()
	if err := pending.Commit(); err != nil {
		return err
	}
	checksum := ""
	if sum != nil {
		checksum = encodeChecksum(sum)
	}
	etag := `"` + hex.EncodeToString(pending.MD5) + `"`
	if err := h.savePart(req, u, partNumber, pending, etag, checksum); err != nil {
		return err
	}
	writeXML(req.w, http.StatusOK, copyPartResult{ETag: etag, LastModified: isoTime(time.Now())})
	return nil
}

// ---- conditional writes ------------------------------------------------------

// checkWriteConditions applies If-Match / If-None-Match on PutObject and
// CompleteMultipartUpload against the key's current version, inside the
// write transaction so no other write can slip in between.
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
func checkWriteConditions(req *request, tx *store.Tx, key string) error {
	ifMatch := req.r.Header.Get("If-Match")
	ifNoneMatch := req.r.Header.Get("If-None-Match")
	if ifMatch == "" && ifNoneMatch == "" {
		return nil
	}
	var etag string
	err := tx.QueryRowContext(req.ctx, `SELECT etag FROM s3_objects WHERE bucket = ? AND key = ? AND is_latest = 1 AND delete_marker = 0`,
		req.bucket, key).Scan(&etag)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	failed := errf(412, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
	if ifMatch != "" {
		if !exists {
			return errNoSuchKey(req.bucket, key)
		}
		if !etagMatches(ifMatch, etag) {
			return failed
		}
	}
	if ifNoneMatch != "" && exists && etagMatches(ifNoneMatch, etag) {
		return failed
	}
	return nil
}
