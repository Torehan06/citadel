package s3

import (
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"citadel/internal/store"
)

// Multipart upload: https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
// Every part is a blob. Completion writes the object with a manifest of the
// chosen parts' blobs, so no bytes are copied and GET streams across them.

const (
	maxPartNumber = 10000
	minPartSize   = 5 << 20 // every part but the last
)

// partRef is one entry of a multipart object's manifest.
type partRef struct {
	Blob     string `json:"blob"`
	Size     int64  `json:"size"`
	Number   int    `json:"n,omitempty"`        // part number in the upload
	ETag     string `json:"etag,omitempty"`     // the part's ETag
	Checksum string `json:"checksum,omitempty"` // the part's checksum (upload's algorithm)
}

// openRange returns a reader over [start, start+length) of the object,
// whether it is one blob or a manifest of part blobs.
func (h *Handler) openRange(o *objectRow, start, length int64) (io.ReadCloser, error) {
	parts := o.Parts
	if len(parts) == 0 {
		parts = []partRef{{Blob: o.Blob, Size: o.Size}}
	}
	return &manifestReader{h: h, parts: parts, pos: start, end: start + length}, nil
}

type manifestReader struct {
	h        *Handler
	parts    []partRef
	pos, end int64 // absolute object offsets still to read
	cur      *os.File
	curEnd   int64 // absolute offset where the open part's remaining window ends
}

func (m *manifestReader) Read(p []byte) (int, error) {
	for {
		if m.pos >= m.end {
			return 0, io.EOF
		}
		if m.cur == nil {
			if err := m.openAt(m.pos); err != nil {
				return 0, err
			}
		}
		want := min(int64(len(p)), m.curEnd-m.pos)
		n, err := m.cur.Read(p[:want])
		m.pos += int64(n)
		if m.pos >= m.curEnd || err == io.EOF {
			m.cur.Close()
			m.cur = nil
			if err == io.EOF && m.pos < m.curEnd {
				return n, io.ErrUnexpectedEOF // blob shorter than recorded
			}
			err = nil
		}
		if n > 0 || err != nil {
			return n, err
		}
	}
}

func (m *manifestReader) openAt(pos int64) error {
	var off int64
	for _, pr := range m.parts {
		if pos < off+pr.Size {
			f, err := m.h.st.Blobs.Open(pr.Blob)
			if err != nil {
				return err
			}
			if _, err := f.Seek(pos-off, io.SeekStart); err != nil {
				f.Close()
				return err
			}
			m.cur, m.curEnd = f, min(off+pr.Size, m.end)
			return nil
		}
		off += pr.Size
	}
	return io.ErrUnexpectedEOF
}

func (m *manifestReader) Close() error {
	if m.cur != nil {
		return m.cur.Close()
	}
	return nil
}

func newUploadID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func errNoSuchUpload() *Error {
	return errf(404, "NoSuchUpload", "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")
}

type upload struct {
	ID        string
	Key       string
	Owner     string // account that will own the object
	Meta      objectMeta
	Tags      []tag
	ACL       *acl   // nil: default private
	Completed string // ETag of the object it became, "" while in progress
}

// loadUpload finds an in-progress upload (or, with completed, one that has
// already been completed).
func (h *Handler) loadUpload(req *request, id string, completed bool) (*upload, error) {
	var u upload
	var meta, tags, aclJSON, ownerCanonical string
	err := h.st.DB().QueryRowContext(req.ctx, `
		SELECT u.upload_id, u.key, u.owner, u.meta_json, u.tagging, u.acl, u.completed_etag, COALESCE(a.canonical_id, u.owner)
		FROM s3_uploads u LEFT JOIN accounts a ON a.id = u.owner
		WHERE u.upload_id = ? AND u.bucket = ? AND u.key = ?`,
		id, req.bucket, req.key).Scan(&u.ID, &u.Key, &u.Owner, &meta, &tags, &aclJSON, &u.Completed, &ownerCanonical)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && u.Completed != "" && !completed) {
		return nil, errNoSuchUpload()
	}
	if err != nil {
		return nil, err
	}
	u.Tags = parseStoredTags(tags)
	if aclJSON != "" {
		u.ACL = parseStoredACL(aclJSON, ownerCanonical)
	}
	return &u, json.Unmarshal([]byte(meta), &u.Meta)
}

type initiateResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

func (h *Handler) createMultipartUpload(req *request) error {
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
	ctype := strings.ToUpper(req.r.Header.Get("X-Amz-Checksum-Type"))
	if a := strings.ToUpper(req.r.Header.Get("X-Amz-Checksum-Algorithm")); a != "" {
		if newChecksum(a) == nil {
			return errInvalidArgument("Checksum algorithm provided is unsupported.")
		}
		if ctype == "" {
			// S3's defaults: CRC64NVME is always full-object, the rest composite.
			ctype = "COMPOSITE"
			if a == "CRC64NVME" {
				ctype = "FULL_OBJECT"
			}
		}
		if ctype != "COMPOSITE" && ctype != "FULL_OBJECT" {
			return errInvalidArgument("Value for x-amz-checksum-type header is invalid.")
		}
		if ctype == "FULL_OBJECT" && (a == "SHA1" || a == "SHA256") {
			return errf(400, "InvalidRequest", "The FULL_OBJECT checksum type cannot be used with the %s checksum algorithm.", strings.ToLower(a))
		}
		if ctype == "COMPOSITE" && a == "CRC64NVME" {
			return errf(400, "InvalidRequest", "The COMPOSITE checksum type cannot be used with the crc64nvme checksum algorithm.")
		}
		meta.ChecksumAlgo, meta.ChecksumType = a, ctype
	} else if ctype != "" {
		return errf(400, "InvalidRequest", "The x-amz-checksum-type header can only be used with the x-amz-checksum-algorithm header.")
	}
	owner, objACL, err := h.newObjectOwnership(req, b)
	if err != nil {
		return err
	}
	tags, err := tagsFromHeader(req.r)
	if err != nil {
		return err
	}
	aclJSON := ""
	if objACL != nil {
		aclJSON = objACL.json()
	}
	metaJSON, _ := json.Marshal(meta)
	id := newUploadID()
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx,
			`INSERT INTO s3_uploads(upload_id, bucket, key, initiated, owner, meta_json, tagging, acl) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, req.bucket, req.key, tx.HLC().WallMs(), owner, string(metaJSON), tagsJSON(tags), aclJSON); err != nil {
			return err
		}
		return tx.Change("s3", "CreateMultipartUpload", req.bucket+"/"+req.key, map[string]string{"upload": id})
	})
	if err != nil {
		return err
	}
	if meta.ChecksumAlgo != "" {
		req.w.Header().Set("x-amz-checksum-algorithm", meta.ChecksumAlgo)
		req.w.Header().Set("x-amz-checksum-type", meta.ChecksumType)
	}
	writeXML(req.w, http.StatusOK, initiateResult{Bucket: req.bucket, Key: req.key, UploadID: id})
	return nil
}

func (h *Handler) uploadPart(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	if err := h.authorizeWrite(req, b, req.key, "s3:PutObject"); err != nil {
		return err
	}
	q := req.r.URL.Query()
	n, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || n < 1 || n > maxPartNumber {
		return errInvalidArgument("Part number must be an integer between 1 and 10000, inclusive")
	}
	u, err := h.loadUpload(req, q.Get("uploadId"), false)
	if err != nil {
		return err
	}
	if req.r.Header.Get("X-Amz-Copy-Source") != "" {
		return h.uploadPartCopy(req, u, n)
	}
	in, err := h.ingest(req, u.Meta.ChecksumAlgo)
	if err != nil {
		return err
	}
	defer in.pending.Abort()
	if err := in.pending.Commit(); err != nil {
		return err
	}
	etag := `"` + hex.EncodeToString(in.pending.MD5) + `"`
	if err := h.savePart(req, u, n, in.pending, etag, in.checksum); err != nil {
		return err
	}
	req.w.Header().Set("ETag", etag)
	if in.algo != "" {
		req.w.Header().Set(checksumHeader(in.algo), in.checksum)
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

// savePart records a committed part blob, replacing an earlier upload of the
// same part number.
func (h *Handler) savePart(req *request, u *upload, n int, p *store.Pending, etag, checksum string) error {
	return h.st.Update(req.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(req.ctx, `
			INSERT INTO s3_parts(upload_id, part_number, size, etag, blob, checksum, last_modified)
			SELECT upload_id, ?, ?, ?, ?, ?, ? FROM s3_uploads WHERE upload_id = ? AND completed_etag = ''
			ON CONFLICT(upload_id, part_number) DO UPDATE SET size=excluded.size, etag=excluded.etag,
				blob=excluded.blob, checksum=excluded.checksum, last_modified=excluded.last_modified`,
			n, p.Size, etag, p.SHA256, checksum, tx.HLC().WallMs(), u.ID)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c == 0 {
			return errNoSuchUpload() // aborted or completed while the part streamed in
		}
		return tx.Change("s3", "UploadPart", req.bucket+"/"+req.key, map[string]any{"upload": u.ID, "part": n, "blob": p.SHA256})
	})
}

type completePart struct {
	PartNumber        int    `xml:"PartNumber"`
	ETag              string `xml:"ETag"`
	ChecksumCRC32     string `xml:"ChecksumCRC32"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME"`
	ChecksumSHA1      string `xml:"ChecksumSHA1"`
	ChecksumSHA256    string `xml:"ChecksumSHA256"`
}

type completeRequest struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []completePart `xml:"Part"`
}

// checksum returns the part checksum the client listed for algo.
func (p completePart) checksum(algo string) string {
	switch algo {
	case "CRC32":
		return p.ChecksumCRC32
	case "CRC32C":
		return p.ChecksumCRC32C
	case "CRC64NVME":
		return p.ChecksumCRC64NVME
	case "SHA1":
		return p.ChecksumSHA1
	case "SHA256":
		return p.ChecksumSHA256
	}
	return ""
}

type completeResult struct {
	XMLName           xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location          string   `xml:"Location"`
	Bucket            string   `xml:"Bucket"`
	Key               string   `xml:"Key"`
	ETag              string   `xml:"ETag"`
	ChecksumCRC32     string   `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string   `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string   `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string   `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string   `xml:"ChecksumSHA256,omitempty"`
	ChecksumType      string   `xml:"ChecksumType,omitempty"`
}

type storedPart struct {
	size     int64
	etag     string
	blob     string
	checksum string
}

func (h *Handler) completeMultipartUpload(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	if err := h.authorizeWrite(req, b, req.key, "s3:PutObject"); err != nil {
		return err
	}
	u, err := h.loadUpload(req, req.r.URL.Query().Get("uploadId"), true)
	if err != nil {
		return err
	}
	// On Complete, x-amz-checksum-* describes the whole object, not this
	// small XML body, so read the body without checking those headers.
	body, err := readPlainBody(req, 4<<20)
	if err != nil {
		return err
	}
	var cr completeRequest
	if err := xml.Unmarshal(body, &cr); err != nil || len(cr.Parts) == 0 {
		return errMalformedXML()
	}

	stored := map[int]storedPart{}
	rows, err := h.st.DB().QueryContext(req.ctx,
		`SELECT part_number, size, etag, blob, checksum FROM s3_parts WHERE upload_id = ?`, u.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n int
		var p storedPart
		if err := rows.Scan(&n, &p.size, &p.etag, &p.blob, &p.checksum); err != nil {
			rows.Close()
			return err
		}
		stored[n] = p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var (
		manifest []partRef
		md5s     []byte
		sums     []byte
		size     int64
	)
	for i, p := range cr.Parts {
		if i > 0 && p.PartNumber <= cr.Parts[i-1].PartNumber {
			return errf(400, "InvalidPartOrder", "The list of parts was not in ascending order. The parts list must be specified in order by part number.")
		}
		sp, ok := stored[p.PartNumber]
		if !ok || strings.Trim(p.ETag, `"`) != strings.Trim(sp.etag, `"`) {
			return errf(400, "InvalidPart", "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not have matched the part's entity tag.")
		}
		if i < len(cr.Parts)-1 && sp.size < minPartSize {
			return errf(400, "EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size.")
		}
		if want := p.checksum(u.Meta.ChecksumAlgo); want != "" && want != sp.checksum {
			return errf(400, "InvalidPart", "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not have matched the part's entity tag.")
		}
		raw, _ := hex.DecodeString(strings.Trim(sp.etag, `"`))
		md5s = append(md5s, raw...)
		if u.Meta.ChecksumAlgo != "" {
			c, err := base64.StdEncoding.DecodeString(sp.checksum)
			if err != nil {
				return err
			}
			sums = append(sums, c...)
		}
		manifest = append(manifest, partRef{Blob: sp.blob, Size: sp.size, Number: p.PartNumber, ETag: sp.etag, Checksum: sp.checksum})
		size += sp.size
	}
	sum := md5.Sum(md5s)
	etag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(sum[:]), len(cr.Parts))

	meta := u.Meta
	res := completeResult{Location: "/" + req.bucket + "/" + req.key, Bucket: req.bucket, Key: req.key, ETag: etag}
	algo, ctype := meta.ChecksumAlgo, meta.ChecksumType
	if algo == "" {
		// No algorithm named: S3 still gives the object a full-object CRC64NVME.
		algo, ctype = "CRC64NVME", "FULL_OBJECT"
	}
	var objSum string
	if ctype == "COMPOSITE" {
		// A composite checksum is the checksum of the parts' checksums,
		// suffixed with the part count.
		c := newChecksum(algo)
		c.Write(sums)
		objSum = encodeChecksum(c) + "-" + strconv.Itoa(len(cr.Parts))
	} else {
		// A full-object checksum covers the object's bytes: stream the parts
		// once. (CRCs could be combined arithmetically instead; this is the
		// simple, obviously-correct version.)
		c := newChecksum(algo)
		rd, err := h.openRange(&objectRow{Size: size, Parts: manifest}, 0, size)
		if err != nil {
			return err
		}
		_, err = io.Copy(c, rd)
		rd.Close()
		if err != nil {
			return err
		}
		objSum = encodeChecksum(c)
	}
	if want := req.r.Header.Get(checksumHeader(algo)); want != "" && want != objSum {
		return checksumMismatch(algo)
	}
	meta.ChecksumAlgo, meta.ChecksumType, meta.Checksum = algo, ctype, objSum
	if u.Meta.ChecksumAlgo != "" {
		setResultChecksum(&res, algo, objSum)
		res.ChecksumType = ctype
	}

	if u.Completed != "" {
		// A repeated Complete with the same parts gets the same answer.
		if u.Completed != etag {
			return errNoSuchUpload()
		}
		writeXML(req.w, http.StatusOK, res)
		return nil
	}
	o := objectRow{Key: req.key, Size: size, ETag: etag, Parts: manifest, Meta: meta, Owner: u.Owner, ACL: u.ACL, Tags: u.Tags}
	var vid string
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(req.ctx, `UPDATE s3_uploads SET completed_etag = ? WHERE upload_id = ? AND completed_etag = ''`, etag, u.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoSuchUpload()
		}
		if err := tx.Change("s3", "CompleteMultipartUpload", req.bucket+"/"+req.key, map[string]any{"upload": u.ID, "parts": len(manifest)}); err != nil {
			return err
		}
		vid, err = writeObjectTx(req, tx, o)
		return err
	})
	if err != nil {
		return err
	}
	if b.Versioning == versioningEnabled {
		req.w.Header().Set("x-amz-version-id", vid)
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}

func setResultChecksum(r *completeResult, algo, v string) {
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

func (h *Handler) abortMultipartUpload(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	if err := h.authorizeWrite(req, b, req.key, "s3:AbortMultipartUpload"); err != nil {
		return err
	}
	id := req.r.URL.Query().Get("uploadId")
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(req.ctx, `DELETE FROM s3_uploads WHERE upload_id = ? AND bucket = ? AND key = ? AND completed_etag = ''`, id, req.bucket, req.key)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoSuchUpload()
		}
		return tx.Change("s3", "AbortMultipartUpload", req.bucket+"/"+req.key, map[string]string{"upload": id})
	})
	if err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

type listPartsResult struct {
	XMLName              xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket               string     `xml:"Bucket"`
	Key                  string     `xml:"Key"`
	UploadID             string     `xml:"UploadId"`
	Initiator            *owner     `xml:"Initiator"`
	Owner                *owner     `xml:"Owner"`
	StorageClass         string     `xml:"StorageClass"`
	PartNumberMarker     int        `xml:"PartNumberMarker"`
	NextPartNumberMarker int        `xml:"NextPartNumberMarker"`
	MaxParts             int        `xml:"MaxParts"`
	IsTruncated          bool       `xml:"IsTruncated"`
	Parts                []partItem `xml:"Part"`
	ChecksumAlgorithm    string     `xml:"ChecksumAlgorithm,omitempty"`
}

type partItem struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

func (h *Handler) listParts(req *request) error {
	if _, err := h.bucketAccess(req, "s3:ListMultipartUploadParts", permRead); err != nil {
		return err
	}
	q := req.r.URL.Query()
	u, err := h.loadUpload(req, q.Get("uploadId"), false)
	if err != nil {
		return err
	}
	maxParts := 1000
	if s := q.Get("max-parts"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errInvalidArgument("Provided max-parts not an integer or within integer range")
		}
		maxParts = min(n, 1000)
	}
	marker := 0
	if s := q.Get("part-number-marker"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errInvalidArgument("Provided part-number-marker not an integer or within integer range")
		}
		marker = n
	}
	rows, err := h.st.DB().QueryContext(req.ctx, `
		SELECT part_number, last_modified, etag, size FROM s3_parts
		WHERE upload_id = ? AND part_number > ? ORDER BY part_number LIMIT ?`, u.ID, marker, maxParts+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	ow := (&owners{h: h, ctx: req.ctx}).get(u.Owner)
	res := listPartsResult{
		Bucket: req.bucket, Key: req.key, UploadID: u.ID, Initiator: ow, Owner: ow, StorageClass: "STANDARD",
		PartNumberMarker: marker, MaxParts: maxParts, ChecksumAlgorithm: u.Meta.ChecksumAlgo,
	}
	for rows.Next() {
		var p partItem
		var lm int64
		if err := rows.Scan(&p.PartNumber, &lm, &p.ETag, &p.Size); err != nil {
			return err
		}
		p.LastModified = isoTime(msTime(lm))
		res.Parts = append(res.Parts, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(res.Parts) > maxParts {
		res.Parts, res.IsTruncated = res.Parts[:maxParts], true
	}
	if len(res.Parts) > 0 {
		res.NextPartNumberMarker = res.Parts[len(res.Parts)-1].PartNumber
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}

type listUploadsResult struct {
	XMLName            xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
	Bucket             string         `xml:"Bucket"`
	KeyMarker          string         `xml:"KeyMarker"`
	UploadIDMarker     string         `xml:"UploadIdMarker"`
	NextKeyMarker      string         `xml:"NextKeyMarker"`
	NextUploadIDMarker string         `xml:"NextUploadIdMarker"`
	Prefix             string         `xml:"Prefix"`
	Delimiter          string         `xml:"Delimiter,omitempty"`
	MaxUploads         int            `xml:"MaxUploads"`
	IsTruncated        bool           `xml:"IsTruncated"`
	Uploads            []uploadItem   `xml:"Upload"`
	CommonPrefixes     []commonPrefix `xml:"CommonPrefixes"`
}

type uploadItem struct {
	Key          string `xml:"Key"`
	UploadID     string `xml:"UploadId"`
	Initiator    *owner `xml:"Initiator"`
	Owner        *owner `xml:"Owner"`
	StorageClass string `xml:"StorageClass"`
	Initiated    string `xml:"Initiated"`
}

// listMultipartUploads lists in-progress uploads in (key, initiated) order.
// Delimiter roll-up and upload-id-marker are basic for now (M2 finishes them).
func (h *Handler) listMultipartUploads(req *request) error {
	if _, err := h.bucketAccess(req, "s3:ListBucketMultipartUploads", permRead); err != nil {
		return err
	}
	q := req.r.URL.Query()
	maxUploads := 1000
	if s := q.Get("max-uploads"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errInvalidArgument("Provided max-uploads not an integer or within integer range")
		}
		maxUploads = min(n, 1000)
	}
	prefix, keyMarker := q.Get("prefix"), q.Get("key-marker")
	rows, err := h.st.DB().QueryContext(req.ctx, `
		SELECT key, upload_id, owner, initiated FROM s3_uploads
		WHERE bucket = ? AND completed_etag = '' AND key > ? AND substr(key, 1, length(?)) = ?
		ORDER BY key, initiated LIMIT ?`, req.bucket, keyMarker, prefix, prefix, maxUploads+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	ow := &owners{h: h, ctx: req.ctx}
	res := listUploadsResult{Bucket: req.bucket, KeyMarker: keyMarker, UploadIDMarker: q.Get("upload-id-marker"),
		Prefix: prefix, Delimiter: q.Get("delimiter"), MaxUploads: maxUploads}
	for rows.Next() {
		var it uploadItem
		var acct string
		var initiated int64
		if err := rows.Scan(&it.Key, &it.UploadID, &acct, &initiated); err != nil {
			return err
		}
		it.Initiator, it.Owner = ow.get(acct), ow.get(acct)
		it.StorageClass, it.Initiated = "STANDARD", isoTime(msTime(initiated))
		res.Uploads = append(res.Uploads, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(res.Uploads) > maxUploads {
		res.Uploads, res.IsTruncated = res.Uploads[:maxUploads], true
	}
	if n := len(res.Uploads); n > 0 {
		res.NextKeyMarker, res.NextUploadIDMarker = res.Uploads[n-1].Key, res.Uploads[n-1].UploadID
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}
