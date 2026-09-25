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
	Blob string `json:"blob"`
	Size int64  `json:"size"`
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
	ID    string
	Key   string
	Owner string
	Meta  objectMeta
}

func (h *Handler) loadUpload(req *request, id string) (*upload, error) {
	var u upload
	var meta string
	err := h.st.DB().QueryRowContext(req.ctx,
		`SELECT upload_id, key, owner, meta_json FROM s3_uploads WHERE upload_id = ? AND bucket = ? AND key = ?`,
		id, req.bucket, req.key).Scan(&u.ID, &u.Key, &u.Owner, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoSuchUpload()
	}
	if err != nil {
		return nil, err
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
	if _, err := h.ownedBucket(req); err != nil {
		return err
	}
	if len(req.key) > maxKeyLength {
		return errf(400, "KeyTooLongError", "Your key is too long")
	}
	meta, merr := metaFromRequest(req.r)
	if merr != nil {
		return merr
	}
	if a := strings.ToUpper(req.r.Header.Get("X-Amz-Checksum-Algorithm")); a != "" {
		if newChecksum(a) == nil {
			return errInvalidArgument("Checksum algorithm provided is unsupported.")
		}
		meta.ChecksumAlgo = a
		meta.ChecksumType = strings.ToUpper(req.r.Header.Get("X-Amz-Checksum-Type"))
		if meta.ChecksumType == "" {
			meta.ChecksumType = "COMPOSITE"
		}
	}
	metaJSON, _ := json.Marshal(meta)
	id := newUploadID()
	err := h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx,
			`INSERT INTO s3_uploads(upload_id, bucket, key, initiated, owner, meta_json) VALUES (?, ?, ?, ?, ?, ?)`,
			id, req.bucket, req.key, tx.HLC().WallMs(), req.who.Account.ID, string(metaJSON)); err != nil {
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
	if _, err := h.ownedBucket(req); err != nil {
		return err
	}
	q := req.r.URL.Query()
	if req.r.Header.Get("X-Amz-Copy-Source") != "" {
		return errNotImplemented("UploadPartCopy")
	}
	n, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || n < 1 || n > maxPartNumber {
		return errInvalidArgument("Part number must be an integer between 1 and 10000, inclusive")
	}
	u, err := h.loadUpload(req, q.Get("uploadId"))
	if err != nil {
		return err
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
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(req.ctx, `
			INSERT INTO s3_parts(upload_id, part_number, size, etag, blob, checksum, last_modified)
			SELECT upload_id, ?, ?, ?, ?, ?, ? FROM s3_uploads WHERE upload_id = ?
			ON CONFLICT(upload_id, part_number) DO UPDATE SET size=excluded.size, etag=excluded.etag,
				blob=excluded.blob, checksum=excluded.checksum, last_modified=excluded.last_modified`,
			n, in.pending.Size, etag, in.pending.SHA256, in.checksum, tx.HLC().WallMs(), u.ID)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c == 0 {
			return errNoSuchUpload() // aborted or completed while the part streamed in
		}
		return tx.Change("s3", "UploadPart", req.bucket+"/"+req.key, map[string]any{"upload": u.ID, "part": n, "blob": in.pending.SHA256})
	})
	if err != nil {
		return err
	}
	req.w.Header().Set("ETag", etag)
	if in.algo != "" {
		req.w.Header().Set(checksumHeader(in.algo), in.checksum)
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

type completeRequest struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber        int    `xml:"PartNumber"`
		ETag              string `xml:"ETag"`
		ChecksumCRC32     string `xml:"ChecksumCRC32"`
		ChecksumCRC32C    string `xml:"ChecksumCRC32C"`
		ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME"`
		ChecksumSHA1      string `xml:"ChecksumSHA1"`
		ChecksumSHA256    string `xml:"ChecksumSHA256"`
	} `xml:"Part"`
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
	if _, err := h.ownedBucket(req); err != nil {
		return err
	}
	u, err := h.loadUpload(req, req.r.URL.Query().Get("uploadId"))
	if err != nil {
		return err
	}
	body, err := readSmallBody(req, 4<<20, false)
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
		raw, _ := hex.DecodeString(strings.Trim(sp.etag, `"`))
		md5s = append(md5s, raw...)
		if u.Meta.ChecksumAlgo != "" {
			c, err := base64.StdEncoding.DecodeString(sp.checksum)
			if err != nil {
				return err
			}
			sums = append(sums, c...)
		}
		manifest = append(manifest, partRef{Blob: sp.blob, Size: sp.size})
		size += sp.size
	}
	sum := md5.Sum(md5s)
	etag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(sum[:]), len(cr.Parts))

	meta := u.Meta
	res := completeResult{Location: "/" + req.bucket + "/" + req.key, Bucket: req.bucket, Key: req.key, ETag: etag}
	if meta.ChecksumAlgo != "" && meta.ChecksumType == "COMPOSITE" {
		// A composite checksum is the checksum of the parts' checksums, suffixed
		// with the part count. (FULL_OBJECT multipart checksums arrive in M2.)
		c := newChecksum(meta.ChecksumAlgo)
		c.Write(sums)
		meta.Checksum = encodeChecksum(c) + "-" + strconv.Itoa(len(cr.Parts))
		setResultChecksum(&res, meta.ChecksumAlgo, meta.Checksum)
		res.ChecksumType = "COMPOSITE"
	} else {
		meta.ChecksumAlgo, meta.ChecksumType = "", ""
	}

	o := objectRow{Key: req.key, Size: size, ETag: etag, Parts: manifest, Meta: meta}
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(req.ctx, `DELETE FROM s3_uploads WHERE upload_id = ?`, u.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoSuchUpload()
		}
		if err := tx.Change("s3", "CompleteMultipartUpload", req.bucket+"/"+req.key, map[string]any{"upload": u.ID, "parts": len(manifest)}); err != nil {
			return err
		}
		return writeObjectTx(req, tx, o)
	})
	if err != nil {
		return err
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
	if _, err := h.ownedBucket(req); err != nil {
		return err
	}
	id := req.r.URL.Query().Get("uploadId")
	err := h.st.Update(req.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(req.ctx, `DELETE FROM s3_uploads WHERE upload_id = ? AND bucket = ? AND key = ?`, id, req.bucket, req.key)
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
	if _, err := h.ownedBucket(req); err != nil {
		return err
	}
	q := req.r.URL.Query()
	u, err := h.loadUpload(req, q.Get("uploadId"))
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
	if _, err := h.ownedBucket(req); err != nil {
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
		WHERE bucket = ? AND key > ? AND substr(key, 1, length(?)) = ?
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
