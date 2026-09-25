package s3

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"citadel/internal/store"
)

// validBucketName applies the general-purpose bucket naming rules:
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func validBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	// Every dot-separated label starts and ends with a letter or digit; this
	// also rules out "..", ".-" and "-.".
	for _, label := range strings.Split(name, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	if ip := net.ParseIP(name); ip != nil {
		return false
	}
	for _, p := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	for _, s := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

type createBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

func (h *Handler) createBucket(req *request) error {
	if req.who == nil {
		return errAccessDenied()
	}
	if !validBucketName(req.bucket) {
		return &Error{Status: 400, Code: "InvalidBucketName", Message: "The specified bucket is not valid.", Bucket: req.bucket}
	}
	if strings.EqualFold(req.r.Header.Get("X-Amz-Bucket-Object-Lock-Enabled"), "true") {
		return errNotImplemented("object lock")
	}
	body, err := io.ReadAll(io.LimitReader(req.r.Body, 64<<10))
	if err != nil {
		return err
	}
	var cfg createBucketConfiguration
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := xml.Unmarshal(body, &cfg); err != nil {
			return errMalformedXML()
		}
	}
	// A bucket lives in this region. The constraint is recorded as given and
	// reported back by GetBucketLocation; Citadel doesn't route by it (yet).
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		var owner string
		switch err := tx.QueryRowContext(req.ctx, `SELECT account_id FROM s3_buckets WHERE name = ?`, req.bucket).Scan(&owner); {
		case err == nil && owner == req.who.Account.ID && legacyUSEast1(req, cfg.LocationConstraint):
			return nil // idempotent: the bucket already exists as asked
		case err == nil && owner == req.who.Account.ID:
			return &Error{Status: 409, Code: "BucketAlreadyOwnedByYou",
				Message: "Your previous request to create the named bucket succeeded and you already own it.", Bucket: req.bucket}
		case err == nil:
			return &Error{Status: 409, Code: "BucketAlreadyExists",
				Message: "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.",
				Bucket:  req.bucket}
		case !errors.Is(err, errNoRows):
			return err
		}
		if _, err := tx.ExecContext(req.ctx, `
			INSERT INTO s3_buckets(name, account_id, region, location_constraint, created, hlc) VALUES (?, ?, ?, ?, ?, ?)`,
			req.bucket, req.who.Account.ID, h.region, cfg.LocationConstraint, tx.HLC().WallMs(), int64(tx.HLC())); err != nil {
			return err
		}
		return tx.Change("s3", "CreateBucket", req.bucket, map[string]string{
			"account": req.who.Account.ID, "location": cfg.LocationConstraint,
		})
	})
	if err != nil {
		return err
	}
	req.w.Header().Set("Location", "/"+req.bucket)
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) headBucket(req *request) error {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return err
	}
	req.w.Header().Set("x-amz-bucket-region", b.Region)
	if req.who == nil || req.who.Account.ID != b.Account {
		return errAccessDenied()
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) deleteBucket(req *request) error {
	if _, err := h.ownedBucket(req); err != nil {
		return err
	}
	err := h.st.Update(req.ctx, func(tx *store.Tx) error {
		var n int
		if err := tx.QueryRowContext(req.ctx,
			`SELECT COUNT(*) FROM (SELECT 1 FROM s3_objects WHERE bucket = ? LIMIT 1)`, req.bucket).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return &Error{Status: 409, Code: "BucketNotEmpty", Message: "The bucket you tried to delete is not empty", Bucket: req.bucket}
		}
		// In-progress multipart uploads don't keep a bucket alive; their parts go too.
		if _, err := tx.ExecContext(req.ctx, `DELETE FROM s3_uploads WHERE bucket = ?`, req.bucket); err != nil {
			return err
		}
		res, err := tx.ExecContext(req.ctx, `DELETE FROM s3_buckets WHERE name = ?`, req.bucket)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoSuchBucket(req.bucket)
		}
		return tx.Change("s3", "DeleteBucket", req.bucket, nil)
	})
	if err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

type owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

func ownerOf(a store.Account) *owner { return &owner{ID: a.CanonicalID, DisplayName: a.DisplayName} }

type listAllMyBucketsResult struct {
	XMLName           xml.Name     `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner             *owner       `xml:"Owner"`
	Buckets           []bucketItem `xml:"Buckets>Bucket"`
	ContinuationToken string       `xml:"ContinuationToken,omitempty"`
	Prefix            string       `xml:"Prefix,omitempty"`
}

type bucketItem struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
	BucketRegion string `xml:"BucketRegion,omitempty"`
}

// listBuckets returns the caller's buckets in name order. Supports the
// max-buckets / continuation-token / prefix / bucket-region parameters.
func (h *Handler) listBuckets(req *request) error {
	if req.who == nil {
		return errAccessDenied()
	}
	q := req.r.URL.Query()
	limit := 10000
	if s := q.Get("max-buckets"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 10000 {
			return errInvalidArgument("Argument max-buckets must be an integer between 1 and 10000.")
		}
		limit = n
	}
	after := ""
	if tok := q.Get("continuation-token"); tok != "" {
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			return errInvalidArgument("The continuation token provided is incorrect")
		}
		after = string(raw)
	}
	prefix := q.Get("prefix")
	region := q.Get("bucket-region")

	rows, err := h.st.DB().QueryContext(req.ctx, `
		SELECT name, created, region FROM s3_buckets
		WHERE account_id = ? AND name > ? AND substr(name, 1, length(?)) = ? AND (? = '' OR region = ?)
		ORDER BY name LIMIT ?`,
		req.who.Account.ID, after, prefix, prefix, region, region, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	res := listAllMyBucketsResult{Owner: ownerOf(req.who.Account), Prefix: prefix, Buckets: []bucketItem{}}
	for rows.Next() {
		var it bucketItem
		var created int64
		if err := rows.Scan(&it.Name, &created, &it.BucketRegion); err != nil {
			return err
		}
		it.CreationDate = isoTime(msTime(created))
		res.Buckets = append(res.Buckets, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(res.Buckets) > limit {
		res.Buckets = res.Buckets[:limit]
		res.ContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(res.Buckets[limit-1].Name))
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}

type locationConstraint struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
	Value   string   `xml:",chardata"`
}

func (h *Handler) getBucketLocation(req *request) error {
	b, err := h.ownedBucket(req)
	if err != nil {
		return err
	}
	writeXML(req.w, http.StatusOK, locationConstraint{Value: b.Location})
	return nil
}

type versioningConfiguration struct {
	XMLName   xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
	Status    string   `xml:"Status,omitempty"`
	MfaDelete string   `xml:"MfaDelete,omitempty"`
}

func (h *Handler) getBucketVersioning(req *request) error {
	b, err := h.ownedBucket(req)
	if err != nil {
		return err
	}
	writeXML(req.w, http.StatusOK, versioningConfiguration{Status: b.Versioning})
	return nil
}

// legacyUSEast1 reports whether a CreateBucket for a bucket the caller
// already owns gets us-east-1's legacy answer: 200 OK instead of 409
// BucketAlreadyOwnedByYou. S3 does that only for requests addressed to
// us-east-1 without a location constraint (or with "us-east-1").
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func legacyUSEast1(req *request, constraint string) bool {
	return req.auth.Region == "us-east-1" && (constraint == "" || constraint == "us-east-1")
}
