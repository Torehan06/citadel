package s3

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"citadel/internal/store"
)

// Bucket and object configuration documents: tagging, bucket policy and
// policy status, public access block, object ownership controls.

// ---- tagging ----------------------------------------------------------------

type tag struct {
	Key   string `xml:"Key" json:"k"`
	Value string `xml:"Value" json:"v"`
}

func parseStoredTags(s string) []tag {
	if s == "" {
		return nil
	}
	var t []tag
	_ = json.Unmarshal([]byte(s), &t)
	return t
}

func tagsJSON(t []tag) string {
	if len(t) == 0 {
		return ""
	}
	b, _ := json.Marshal(t)
	return string(b)
}

// validateTags applies S3's tag limits (10 per object, 50 per bucket).
func validateTags(t []tag, max int) error {
	if len(t) > max {
		if max == 10 {
			return errf(400, "BadRequest", "Object tags cannot be greater than 10")
		}
		return errf(400, "InvalidTag", "Bucket tag count cannot be greater than %d", max)
	}
	seen := map[string]bool{}
	for _, x := range t {
		if x.Key == "" || utf8.RuneCountInString(x.Key) > 128 {
			return errf(400, "InvalidTag", "The TagKey you have provided is invalid")
		}
		if utf8.RuneCountInString(x.Value) > 256 {
			return errf(400, "InvalidTag", "The TagValue you have provided is invalid")
		}
		if seen[x.Key] {
			return errf(400, "InvalidTag", "Cannot provide multiple Tags with the same key")
		}
		seen[x.Key] = true
	}
	return nil
}

// tagsFromHeader parses x-amz-tagging ("k1=v1&k2=v2") on PutObject and friends.
func tagsFromHeader(r *http.Request) ([]tag, error) {
	h := r.Header.Get("X-Amz-Tagging")
	if h == "" {
		return nil, nil
	}
	var t []tag
	for _, pair := range strings.Split(h, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return nil, errf(400, "InvalidArgument", "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.")
		}
		t = append(t, tag{Key: dk, Value: dv})
	}
	return t, validateTags(t, 10)
}

type tagging struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Tagging"`
	TagSet  []tag    `xml:"TagSet>Tag"`
}

type taggingIn struct {
	TagSet []tag `xml:"TagSet>Tag"`
}

func readTagging(req *request, max int) ([]tag, error) {
	body, err := readSmallBody(req, 64<<10, false)
	if err != nil {
		return nil, err
	}
	var in taggingIn
	if err := xml.Unmarshal(body, &in); err != nil {
		return nil, errMalformedXML()
	}
	return in.TagSet, validateTags(in.TagSet, max)
}

func (h *Handler) getObjectTagging(req *request) error {
	b, o, err := h.objectForRead(req, "s3:GetObjectTagging", permRead)
	if err != nil {
		return err
	}
	if b.Versioning != "" {
		req.w.Header().Set("x-amz-version-id", o.VersionID)
	}
	writeXML(req.w, http.StatusOK, tagging{TagSet: nonNilTags(o.Tags)})
	return nil
}

func nonNilTags(t []tag) []tag {
	if t == nil {
		return []tag{}
	}
	return t
}

func (h *Handler) putObjectTagging(req *request, remove bool) error {
	action := "s3:PutObjectTagging"
	if remove {
		action = "s3:DeleteObjectTagging"
	}
	b, o, err := h.objectForRead(req, action, permWrite)
	if err != nil {
		return err
	}
	var t []tag
	if !remove {
		if t, err = readTagging(req, 10); err != nil {
			return err
		}
	}
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx, `UPDATE s3_objects SET tagging = ? WHERE bucket = ? AND key = ? AND version_id = ?`,
			tagsJSON(t), req.bucket, req.key, o.VersionID); err != nil {
			return err
		}
		return tx.Change("s3", action[3:], req.bucket+"/"+req.key, map[string]any{"version": o.VersionID, "tags": len(t)})
	})
	if err != nil {
		return err
	}
	if b.Versioning != "" {
		req.w.Header().Set("x-amz-version-id", o.VersionID)
	}
	if remove {
		req.w.WriteHeader(http.StatusNoContent)
	} else {
		req.w.WriteHeader(http.StatusOK)
	}
	return nil
}

// setBucketColumn stores one bucket configuration column ("" clears it).
func (h *Handler) setBucketColumn(req *request, column, value, changeKind string) error {
	return h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx, `UPDATE s3_buckets SET `+column+` = ? WHERE name = ?`, value, req.bucket); err != nil {
			return err
		}
		return tx.Change("s3", changeKind, req.bucket, nil)
	})
}

func (h *Handler) getBucketTagging(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketTagging", "")
	if err != nil {
		return err
	}
	t := parseStoredTags(b.Tagging)
	if len(t) == 0 {
		return &Error{Status: 404, Code: "NoSuchTagSet", Message: "The TagSet does not exist", Bucket: req.bucket}
	}
	writeXML(req.w, http.StatusOK, tagging{TagSet: t})
	return nil
}

func (h *Handler) putBucketTagging(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketTagging", ""); err != nil {
		return err
	}
	t, err := readTagging(req, 50)
	if err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "tagging", tagsJSON(t), "PutBucketTagging"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) deleteBucketTagging(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketTagging", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "tagging", "", "DeleteBucketTagging"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- bucket policy ------------------------------------------------------------

func (h *Handler) getBucketPolicy(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketPolicy", "")
	if err != nil {
		return err
	}
	if b.PolicyRaw == "" {
		return &Error{Status: 404, Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist", Bucket: req.bucket}
	}
	req.w.Header().Set("Content-Type", "application/json")
	req.w.WriteHeader(http.StatusOK)
	_, _ = req.w.Write([]byte(b.PolicyRaw))
	return nil
}

func (h *Handler) putBucketPolicy(req *request) error {
	b, err := h.bucketAccess(req, "s3:PutBucketPolicy", "")
	if err != nil {
		return err
	}
	body, err := readSmallBody(req, 20<<10, false)
	if err != nil {
		return err
	}
	p, err := parsePolicy(body, req.bucket)
	if err != nil {
		return err
	}
	if b.PAB.BlockPublicPolicy && p.isPublic() {
		return errAccessDenied()
	}
	if err := h.setBucketColumn(req, "policy", string(body), "PutBucketPolicy"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) deleteBucketPolicy(req *request) error {
	if _, err := h.bucketAccess(req, "s3:DeleteBucketPolicy", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "policy", "", "DeleteBucketPolicy"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

type policyStatus struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ PolicyStatus"`
	IsPublic bool     `xml:"IsPublic"`
}

func (h *Handler) getBucketPolicyStatus(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketPolicyStatus", "")
	if err != nil {
		return err
	}
	public := b.Policy.isPublic() && !b.PAB.RestrictPublicBuckets
	writeXML(req.w, http.StatusOK, policyStatus{IsPublic: public})
	return nil
}

// ---- public access block ---------------------------------------------------------

type publicAccessBlockConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ PublicAccessBlockConfiguration"`
	publicAccessBlock
}

func (h *Handler) getPublicAccessBlock(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketPublicAccessBlock", "")
	if err != nil {
		return err
	}
	if !b.HasPAB {
		return &Error{Status: 404, Code: "NoSuchPublicAccessBlockConfiguration",
			Message: "The public access block configuration was not found", Bucket: req.bucket}
	}
	writeXML(req.w, http.StatusOK, publicAccessBlockConfiguration{publicAccessBlock: b.PAB})
	return nil
}

func (h *Handler) putPublicAccessBlock(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketPublicAccessBlock", ""); err != nil {
		return err
	}
	body, err := readSmallBody(req, 64<<10, false)
	if err != nil {
		return err
	}
	var cfg publicAccessBlock
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return errMalformedXML()
	}
	raw, _ := json.Marshal(cfg)
	if err := h.setBucketColumn(req, "public_access_block", string(raw), "PutPublicAccessBlock"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) deletePublicAccessBlock(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketPublicAccessBlock", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "public_access_block", "", "DeletePublicAccessBlock"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- object ownership ---------------------------------------------------------------

type ownershipControls struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ OwnershipControls"`
	Rules   []struct {
		ObjectOwnership string `xml:"ObjectOwnership"`
	} `xml:"Rule"`
}

func validOwnership(s string) bool {
	return s == ownershipObjectWriter || s == ownershipOwnerPreferred || s == ownershipOwnerEnforced
}

func (h *Handler) getOwnershipControls(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketOwnershipControls", "")
	if err != nil {
		return err
	}
	var out ownershipControls
	out.Rules = append(out.Rules, struct {
		ObjectOwnership string `xml:"ObjectOwnership"`
	}{b.Ownership})
	writeXML(req.w, http.StatusOK, out)
	return nil
}

func (h *Handler) putOwnershipControls(req *request) error {
	b, err := h.bucketAccess(req, "s3:PutBucketOwnershipControls", "")
	if err != nil {
		return err
	}
	body, err := readSmallBody(req, 64<<10, false)
	if err != nil {
		return err
	}
	var in ownershipControls
	if err := xml.Unmarshal(body, &in); err != nil || len(in.Rules) != 1 || !validOwnership(in.Rules[0].ObjectOwnership) {
		return errMalformedXML()
	}
	mode := in.Rules[0].ObjectOwnership
	if mode == ownershipOwnerEnforced && !b.ACL.onlyOwner() {
		return errf(400, "InvalidBucketAclWithObjectOwnership", "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting")
	}
	if err := h.setBucketColumn(req, "ownership", mode, "PutBucketOwnershipControls"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) deleteOwnershipControls(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketOwnershipControls", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "ownership", ownershipObjectWriter, "DeleteBucketOwnershipControls"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}
