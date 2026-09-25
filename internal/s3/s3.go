// Package s3 implements the S3 REST-XML API (path-style addressing) on top of
// the region store.
package s3

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"citadel/internal/sigv4"
	"citadel/internal/store"
)

// Handler serves S3 for one region.
type Handler struct {
	st     *store.Store
	auth   *sigv4.Verifier
	region string
	log    *slog.Logger
}

func New(st *store.Store, v *sigv4.Verifier, region string, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{st: st, auth: v, region: region, log: log}
}

// request carries what every operation needs after authentication.
type request struct {
	w      http.ResponseWriter
	r      *http.Request
	ctx    context.Context
	auth   *sigv4.Auth
	who    *store.Principal // nil for anonymous requests
	bucket string
	key    string
	hasKey bool
}

// subresources are query parameters that turn a request into a different
// operation. Any we don't implement answers NotImplemented instead of being
// mistaken for the plain bucket/object operation.
var subresources = []string{
	"accelerate", "acl", "analytics", "attributes", "cors", "delete", "encryption",
	"intelligent-tiering", "inventory", "legal-hold", "lifecycle", "location", "logging",
	"metadataConfiguration", "metadataTable", "metrics", "notification", "object-lock",
	"ownershipControls", "partNumber", "policy", "policyStatus", "publicAccessBlock",
	"renameObject", "replication", "requestPayment", "restore", "retention", "select",
	"session", "tagging", "torrent", "uploadId", "uploads", "versioning", "versions", "website",
}

func subresource(q map[string][]string) string {
	for _, s := range subresources {
		if _, ok := q[s]; ok {
			return s
		}
	}
	return ""
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("x-amz-id-2", w.Header().Get("x-amz-request-id"))
	if err := h.serve(w, r); err != nil {
		if writeError(w, r, err) == http.StatusInternalServerError {
			h.log.Error("s3 internal error", "method", r.Method, "path", r.URL.Path, "err", err)
		}
	}
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) error {
	auth, err := h.auth.Verify(r)
	if err != nil {
		return err
	}
	req := &request{w: w, r: r, ctx: r.Context(), auth: auth}
	if !auth.Anonymous {
		_, p, err := h.st.LookupKey(r.Context(), auth.AccessKey)
		if err != nil {
			return err
		}
		req.who = &p
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	req.bucket, req.key, req.hasKey = strings.Cut(path, "/")
	if req.hasKey && req.key == "" {
		req.hasKey = false // "/bucket/" addresses the bucket
	}
	q := r.URL.Query()
	sub := subresource(q)

	if req.bucket == "" {
		if r.Method == http.MethodGet && sub == "" {
			return h.listBuckets(req)
		}
		return errNotImplemented("this service-level operation")
	}
	if !req.hasKey {
		return h.bucketOp(req, sub)
	}
	return h.objectOp(req, sub)
}

func (h *Handler) bucketOp(req *request, sub string) error {
	m := req.r.Method
	switch {
	case sub == "" && m == http.MethodPut:
		return h.createBucket(req)
	case sub == "" && m == http.MethodHead:
		return h.headBucket(req)
	case sub == "" && m == http.MethodDelete:
		return h.deleteBucket(req)
	case sub == "" && m == http.MethodGet:
		if req.r.URL.Query().Get("list-type") == "2" {
			return h.listObjectsV2(req)
		}
		return h.listObjectsV1(req)
	case sub == "versions" && m == http.MethodGet:
		return h.listObjectVersions(req)
	case sub == "location" && m == http.MethodGet:
		return h.getBucketLocation(req)
	case sub == "versioning" && m == http.MethodGet:
		return h.getBucketVersioning(req)
	case sub == "delete" && m == http.MethodPost:
		return h.deleteObjects(req)
	case sub == "uploads" && m == http.MethodGet:
		return h.listMultipartUploads(req)
	case sub == "" && m == http.MethodPost:
		return errNotImplemented("PostObject (browser-based upload)")
	}
	if sub == "" {
		return errf(405, "MethodNotAllowed", "The specified method is not allowed against this resource.")
	}
	return errNotImplemented(m + " ?" + sub)
}

func (h *Handler) objectOp(req *request, sub string) error {
	m := req.r.Method
	q := req.r.URL.Query()
	if _, ok := q["uploadId"]; ok {
		switch m {
		case http.MethodPut:
			return h.uploadPart(req)
		case http.MethodPost:
			return h.completeMultipartUpload(req)
		case http.MethodDelete:
			return h.abortMultipartUpload(req)
		case http.MethodGet:
			return h.listParts(req)
		}
	}
	if sub == "uploads" && m == http.MethodPost {
		return h.createMultipartUpload(req)
	}
	if sub == "" {
		switch m {
		case http.MethodPut:
			if req.r.Header.Get("X-Amz-Copy-Source") != "" {
				return errNotImplemented("CopyObject")
			}
			return h.putObject(req)
		case http.MethodGet, http.MethodHead:
			return h.getObject(req, m == http.MethodHead)
		case http.MethodDelete:
			return h.deleteObject(req)
		}
		return errf(405, "MethodNotAllowed", "The specified method is not allowed against this resource.")
	}
	return errNotImplemented(m + " object ?" + sub)
}

// bucketInfo is a bucket row plus its owner.
type bucketInfo struct {
	Name       string
	Account    string
	Region     string
	Location   string
	Created    time.Time
	Versioning string
}

func (h *Handler) loadBucket(ctx context.Context, name string) (*bucketInfo, error) {
	var b bucketInfo
	var created int64
	err := h.st.DB().QueryRowContext(ctx,
		`SELECT name, account_id, region, location_constraint, created, versioning FROM s3_buckets WHERE name = ?`, name).
		Scan(&b.Name, &b.Account, &b.Region, &b.Location, &created, &b.Versioning)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoSuchBucket(name)
	}
	if err != nil {
		return nil, err
	}
	b.Created = time.UnixMilli(created).UTC()
	return &b, nil
}

// ownedBucket loads a bucket and checks the caller may use it. Until bucket
// ACLs and policies land (M2), only the owning account may.
func (h *Handler) ownedBucket(req *request) (*bucketInfo, error) {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return nil, err
	}
	if req.who == nil || req.who.Account.ID != b.Account {
		return nil, errAccessDenied()
	}
	return b, nil
}

const isoMillis = "2006-01-02T15:04:05.000Z"

func isoTime(t time.Time) string { return t.UTC().Format(isoMillis) }
