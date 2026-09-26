package s3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"citadel/internal/iam"
)

// Authorization for S3 (ARCHITECTURE.md §5, phase M2): bucket policies,
// ACLs, object ownership and public access blocks, plus (M5) the identity
// policies of IAM users and role sessions. Account roots, which include the
// bootstrap identities, have no identity policies and may do anything to
// resources their own account owns.
//
// Order of evaluation, as S3 applies it:
//  1. An explicit Deny in the bucket policy or an identity policy wins.
//  2. The resource owner's account is allowed when the caller's identity
//     policies allow (roots always do) or the bucket policy names it.
//  3. An Allow in the bucket policy grants access (to objects the bucket
//     owner owns); across accounts the identity policies must allow too.
//  4. An ACL grant grants access, unless ACLs are disabled
//     (BucketOwnerEnforced) or the grant is public and IgnorePublicAcls is on.
//  5. Otherwise: implicit deny.

type publicAccessBlock struct {
	BlockPublicAcls       bool `xml:"BlockPublicAcls" json:"block_public_acls"`
	IgnorePublicAcls      bool `xml:"IgnorePublicAcls" json:"ignore_public_acls"`
	BlockPublicPolicy     bool `xml:"BlockPublicPolicy" json:"block_public_policy"`
	RestrictPublicBuckets bool `xml:"RestrictPublicBuckets" json:"restrict_public_buckets"`
}

// bucketInfo is a bucket row with its access configuration parsed.
type bucketInfo struct {
	Name           string
	Account        string
	OwnerCanonical string
	Region         string
	Location       string
	Created        time.Time
	Versioning     string
	ACL            *acl
	PolicyRaw      string
	Policy         *policyDoc
	Ownership      string
	PAB            publicAccessBlock
	HasPAB         bool
	Tagging        string
	CORS           string
	Lifecycle      string
	Notification   string
}

func (h *Handler) loadBucket(ctx context.Context, name string) (*bucketInfo, error) {
	var b bucketInfo
	var created int64
	var aclJSON, pab string
	err := h.st.DB().QueryRowContext(ctx, `
		SELECT b.name, b.account_id, a.canonical_id, b.region, b.location_constraint, b.created, b.versioning,
			b.acl, b.policy, b.ownership, b.public_access_block, b.tagging, b.cors, b.lifecycle, b.notification
		FROM s3_buckets b JOIN accounts a ON a.id = b.account_id WHERE b.name = ?`, name).
		Scan(&b.Name, &b.Account, &b.OwnerCanonical, &b.Region, &b.Location, &created, &b.Versioning,
			&aclJSON, &b.PolicyRaw, &b.Ownership, &pab, &b.Tagging, &b.CORS, &b.Lifecycle, &b.Notification)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoSuchBucket(name)
	}
	if err != nil {
		return nil, err
	}
	b.Created = msTime(created)
	b.ACL = parseStoredACL(aclJSON, b.OwnerCanonical)
	if b.PolicyRaw != "" {
		if p, err := parsePolicy([]byte(b.PolicyRaw), b.Name); err == nil {
			b.Policy = p
		}
	}
	if pab != "" {
		b.HasPAB = json.Unmarshal([]byte(pab), &b.PAB) == nil
	}
	return &b, nil
}

// requestKeys collects the condition context keys a request carries.
func requestKeys(req *request) map[string][]string {
	k := map[string][]string{}
	r := req.r
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		k["aws:sourceip"] = []string{host}
	}
	k["aws:securetransport"] = []string{"false"}
	if r.TLS != nil {
		k["aws:securetransport"] = []string{"true"}
	}
	if v := r.Header.Get("Referer"); v != "" {
		k["aws:referer"] = []string{v}
	}
	if v := r.Header.Get("User-Agent"); v != "" {
		k["aws:useragent"] = []string{v}
	}
	for name, vals := range r.Header {
		lower := strings.ToLower(name)
		switch {
		case lower == "x-amz-acl", strings.HasPrefix(lower, "x-amz-grant-"), lower == "x-amz-copy-source",
			lower == "x-amz-metadata-directive", strings.HasPrefix(lower, "x-amz-server-side-encryption"),
			lower == "x-amz-storage-class", lower == "x-amz-content-sha256", lower == "x-amz-object-ownership":
			k["s3:"+lower] = vals
		}
	}
	q := r.URL.Query()
	for _, p := range []string{"prefix", "delimiter", "max-keys"} {
		if v, ok := q[p]; ok {
			k["s3:"+p] = v
		}
	}
	if v := q.Get("versionId"); v != "" {
		k["s3:versionid"] = []string{v}
	}
	if t := r.Header.Get("X-Amz-Tagging"); t != "" {
		if vals, err := url.ParseQuery(t); err == nil {
			var names []string
			for tk, tv := range vals {
				k["s3:requestobjecttag/"+strings.ToLower(tk)] = tv
				names = append(names, tk)
			}
			k["s3:requestobjecttagkeys"] = names
		}
	}
	return k
}

func (h *Handler) evalRequest(req *request, action, resource string, extra map[string][]string) *evalRequest {
	e := &evalRequest{Anonymous: req.who == nil, Action: action, Resource: resource, Keys: requestKeys(req)}
	if req.who != nil {
		e.AccountID, e.UserName, e.CanonicalID = req.who.Account.ID, req.who.UserName, req.who.Account.CanonicalID
		e.Keys["aws:principalaccount"] = []string{e.AccountID}
		if req.who.Kind == "session" {
			e.UserName = "" // a session is named by its role, not a user
		}
		if !iam.IsRoot(req.who) {
			e.ARNs = iam.PrincipalARNs(req.who)
		}
	}
	for k, v := range extra {
		e.Keys[strings.ToLower(k)] = v
	}
	return e
}

func (req *request) account() string {
	if req.who == nil {
		return ""
	}
	return req.who.Account.ID
}

func (req *request) canonical() string {
	if req.who == nil {
		return ""
	}
	return req.who.Account.CanonicalID
}

// policyDecision evaluates the bucket policy, applying RestrictPublicBuckets.
func (h *Handler) policyDecision(req *request, b *bucketInfo, e *evalRequest) decision {
	d := b.Policy.evaluate(e)
	if d == decisionAllow && b.PAB.RestrictPublicBuckets && b.Policy.isPublic() && req.account() != b.Account {
		return decisionNone
	}
	return d
}

// ownerOnlyEvenIfDenied are the actions the bucket owner can always perform,
// so a bad policy can't lock the owner out of fixing it.
var ownerOnlyEvenIfDenied = map[string]bool{
	"s3:GetBucketPolicy": true, "s3:PutBucketPolicy": true, "s3:DeleteBucketPolicy": true,
}

// bucketAccess loads req.bucket and authorizes a bucket-level action.
// aclPerm is the ACL permission that also grants it ("" when only the owner
// or a policy can).
func (h *Handler) bucketAccess(req *request, action, aclPerm string) (*bucketInfo, error) {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return nil, err
	}
	return b, h.authorizeBucket(req, b, action, aclPerm, nil)
}

func (h *Handler) authorizeBucket(req *request, b *bucketInfo, action, aclPerm string, extra map[string][]string) error {
	return h.authorize(req, b, action, bucketResource(b.Name), aclPerm, extra)
}

// authorizeWrite checks an action that creates or removes key in the bucket
// (PutObject, DeleteObject, multipart): the policy sees the object ARN, the
// ACL check is WRITE on the bucket.
func (h *Handler) authorizeWrite(req *request, b *bucketInfo, key, action string) error {
	return h.authorize(req, b, action, objectResource(b.Name, key), permWrite, nil)
}

func (h *Handler) authorize(req *request, b *bucketInfo, action, resource, aclPerm string, extra map[string][]string) error {
	isOwner := req.account() == b.Account && req.who != nil
	e := h.evalRequest(req, action, resource, extra)
	d := h.policyDecision(req, b, e)
	id, err := h.identity(req, action, resource, e.Keys)
	if err != nil {
		return err
	}
	if id == iam.Deny || (d == decisionDeny && !(isOwner && iam.IsRoot(req.who) && ownerOnlyEvenIfDenied[action])) {
		return errAccessDenied()
	}
	if isOwner && (id == iam.Allow || d == decisionAllow) {
		return nil
	}
	if !isOwner && d == decisionAllow && id == iam.Allow {
		return nil
	}
	if aclPerm != "" && id == iam.Allow && b.Ownership != ownershipOwnerEnforced && b.ACL.allows(req.canonical(), aclPerm, b.PAB.IgnorePublicAcls) {
		return nil
	}
	return errAccessDenied()
}

// identity evaluates the caller's IAM identity policies. Anonymous callers
// and account roots have none to consult, so they get Allow here and are
// judged by bucket policies and ACLs alone.
func (h *Handler) identity(req *request, action, resource string, keys map[string][]string) (iam.Decision, error) {
	if h.IAM == nil || req.who == nil || iam.IsRoot(req.who) {
		return iam.Allow, nil
	}
	return h.IAM.Decide(req.ctx, req.who, action, resource, keys)
}

// requireIdentity is for actions no resource policy can grant (CreateBucket,
// ListAllMyBuckets): the identity policies alone decide.
func (h *Handler) requireIdentity(req *request, action, resource string) error {
	id, err := h.identity(req, action, resource, requestKeys(req))
	if err != nil {
		return err
	}
	if id != iam.Allow {
		return errAccessDenied()
	}
	return nil
}

// authorizeObject checks an action on an existing object version.
func (h *Handler) authorizeObject(req *request, b *bucketInfo, o *objectRow, action, aclPerm string) error {
	extra := map[string][]string{}
	for _, t := range o.Tags {
		extra["s3:ExistingObjectTag/"+t.Key] = []string{t.Value}
	}
	e := h.evalRequest(req, action, objectResource(b.Name, o.Key), extra)
	d := h.policyDecision(req, b, e)
	id, err := h.identity(req, action, objectResource(b.Name, o.Key), e.Keys)
	if err != nil {
		return err
	}
	if d == decisionDeny || id == iam.Deny {
		return errAccessDenied()
	}
	if id != iam.Allow {
		// An IAM principal without an identity allow gets in only through
		// a bucket policy that names it (same account).
		if d == decisionAllow && req.account() == b.Account && objOwnerIs(b, o, b.Account) {
			return nil
		}
		return errAccessDenied()
	}
	acct := req.account()
	objOwner := o.Owner
	if b.Ownership == ownershipOwnerEnforced {
		objOwner = b.Account
	}
	switch {
	case req.who != nil && acct == objOwner:
		// The object owner has full control, except READ through an ACL
		// that no longer grants it (READ_ACP/WRITE_ACP always remain).
		if aclPerm != permRead || b.Ownership == ownershipOwnerEnforced || o.ACL.allows(req.canonical(), permRead, false) {
			return nil
		}
	case req.who != nil && acct == b.Account && objOwner == b.Account:
		return nil
	}
	if d == decisionAllow && objOwner == b.Account {
		return nil
	}
	if aclPerm != "" && b.Ownership != ownershipOwnerEnforced && o.ACL.allows(req.canonical(), aclPerm, b.PAB.IgnorePublicAcls) {
		return nil
	}
	return errAccessDenied()
}

func objOwnerIs(b *bucketInfo, o *objectRow, account string) bool {
	return b.Ownership == ownershipOwnerEnforced || o.Owner == account
}

// objectForRead loads the bucket and the addressed object version, and
// authorizes action on it. A missing object answers 404 only to callers
// who may list the bucket; everyone else gets 403, as in S3.
func (h *Handler) objectForRead(req *request, action, aclPerm string) (*bucketInfo, *objectRow, error) {
	b, err := h.loadBucket(req.ctx, req.bucket)
	if err != nil {
		return nil, nil, err
	}
	vid, err := versionParam(req)
	if err != nil {
		return nil, nil, err
	}
	if vid != "" && (action == "s3:GetObject" || action == "s3:GetObjectAcl" || action == "s3:PutObjectAcl") {
		action += "Version"
	}
	o, err := h.loadObject(req, vid)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && (e.Code == "NoSuchKey" || e.Code == "NoSuchVersion") {
			if h.authorizeBucket(req, b, "s3:ListBucket", permRead, nil) != nil {
				return nil, nil, errAccessDenied()
			}
		}
		return nil, nil, err
	}
	if err := h.authorizeObject(req, b, o, action, aclPerm); err != nil {
		return nil, nil, err
	}
	return b, o, nil
}
