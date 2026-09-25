package s3

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"

	"citadel/internal/store"
)

// Access control lists: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html

const (
	groupAllUsers    = "http://acs.amazonaws.com/groups/global/AllUsers"
	groupAuthUsers   = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	groupLogDelivery = "http://acs.amazonaws.com/groups/s3/LogDelivery"

	permFullControl = "FULL_CONTROL"
	permRead        = "READ"
	permWrite       = "WRITE"
	permReadACP     = "READ_ACP"
	permWriteACP    = "WRITE_ACP"

	// Object ownership modes (PutBucketOwnershipControls).
	ownershipObjectWriter    = "ObjectWriter"
	ownershipOwnerPreferred  = "BucketOwnerPreferred"
	ownershipOwnerEnforced   = "BucketOwnerEnforced"
	cannedBucketOwnerFullCtl = "bucket-owner-full-control"
)

// grant is one ACL entry. Grantees are stored resolved: email grants become
// canonical users, as S3 reports them.
type grant struct {
	Type       string `json:"type"` // CanonicalUser | Group
	ID         string `json:"id,omitempty"`
	URI        string `json:"uri,omitempty"`
	Permission string `json:"perm"`
}

type acl struct {
	Owner  string  `json:"owner"` // canonical ID
	Grants []grant `json:"grants"`
}

// privateACL is the default: the owner has full control.
func privateACL(owner string) *acl {
	return &acl{Owner: owner, Grants: []grant{{Type: "CanonicalUser", ID: owner, Permission: permFullControl}}}
}

func parseStoredACL(s, owner string) *acl {
	if s == "" {
		return privateACL(owner)
	}
	var a acl
	if json.Unmarshal([]byte(s), &a) != nil {
		return privateACL(owner)
	}
	return &a
}

func (a *acl) json() string {
	b, _ := json.Marshal(a)
	return string(b)
}

// cannedACL expands a canned ACL name. bucketOwner is used by the
// bucket-owner-* object ACLs.
func cannedACL(name, owner, bucketOwner string) (*acl, error) {
	// S3 lists the extra grants first and the owner's FULL_CONTROL last.
	a := &acl{Owner: owner}
	add := func(g grant) { a.Grants = append(a.Grants, g) }
	switch name {
	case "private":
	case "public-read":
		add(grant{Type: "Group", URI: groupAllUsers, Permission: permRead})
	case "public-read-write":
		add(grant{Type: "Group", URI: groupAllUsers, Permission: permRead})
		add(grant{Type: "Group", URI: groupAllUsers, Permission: permWrite})
	case "authenticated-read":
		add(grant{Type: "Group", URI: groupAuthUsers, Permission: permRead})
	case "log-delivery-write":
		add(grant{Type: "Group", URI: groupLogDelivery, Permission: permWrite})
		add(grant{Type: "Group", URI: groupLogDelivery, Permission: permReadACP})
	case "bucket-owner-read":
		if bucketOwner != owner {
			add(grant{Type: "CanonicalUser", ID: bucketOwner, Permission: permRead})
		}
	case cannedBucketOwnerFullCtl:
		if bucketOwner != owner {
			add(grant{Type: "CanonicalUser", ID: bucketOwner, Permission: permFullControl})
		}
	default:
		return nil, errInvalidArgument("Invalid canned ACL %q", name)
	}
	add(grant{Type: "CanonicalUser", ID: owner, Permission: permFullControl})
	return a, nil
}

var grantHeaders = map[string]string{
	"X-Amz-Grant-Read":         permRead,
	"X-Amz-Grant-Write":        permWrite,
	"X-Amz-Grant-Read-Acp":     permReadACP,
	"X-Amz-Grant-Write-Acp":    permWriteACP,
	"X-Amz-Grant-Full-Control": permFullControl,
}

// aclFromRequest builds the ACL a request asks for with x-amz-acl or
// x-amz-grant-* headers. It returns nil when the request names none.
func (h *Handler) aclFromRequest(ctx context.Context, r *http.Request, owner, bucketOwner string) (*acl, error) {
	canned := r.Header.Get("X-Amz-Acl")
	var granted bool
	for hdr := range grantHeaders {
		if r.Header.Get(hdr) != "" {
			granted = true
		}
	}
	if canned != "" && granted {
		return nil, errf(400, "InvalidRequest", "Specifying both Canned ACLs and Header Grants is not allowed")
	}
	if canned != "" {
		return cannedACL(canned, owner, bucketOwner)
	}
	if !granted {
		return nil, nil
	}
	a := &acl{Owner: owner}
	for hdr, perm := range grantHeaders {
		v := r.Header.Get(hdr)
		if v == "" {
			continue
		}
		for _, item := range strings.Split(v, ",") {
			k, val, ok := strings.Cut(strings.TrimSpace(item), "=")
			if !ok {
				return nil, errInvalidArgument("Invalid grant header %s", hdr)
			}
			val = strings.Trim(strings.TrimSpace(val), `"`)
			g, err := h.resolveGrantee(ctx, strings.ToLower(strings.TrimSpace(k)), val)
			if err != nil {
				return nil, err
			}
			g.Permission = perm
			a.Grants = append(a.Grants, g)
		}
	}
	return a, nil
}

// resolveGrantee turns id=, emailAddress= or uri= into a stored grantee.
func (h *Handler) resolveGrantee(ctx context.Context, kind, val string) (grant, error) {
	switch kind {
	case "id":
		if _, err := h.st.AccountByCanonicalID(ctx, val); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return grant{}, errInvalidArgument("Invalid id")
			}
			return grant{}, err
		}
		return grant{Type: "CanonicalUser", ID: val}, nil
	case "emailaddress":
		a, err := h.st.AccountByEmail(ctx, val)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return grant{}, errf(400, "UnresolvableGrantByEmailAddress", "The email address you provided does not match any account on record.")
			}
			return grant{}, err
		}
		return grant{Type: "CanonicalUser", ID: a.CanonicalID}, nil
	case "uri":
		switch val {
		case groupAllUsers, groupAuthUsers, groupLogDelivery:
			return grant{Type: "Group", URI: val}, nil
		}
		return grant{}, errInvalidArgument("Invalid group uri")
	}
	return grant{}, errInvalidArgument("Invalid grantee type %q", kind)
}

// allows reports whether the ACL gives perm to the requester.
// canonical is "" for anonymous requests.
func (a *acl) allows(canonical, perm string, ignorePublic bool) bool {
	for _, g := range a.Grants {
		if g.Permission != perm && g.Permission != permFullControl {
			continue
		}
		switch {
		case g.Type == "CanonicalUser" && canonical != "" && g.ID == canonical:
			return true
		case g.Type == "Group" && g.URI == groupAllUsers && !ignorePublic:
			return true
		case g.Type == "Group" && g.URI == groupAuthUsers && canonical != "" && !ignorePublic:
			return true
		}
	}
	return false
}

// isPublic: grants to AllUsers or AuthenticatedUsers.
func (a *acl) isPublic() bool {
	for _, g := range a.Grants {
		if g.Type == "Group" && (g.URI == groupAllUsers || g.URI == groupAuthUsers) {
			return true
		}
	}
	return false
}

// onlyOwner: nothing beyond the owner's own grants (what BucketOwnerEnforced allows).
func (a *acl) onlyOwner() bool {
	for _, g := range a.Grants {
		if g.Type != "CanonicalUser" || g.ID != a.Owner {
			return false
		}
	}
	return true
}

// ---- XML ------------------------------------------------------------------

type xmlGrantee struct {
	XMLNS        string `xml:"xmlns:xsi,attr,omitempty"`
	Type         string `xml:"xsi:type,attr"`
	ID           string `xml:"ID,omitempty"`
	DisplayName  string `xml:"DisplayName,omitempty"`
	URI          string `xml:"URI,omitempty"`
	EmailAddress string `xml:"EmailAddress,omitempty"`
}

type xmlGrant struct {
	Grantee    xmlGrantee `xml:"Grantee"`
	Permission string     `xml:"Permission"`
}

type accessControlPolicy struct {
	XMLName xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy"`
	Owner   owner      `xml:"Owner"`
	Grants  []xmlGrant `xml:"AccessControlList>Grant"`
}

// For parsing, the xsi:type attribute arrives namespaced.
type accessControlPolicyIn struct {
	Owner struct {
		ID string `xml:"ID"`
	} `xml:"Owner"`
	Grants []struct {
		Grantee struct {
			Type         string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			ID           string `xml:"ID"`
			URI          string `xml:"URI"`
			EmailAddress string `xml:"EmailAddress"`
		} `xml:"Grantee"`
		Permission string `xml:"Permission"`
	} `xml:"AccessControlList>Grant"`
}

func (h *Handler) aclXML(ctx context.Context, a *acl) accessControlPolicy {
	ow := &owners{h: h, ctx: ctx}
	name := func(canonical string) string {
		if acct, err := h.st.AccountByCanonicalID(ctx, canonical); err == nil {
			return ow.get(acct.ID).DisplayName
		}
		return ""
	}
	out := accessControlPolicy{Owner: owner{ID: a.Owner, DisplayName: name(a.Owner)}}
	for _, g := range a.Grants {
		xg := xmlGrant{Permission: g.Permission, Grantee: xmlGrantee{
			XMLNS: "http://www.w3.org/2001/XMLSchema-instance", Type: g.Type,
		}}
		if g.Type == "CanonicalUser" {
			xg.Grantee.ID, xg.Grantee.DisplayName = g.ID, name(g.ID)
		} else {
			xg.Grantee.URI = g.URI
		}
		out.Grants = append(out.Grants, xg)
	}
	return out
}

// aclFromBody parses a PutBucketAcl/PutObjectAcl body.
func (h *Handler) aclFromBody(ctx context.Context, body []byte, owner string) (*acl, error) {
	var in accessControlPolicyIn
	if err := xml.Unmarshal(body, &in); err != nil {
		return nil, errMalformedXML()
	}
	if in.Owner.ID != "" && in.Owner.ID != owner {
		return nil, errAccessDenied()
	}
	a := &acl{Owner: owner}
	for _, g := range in.Grants {
		switch g.Permission {
		case permFullControl, permRead, permWrite, permReadACP, permWriteACP:
		default:
			return nil, errMalformedACL()
		}
		var r grant
		var err error
		switch g.Grantee.Type {
		case "CanonicalUser":
			r, err = h.resolveGrantee(ctx, "id", g.Grantee.ID)
		case "AmazonCustomerByEmail":
			r, err = h.resolveGrantee(ctx, "emailaddress", g.Grantee.EmailAddress)
		case "Group":
			r, err = h.resolveGrantee(ctx, "uri", g.Grantee.URI)
		default:
			return nil, errMalformedACL()
		}
		if err != nil {
			return nil, err
		}
		r.Permission = g.Permission
		a.Grants = append(a.Grants, r)
	}
	return a, nil
}

func errMalformedACL() *Error {
	return errf(400, "MalformedACLError", "The XML you provided was not well-formed or did not validate against our published schema")
}

func errACLNotSupported() *Error {
	return errf(400, "AccessControlListNotSupported", "The bucket does not allow ACLs")
}

// requestedACL reads the new ACL of a Put*Acl request from its headers or body.
func (h *Handler) requestedACL(req *request, owner, bucketOwner string) (*acl, error) {
	a, err := h.aclFromRequest(req.ctx, req.r, owner, bucketOwner)
	if err != nil || a != nil {
		return a, err
	}
	body, err := readSmallBody(req, 256<<10, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil, errMalformedACL()
	}
	return h.aclFromBody(req.ctx, body, owner)
}

// ---- handlers ---------------------------------------------------------------

func (h *Handler) getBucketACL(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketAcl", permReadACP)
	if err != nil {
		return err
	}
	a := b.ACL
	if b.Ownership == ownershipOwnerEnforced {
		a = privateACL(b.OwnerCanonical)
	}
	writeXML(req.w, http.StatusOK, h.aclXML(req.ctx, a))
	return nil
}

func (h *Handler) putBucketACL(req *request) error {
	b, err := h.bucketAccess(req, "s3:PutBucketAcl", permWriteACP)
	if err != nil {
		return err
	}
	a, err := h.requestedACL(req, b.OwnerCanonical, b.OwnerCanonical)
	if err != nil {
		return err
	}
	if b.Ownership == ownershipOwnerEnforced && !a.onlyOwner() {
		return errACLNotSupported()
	}
	if a.isPublic() && b.PAB.BlockPublicAcls {
		return errAccessDenied()
	}
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx, `UPDATE s3_buckets SET acl = ? WHERE name = ?`, a.json(), req.bucket); err != nil {
			return err
		}
		return tx.Change("s3", "PutBucketAcl", req.bucket, nil)
	})
	if err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) getObjectACL(req *request) error {
	b, o, err := h.objectForRead(req, "s3:GetObjectAcl", permReadACP)
	if err != nil {
		return err
	}
	a := o.ACL
	if b.Ownership == ownershipOwnerEnforced {
		a = privateACL(b.OwnerCanonical)
	}
	if b.Versioning != "" {
		req.w.Header().Set("x-amz-version-id", o.VersionID)
	}
	writeXML(req.w, http.StatusOK, h.aclXML(req.ctx, a))
	return nil
}

func (h *Handler) putObjectACL(req *request) error {
	b, o, err := h.objectForRead(req, "s3:PutObjectAcl", permWriteACP)
	if err != nil {
		return err
	}
	a, err := h.requestedACL(req, o.ACL.Owner, b.OwnerCanonical)
	if err != nil {
		return err
	}
	if b.Ownership == ownershipOwnerEnforced && !a.onlyOwner() {
		return errACLNotSupported()
	}
	if a.isPublic() && b.PAB.BlockPublicAcls {
		return errAccessDenied()
	}
	err = h.st.Update(req.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(req.ctx, `UPDATE s3_objects SET acl = ? WHERE bucket = ? AND key = ? AND version_id = ?`,
			a.json(), req.bucket, req.key, o.VersionID); err != nil {
			return err
		}
		return tx.Change("s3", "PutObjectAcl", req.bucket+"/"+req.key, map[string]string{"version": o.VersionID})
	})
	if err != nil {
		return err
	}
	if b.Versioning != "" {
		req.w.Header().Set("x-amz-version-id", o.VersionID)
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}
