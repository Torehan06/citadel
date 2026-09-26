package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"citadel/internal/sigv4"
	"citadel/internal/store"
)

// Session is what an STS session credential stands for.
type Session struct {
	Kind        string // "role" (AssumeRole) or "user" (GetSessionToken)
	RoleARN     string `json:",omitempty"`
	RoleID      string `json:",omitempty"`
	RoleName    string `json:",omitempty"`
	SessionName string `json:",omitempty"`
	UserName    string `json:",omitempty"` // Kind "user": "" means the account root
	Policy      string `json:",omitempty"` // inline session policy
	PolicyARNs  []string
	SourceARN   string `json:",omitempty"` // who created the session
}

func sessionOf(p *store.Principal) *Session {
	if p == nil || p.Kind != "session" || p.Session == "" {
		return nil
	}
	var s Session
	if json.Unmarshal([]byte(p.Session), &s) != nil {
		return nil
	}
	return &s
}

// IsRoot reports whether p acts as its account's root user. Bootstrap
// identities do; so do session credentials a root caller got from
// GetSessionToken.
func IsRoot(p *store.Principal) bool {
	if p == nil {
		return false
	}
	switch p.Kind {
	case "", "root":
		return true
	case "session":
		s := sessionOf(p)
		return s != nil && s.Kind == "user" && s.UserName == ""
	}
	return false
}

// Identity describes the caller as GetCallerIdentity does.
func Identity(p *store.Principal) (arn, userID string) {
	acct := p.Account.ID
	switch p.Kind {
	case "user":
		return "arn:aws:iam::" + acct + ":user/" + p.UserName, ""
	case "session":
		if s := sessionOf(p); s != nil {
			if s.Kind == "role" {
				return "arn:aws:sts::" + acct + ":assumed-role/" + s.RoleName + "/" + s.SessionName, s.RoleID + ":" + s.SessionName
			}
			if s.UserName != "" {
				return "arn:aws:sts::" + acct + ":federated-user/" + s.UserName, ""
			}
		}
	}
	return "arn:aws:iam::" + acct + ":root", acct
}

// PrincipalARNs are the ARNs a resource or trust policy may name p by.
func PrincipalARNs(p *store.Principal) []string {
	if p == nil {
		return nil
	}
	acct := p.Account.ID
	switch p.Kind {
	case "user":
		return []string{"arn:aws:iam::" + acct + ":user/" + p.UserName}
	case "session":
		if s := sessionOf(p); s != nil {
			if s.Kind == "role" {
				return []string{s.RoleARN, "arn:aws:sts::" + acct + ":assumed-role/" + s.RoleName + "/" + s.SessionName}
			}
			if s.UserName != "" {
				return []string{"arn:aws:iam::" + acct + ":user/" + s.UserName}
			}
		}
	}
	return []string{"arn:aws:iam::" + acct + ":root"}
}

// Authorizer evaluates identity-based policies for the data-plane services.
type Authorizer struct {
	st *store.Store
}

// Authorizer returns the authorizer backed by this handler's store.
func (h *Handler) Authorizer() *Authorizer { return &Authorizer{st: h.st} }

// Decide evaluates the caller's identity policies for one action. Root
// principals are allowed everything in their own account. For IAM users and
// role sessions it returns Deny on an explicit deny, Allow when the
// identity policies allow and every permissions boundary and session policy
// allows too, and NoMatch otherwise.
func (a *Authorizer) Decide(ctx context.Context, p *store.Principal, action, resource string, extra map[string][]string) (Decision, error) {
	if p == nil {
		return NoMatch, nil
	}
	if IsRoot(p) {
		return Allow, nil
	}
	req := &Request{Action: action, Resource: resource, Account: p.Account.ID, Principals: PrincipalARNs(p), Context: baseContext(p)}
	for k, v := range extra {
		req.Context[strings.ToLower(k)] = v
	}
	acct := p.Account.ID
	var identity []string // identity policy documents
	var gates [][]string  // each gate must also allow: boundaries, session policies
	switch p.Kind {
	case "user":
		docs, boundary, err := a.userPolicies(ctx, acct, p.UserName)
		if err != nil {
			return NoMatch, err
		}
		identity = docs
		if boundary != nil {
			gates = append(gates, boundary)
		}
	case "session":
		s := sessionOf(p)
		if s == nil {
			return NoMatch, nil
		}
		if s.Kind == "user" {
			docs, boundary, err := a.userPolicies(ctx, acct, s.UserName)
			if err != nil {
				return NoMatch, err
			}
			identity = docs
			if boundary != nil {
				gates = append(gates, boundary)
			}
			break
		}
		var r Role
		ok, err := load(ctx, a.st.DB(), acct, kRole, nameKey(s.RoleName), &r)
		if err != nil {
			return NoMatch, err
		}
		if !ok || r.ID != s.RoleID {
			return NoMatch, nil // the role was deleted (or replaced) after the session began
		}
		identity, err = a.holderPolicies(ctx, acct, r.InlineOrder, r.Inline, r.Attached)
		if err != nil {
			return NoMatch, err
		}
		if r.Boundary != "" {
			gates = append(gates, a.policyDocs(ctx, acct, []string{r.Boundary}))
		}
		if s.Policy != "" || len(s.PolicyARNs) > 0 {
			sp := a.policyDocs(ctx, acct, s.PolicyARNs)
			if s.Policy != "" {
				sp = append(sp, s.Policy)
			}
			gates = append(gates, sp)
		}
	default:
		return NoMatch, nil
	}
	decision := evaluateAll(identity, req)
	if decision == Deny {
		return Deny, nil
	}
	for _, g := range gates {
		switch evaluateAll(g, req) {
		case Deny:
			return Deny, nil
		case NoMatch:
			decision = NoMatch
		}
	}
	return decision, nil
}

func evaluateAll(docs []string, req *Request) Decision {
	out := NoMatch
	for _, d := range docs {
		doc, err := ParseDocument(d)
		if err != nil {
			continue
		}
		switch doc.Evaluate(req) {
		case Deny:
			return Deny
		case Allow:
			out = Allow
		}
	}
	return out
}

func baseContext(p *store.Principal) map[string][]string {
	arn, uid := Identity(p)
	now := time.Now().UTC()
	ctx := map[string][]string{
		"aws:principalarn":     {arn},
		"aws:principalaccount": {p.Account.ID},
		"aws:currenttime":      {now.Format(time.RFC3339)},
		"aws:epochtime":        {strconv.FormatInt(now.Unix(), 10)},
		"aws:securetransport":  {"false"},
	}
	if uid != "" {
		ctx["aws:userid"] = []string{uid}
	}
	switch p.Kind {
	case "user":
		ctx["aws:username"] = []string{p.UserName}
		ctx["aws:principaltype"] = []string{"User"}
	case "session":
		ctx["aws:principaltype"] = []string{"AssumedRole"}
		if s := sessionOf(p); s != nil && s.Kind == "user" && s.UserName != "" {
			ctx["aws:username"] = []string{s.UserName}
			ctx["aws:principaltype"] = []string{"User"}
		}
	}
	return ctx
}

// userPolicies returns a user's identity policies (its own and its groups')
// and its permissions boundary documents (nil when it has none).
func (a *Authorizer) userPolicies(ctx context.Context, acct, name string) ([]string, []string, error) {
	var u User
	ok, err := load(ctx, a.st.DB(), acct, kUser, nameKey(name), &u)
	if err != nil || !ok {
		return nil, nil, err
	}
	docs, err := a.holderPolicies(ctx, acct, u.InlineOrder, u.Inline, u.Attached)
	if err != nil {
		return nil, nil, err
	}
	if len(u.Groups) > 0 {
		groups, err := loadAll[Group](ctx, a.st.DB(), acct, kGroup)
		if err != nil {
			return nil, nil, err
		}
		for _, g := range groups {
			if contains(u.Groups, g.ID) {
				more, err := a.holderPolicies(ctx, acct, g.InlineOrder, g.Inline, g.Attached)
				if err != nil {
					return nil, nil, err
				}
				docs = append(docs, more...)
			}
		}
	}
	var boundary []string
	if u.Boundary != "" {
		boundary = a.policyDocs(ctx, acct, []string{u.Boundary})
	}
	return docs, boundary, nil
}

func (a *Authorizer) holderPolicies(ctx context.Context, acct string, order []string, inline map[string]string, attached []string) ([]string, error) {
	var docs []string
	for _, n := range order {
		docs = append(docs, inline[n])
	}
	return append(docs, a.policyDocs(ctx, acct, attached)...), nil
}

// policyDocs returns the default-version documents of managed policies.
// A missing policy contributes nothing (for a boundary: nothing is allowed).
func (a *Authorizer) policyDocs(ctx context.Context, acct string, arns []string) []string {
	var docs []string
	for _, arn := range arns {
		p := awsManaged(arn)
		if p == nil {
			var cp Policy
			ok, err := load(ctx, a.st.DB(), acct, kPolicy, arn, &cp)
			if err != nil || !ok {
				continue
			}
			p = &cp
		}
		for _, v := range p.Versions {
			if v.ID == p.Default {
				docs = append(docs, v.Document)
			}
		}
	}
	return docs
}

// DeniedMessage is AWS's wording for an identity-policy denial.
func DeniedMessage(p *store.Principal, action, resource string, explicit bool) string {
	arn, _ := Identity(p)
	why := "because no identity-based policy allows the " + action + " action"
	if explicit {
		why = "with an explicit deny in an identity-based policy"
	}
	return fmt.Sprintf("User: %s is not authorized to perform: %s on resource: %s %s", arn, action, resource, why)
}

// CheckSession is the SigV4 verifier's session hook: temporary credentials
// must present their session token and be unexpired, and an IAM user's key
// records when and where it was last used.
func (h *Handler) CheckSession(ctx context.Context, a *sigv4.Auth) error {
	_, p, err := h.st.LookupKey(ctx, a.AccessKey)
	if err != nil {
		return nil // unknown keys were already rejected by the signature check
	}
	switch p.Kind {
	case "session":
		if a.SessionToken == "" || a.SessionToken != p.SessionToken {
			return sigv4.Errorf(403, "InvalidClientTokenId", "The security token included in the request is invalid.")
		}
		if h.now().UnixMilli() > p.Expires {
			return sigv4.Errorf(400, "ExpiredToken", "The security token included in the request is expired")
		}
	case "user":
		if a.SessionToken != "" {
			return sigv4.Errorf(403, "InvalidClientTokenId", "The security token included in the request is invalid.")
		}
		region := a.Region
		if region == "" {
			region = h.region
		}
		_ = h.st.Update(ctx, func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE access_keys SET last_used=?, last_service=?, last_region=? WHERE access_key=?`,
				h.now().UnixMilli(), a.Service, region, a.AccessKey)
			return err
		})
	}
	return nil
}

// Denial says which resource an identity-policy check refused, and whether
// an explicit Deny did it.
type Denial struct {
	Action, Resource string
	Explicit         bool
}

// Require checks action on every resource and returns the first denial, or
// nil when the identity policies allow them all. A nil Authorizer allows
// everything (unit tests and tools that run without IAM).
func (a *Authorizer) Require(ctx context.Context, p *store.Principal, action string, resources []string, extra map[string][]string) (*Denial, error) {
	if a == nil || p == nil || IsRoot(p) {
		return nil, nil
	}
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	for _, r := range resources {
		d, err := a.Decide(ctx, p, action, r, extra)
		if err != nil {
			return nil, err
		}
		if d != Allow {
			return &Denial{Action: action, Resource: r, Explicit: d == Deny}, nil
		}
	}
	return nil, nil
}

// RoleByARN returns the role an ARN names in account, or nil if there is none
// (other services check execution roles with it, e.g. Lambda's CreateFunction).
func (a *Authorizer) RoleByARN(ctx context.Context, account, arn string) (*Role, error) {
	name := arn[strings.LastIndexByte(arn, '/')+1:]
	var r Role
	ok, err := load(ctx, a.st.DB(), account, kRole, nameKey(name), &r)
	if err != nil || !ok || r.ARN != arn {
		return nil, err
	}
	return &r, nil
}
