package s3

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

// Bucket policies: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
// This evaluates the subset buckets use: Effect, (Not)Principal, (Not)Action,
// (Not)Resource and Condition with the String*, Arn*, Null, Bool and
// IpAddress operators (plus IfExists and ForAnyValue/ForAllValues).

// strList is a JSON value that may be a string or a list of strings.
type strList []string

func (s *strList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = strList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// principal is "*" or a map like {"AWS": [...], "CanonicalUser": [...]}.
type principal struct {
	Any  bool
	Keys map[string]strList
}

func (p *principal) UnmarshalJSON(b []byte) error {
	var star string
	if err := json.Unmarshal(b, &star); err == nil {
		if star != "*" {
			return errMalformedPolicy("Invalid principal in policy")
		}
		p.Any = true
		return nil
	}
	return json.Unmarshal(b, &p.Keys)
}

type statement struct {
	Sid          string                        `json:"Sid"`
	Effect       string                        `json:"Effect"`
	Principal    *principal                    `json:"Principal"`
	NotPrincipal *principal                    `json:"NotPrincipal"`
	Action       strList                       `json:"Action"`
	NotAction    strList                       `json:"NotAction"`
	Resource     strList                       `json:"Resource"`
	NotResource  strList                       `json:"NotResource"`
	Condition    map[string]map[string]strList `json:"Condition"`
}

type policyDoc struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statementList []statement

func (s *statementList) UnmarshalJSON(b []byte) error {
	var one statement
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = statementList{one}
		return nil
	}
	var many []statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func errMalformedPolicy(msg string) *Error { return errf(400, "MalformedPolicy", "%s", msg) }

// parsePolicy validates a bucket policy document for bucket.
func parsePolicy(doc []byte, bucket string) (*policyDoc, error) {
	var raw struct {
		Version   string        `json:"Version"`
		Statement statementList `json:"Statement"`
	}
	if err := json.Unmarshal(doc, &raw); err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, e
		}
		return nil, errMalformedPolicy("Policies must be valid JSON and the first byte must be '{'")
	}
	if len(raw.Statement) == 0 {
		return nil, errMalformedPolicy("Missing required field Statement")
	}
	for _, st := range raw.Statement {
		if st.Effect != "Allow" && st.Effect != "Deny" {
			return nil, errMalformedPolicy("Invalid effect: " + st.Effect)
		}
		if st.Principal == nil && st.NotPrincipal == nil {
			return nil, errMalformedPolicy("Missing required field Principal")
		}
		if len(st.Action) == 0 && len(st.NotAction) == 0 {
			return nil, errMalformedPolicy("Missing required field Action")
		}
		if len(st.Resource) == 0 && len(st.NotResource) == 0 {
			return nil, errMalformedPolicy("Missing required field Resource")
		}
		for _, r := range append(append(strList{}, st.Resource...), st.NotResource...) {
			if !resourceInBucket(r, bucket) {
				return nil, errMalformedPolicy("Policy has invalid resource")
			}
		}
	}
	return &policyDoc{Version: raw.Version, Statement: raw.Statement}, nil
}

// resourceInBucket reports whether a Resource ARN can refer to this bucket
// or its objects (a bucket policy may not govern other buckets).
func resourceInBucket(arn, bucket string) bool {
	rest, ok := strings.CutPrefix(arn, "arn:aws:s3:::")
	if !ok {
		return arn == "*"
	}
	b, _, _ := strings.Cut(rest, "/")
	return globMatch(b, bucket, false)
}

// evalRequest is the request context a policy is evaluated against.
type evalRequest struct {
	Anonymous   bool
	AccountID   string // requester's account (empty when anonymous)
	UserName    string
	CanonicalID string
	// ARNs are the IAM ARNs the requester can be named by in a Principal
	// element (user, role and assumed-role ARNs).
	ARNs     []string
	Action   string // e.g. "s3:GetObject"
	Resource string // e.g. "arn:aws:s3:::bucket/key"
	// Keys holds condition context keys, lowercased (e.g. "s3:prefix").
	Keys map[string][]string
}

type decision int

const (
	decisionNone decision = iota
	decisionAllow
	decisionDeny
)

// evaluate returns Deny if any matching statement denies, else Allow if any
// allows, else None (fall through to ACLs / implicit deny).
func (p *policyDoc) evaluate(r *evalRequest) decision {
	if p == nil {
		return decisionNone
	}
	out := decisionNone
	for i := range p.Statement {
		st := &p.Statement[i]
		if !st.matches(r) {
			continue
		}
		if st.Effect == "Deny" {
			return decisionDeny
		}
		out = decisionAllow
	}
	return out
}

func (st *statement) matches(r *evalRequest) bool {
	if st.Principal != nil && !principalMatches(st.Principal, r) {
		return false
	}
	if st.NotPrincipal != nil && principalMatches(st.NotPrincipal, r) {
		return false
	}
	if len(st.Action) > 0 && !anyGlob(st.Action, r.Action, true) {
		return false
	}
	if len(st.NotAction) > 0 && anyGlob(st.NotAction, r.Action, true) {
		return false
	}
	if len(st.Resource) > 0 && !anyGlob(st.Resource, r.Resource, false) {
		return false
	}
	if len(st.NotResource) > 0 && anyGlob(st.NotResource, r.Resource, false) {
		return false
	}
	for op, kv := range st.Condition {
		for key, vals := range kv {
			if !evalCondition(op, strings.ToLower(key), vals, r.Keys) {
				return false
			}
		}
	}
	return true
}

func principalMatches(p *principal, r *evalRequest) bool {
	if p.Any {
		return true
	}
	for kind, vals := range p.Keys {
		for _, v := range vals {
			switch kind {
			case "AWS":
				if v == "*" {
					return true
				}
				if r.Anonymous {
					continue
				}
				if v == r.AccountID || v == "arn:aws:iam::"+r.AccountID+":root" ||
					(r.UserName != "" && v == "arn:aws:iam::"+r.AccountID+":user/"+r.UserName) {
					return true
				}
				for _, arn := range r.ARNs {
					if v == arn {
						return true
					}
				}
			case "CanonicalUser":
				if !r.Anonymous && v == r.CanonicalID {
					return true
				}
			}
		}
	}
	return false
}

func anyGlob(patterns []string, s string, fold bool) bool {
	for _, p := range patterns {
		if globMatch(p, s, fold) {
			return true
		}
	}
	return false
}

// globMatch matches IAM wildcards: '*' any run, '?' one character.
func globMatch(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	// Iterative wildcard match with backtracking to the last '*'.
	p, i, star, mark := 0, 0, -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// evalCondition applies one condition operator to one context key.
func evalCondition(op, key string, want []string, keys map[string][]string) bool {
	qualifier := ""
	if q, rest, ok := strings.Cut(op, ":"); ok {
		qualifier, op = q, rest
	}
	ifExists := strings.HasSuffix(op, "IfExists")
	op = strings.TrimSuffix(op, "IfExists")
	have, present := keys[key]

	if op == "Null" {
		wantNull := len(want) > 0 && strings.EqualFold(want[0], "true")
		return wantNull == !present
	}
	if !present {
		if ifExists {
			return true
		}
		// A negated operator is satisfied when the key is absent.
		return strings.Contains(op, "Not")
	}

	negated := strings.Contains(op, "Not")
	base := strings.Replace(op, "Not", "", 1)
	match := func(h string) bool {
		for _, w := range want {
			if valueMatches(base, h, w) {
				return true
			}
		}
		return false
	}
	switch qualifier {
	case "ForAllValues":
		for _, h := range have {
			if match(h) == negated {
				return false
			}
		}
		return true
	default: // single-valued keys and ForAnyValue
		for _, h := range have {
			if match(h) != negated {
				return true
			}
		}
		return false
	}
}

func valueMatches(op, have, want string) bool {
	switch op {
	case "StringEquals", "ArnEquals":
		return have == want
	case "StringEqualsIgnoreCase":
		return strings.EqualFold(have, want)
	case "StringLike", "ArnLike":
		return globMatch(want, have, false)
	case "Bool":
		return strings.EqualFold(have, want)
	case "IpAddress":
		_, cidr, err := net.ParseCIDR(want)
		if err != nil {
			return have == want
		}
		ip := net.ParseIP(have)
		return ip != nil && cidr.Contains(ip)
	}
	return false
}

// isPublic reports whether the policy grants access to everyone without a
// condition that pins it to known sources (S3's "public policy" rule, simplified).
func (p *policyDoc) isPublic() bool {
	if p == nil {
		return false
	}
	for _, st := range p.Statement {
		if st.Effect != "Allow" || st.Principal == nil || !principalIsEveryone(st.Principal) {
			continue
		}
		if !conditionRestricts(st.Condition) {
			return true
		}
	}
	return false
}

func principalIsEveryone(p *principal) bool {
	if p.Any {
		return true
	}
	for _, v := range p.Keys["AWS"] {
		if v == "*" {
			return true
		}
	}
	return false
}

// conditionRestricts is true when a condition limits access to fixed
// accounts, sources or networks, which makes an Allow-* statement non-public.
func conditionRestricts(c map[string]map[string]strList) bool {
	restricting := map[string]bool{
		"aws:sourceip": true, "aws:sourcearn": true, "aws:sourceaccount": true, "aws:sourcevpc": true,
		"aws:sourcevpce": true, "aws:principalaccount": true, "aws:principalarn": true,
		"aws:principalorgid": true, "aws:userid": true, "s3:dataaccesspointaccount": true,
	}
	for op, kv := range c {
		if strings.Contains(op, "Not") || strings.HasSuffix(op, "IfExists") {
			continue
		}
		for k, vals := range kv {
			if !restricting[strings.ToLower(k)] {
				continue
			}
			for _, v := range vals {
				if strings.Contains(v, "*") {
					return false
				}
			}
			return true
		}
	}
	return false
}

// objectResource / bucketResource build the ARNs policies are matched against.
func bucketResource(bucket string) string      { return "arn:aws:s3:::" + bucket }
func objectResource(bucket, key string) string { return "arn:aws:s3:::" + bucket + "/" + key }
