package iam

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"
)

// Decision is the outcome of evaluating policies against a request.
type Decision int

const (
	// NoMatch means no statement applied: an implicit deny unless something
	// else allows the request.
	NoMatch Decision = iota
	Allow
	Deny
)

func (d Decision) String() string {
	return [...]string{"NoMatch", "Allow", "Deny"}[d]
}

// Request is what a policy is evaluated against.
type Request struct {
	Action   string // "s3:GetObject"
	Resource string // "arn:aws:s3:::bucket/key"
	// Principal describes the caller for Principal elements (resource and
	// trust policies): its account and the ARNs it can be named by.
	Account    string
	Principals []string
	// Context holds condition keys, matched without regard to case.
	Context map[string][]string
}

// Document is a parsed policy document.
type Document struct {
	Statements []Statement
}

type Statement struct {
	Effect                   string
	Action, NotAction        []string
	Resource, NotResource    []string
	Principal, NotPrincipal  *Principals
	Condition                map[string]map[string][]string
	hasAction, hasNotAction  bool
	hasResource, hasNotRes   bool
	hasPrincipal, hasNotPrin bool
}

// Principals is a Principal element: "*" or a map of kind → values.
type Principals struct {
	Any   bool
	Kinds map[string][]string
}

// ParseDocument parses a policy document. It is lenient about shape (a
// single string where a list is allowed) but rejects what it cannot read.
func ParseDocument(doc string) (*Document, error) {
	var raw struct {
		Statement json.RawMessage
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return nil, err
	}
	var list []json.RawMessage
	trimmed := bytes.TrimSpace(raw.Statement)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		list = []json.RawMessage{raw.Statement}
	} else if len(trimmed) > 0 {
		if err := json.Unmarshal(raw.Statement, &list); err != nil {
			return nil, err
		}
	}
	d := &Document{}
	for _, r := range list {
		var s map[string]json.RawMessage
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, err
		}
		var st Statement
		if err := json.Unmarshal(s["Effect"], &st.Effect); err != nil {
			return nil, err
		}
		var err error
		st.Action, st.hasAction, err = stringList(s, "Action")
		if err != nil {
			return nil, err
		}
		if st.NotAction, st.hasNotAction, err = stringList(s, "NotAction"); err != nil {
			return nil, err
		}
		if st.Resource, st.hasResource, err = stringList(s, "Resource"); err != nil {
			return nil, err
		}
		if st.NotResource, st.hasNotRes, err = stringList(s, "NotResource"); err != nil {
			return nil, err
		}
		if st.Principal, err = parsePrincipal(s["Principal"]); err != nil {
			return nil, err
		}
		if st.NotPrincipal, err = parsePrincipal(s["NotPrincipal"]); err != nil {
			return nil, err
		}
		st.hasPrincipal, st.hasNotPrin = st.Principal != nil, st.NotPrincipal != nil
		if c, ok := s["Condition"]; ok {
			var cond map[string]map[string]json.RawMessage
			if err := json.Unmarshal(c, &cond); err != nil {
				return nil, err
			}
			st.Condition = map[string]map[string][]string{}
			for op, block := range cond {
				st.Condition[op] = map[string][]string{}
				for k, v := range block {
					vals, err := scalarList(v)
					if err != nil {
						return nil, err
					}
					st.Condition[op][k] = vals
				}
			}
		}
		d.Statements = append(d.Statements, st)
	}
	return d, nil
}

func stringList(s map[string]json.RawMessage, key string) ([]string, bool, error) {
	v, ok := s[key]
	if !ok {
		return nil, false, nil
	}
	vals, err := scalarList(v)
	return vals, true, err
}

// scalarList reads a string, number, bool or a list of them as strings.
func scalarList(raw json.RawMessage) ([]string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var items []any
	if l, ok := v.([]any); ok {
		items = l
	} else {
		items = []any{v}
	}
	out := make([]string, 0, len(items))
	for _, x := range items {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case json.Number:
			out = append(out, t.String())
		case bool:
			out = append(out, strconv.FormatBool(t))
		case nil:
		default:
			return nil, &json.UnsupportedValueError{Str: "nested value"}
		}
	}
	return out, nil
}

func parsePrincipal(raw json.RawMessage) (*Principals, error) {
	if raw == nil {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s != "*" {
			return nil, &json.UnsupportedValueError{Str: "principal " + s}
		}
		return &Principals{Any: true}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	p := &Principals{Kinds: map[string][]string{}}
	for k, v := range m {
		vals, err := scalarList(v)
		if err != nil {
			return nil, err
		}
		p.Kinds[k] = vals
	}
	return p, nil
}

// Evaluate returns Deny if any matching statement denies, Allow if any
// matching statement allows, otherwise NoMatch.
func (d *Document) Evaluate(r *Request) Decision {
	if d == nil {
		return NoMatch
	}
	out := NoMatch
	for i := range d.Statements {
		st := &d.Statements[i]
		if !st.matches(r) {
			continue
		}
		if st.Effect == "Deny" {
			return Deny
		}
		if st.Effect == "Allow" {
			out = Allow
		}
	}
	return out
}

func (st *Statement) matches(r *Request) bool {
	if st.hasPrincipal && !st.Principal.matches(r) {
		return false
	}
	if st.hasNotPrin && st.NotPrincipal.matches(r) {
		return false
	}
	if st.hasAction && !anyMatch(st.Action, r.Action, true, nil) {
		return false
	}
	if st.hasNotAction && anyMatch(st.NotAction, r.Action, true, nil) {
		return false
	}
	if st.hasResource && !anyMatch(st.Resource, r.Resource, false, r.Context) {
		return false
	}
	if st.hasNotRes && anyMatch(st.NotResource, r.Resource, false, r.Context) {
		return false
	}
	for op, block := range st.Condition {
		for key, want := range block {
			if !condition(op, key, want, r.Context) {
				return false
			}
		}
	}
	return true
}

func (p *Principals) matches(r *Request) bool {
	if p.Any {
		return true
	}
	for kind, vals := range p.Kinds {
		if kind != "AWS" {
			continue // Service and Federated principals never sign requests here
		}
		for _, v := range vals {
			if v == "*" {
				return true
			}
			if r.Account != "" && (v == r.Account || v == "arn:aws:iam::"+r.Account+":root") {
				return true
			}
			for _, arn := range r.Principals {
				if v == arn {
					return true
				}
			}
		}
	}
	return false
}

func anyMatch(patterns []string, s string, fold bool, ctx map[string][]string) bool {
	for _, p := range patterns {
		if ctx != nil {
			p = substitute(p, ctx)
		}
		if Glob(p, s, fold) {
			return true
		}
	}
	return false
}

// substitute expands policy variables such as ${aws:username}.
func substitute(p string, ctx map[string][]string) string {
	if !strings.Contains(p, "${") {
		return p
	}
	var b strings.Builder
	for {
		i := strings.Index(p, "${")
		if i < 0 {
			b.WriteString(p)
			return b.String()
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			b.WriteString(p)
			return b.String()
		}
		b.WriteString(p[:i])
		name := p[i+2 : i+j]
		switch name {
		case "*", "?", "$":
			b.WriteString(name)
		default:
			if v := lookup(ctx, name); len(v) == 1 {
				b.WriteString(v[0])
			} else {
				b.WriteString("\x00") // an unknown variable matches nothing
			}
		}
		p = p[i+j+1:]
	}
}

func lookup(ctx map[string][]string, key string) []string {
	if v, ok := ctx[strings.ToLower(key)]; ok {
		return v
	}
	return nil
}

// Glob matches s against a pattern with * and ? wildcards.
func Glob(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	px, sx := 0, 0
	nextPx, nextSx := -1, -1
	for px < len(pattern) || sx < len(s) {
		if px < len(pattern) {
			switch c := pattern[px]; c {
			case '*':
				nextPx, nextSx = px, sx+1
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			default:
				if sx < len(s) && s[sx] == c {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx > 0 && nextSx <= len(s) {
			px, sx = nextPx, nextSx
			continue
		}
		return false
	}
	return true
}

// condition evaluates one condition operator for one key.
func condition(op, key string, want []string, ctx map[string][]string) bool {
	base := op
	set := ""
	for _, p := range []string{"ForAnyValue:", "ForAllValues:"} {
		if strings.HasPrefix(base, p) {
			set, base = p, base[len(p):]
		}
	}
	ifExists := strings.HasSuffix(base, "IfExists")
	base = strings.TrimSuffix(base, "IfExists")
	have, present := ctx[strings.ToLower(key)]
	if base == "Null" {
		wantNull := len(want) > 0 && strings.EqualFold(want[0], "true")
		return wantNull == (!present || len(have) == 0)
	}
	if !present || len(have) == 0 {
		if ifExists {
			return true
		}
		switch set {
		case "ForAllValues:":
			return true
		case "ForAnyValue:":
			return false
		}
		return negated(base)
	}
	expanded := make([]string, len(want))
	for i, w := range want {
		expanded[i] = substitute(w, ctx)
	}
	want = expanded
	switch set {
	case "ForAllValues:":
		for _, h := range have {
			if !valueMatches(base, h, want) {
				return false
			}
		}
		return true
	default:
		// Single-valued keys and ForAnyValue: any context value may match.
		if negated(base) {
			for _, h := range have {
				if !valueMatches(base, h, want) {
					return false
				}
			}
			return true
		}
		for _, h := range have {
			if valueMatches(base, h, want) {
				return true
			}
		}
		return false
	}
}

func negated(op string) bool {
	return strings.Contains(op, "Not") && op != "Null"
}

// valueMatches applies op to one context value against the policy's values.
// Negated operators match when no value matches positively.
func valueMatches(op, have string, want []string) bool {
	pos := strings.Replace(op, "Not", "", 1)
	hit := false
	for _, w := range want {
		if compare(pos, have, w) {
			hit = true
			break
		}
	}
	if negated(op) {
		return !hit
	}
	return hit
}

func compare(op, have, want string) bool {
	switch op {
	case "StringEquals":
		return have == want
	case "StringEqualsIgnoreCase":
		return strings.EqualFold(have, want)
	case "StringLike":
		return Glob(want, have, false)
	case "ArnEquals", "ArnLike":
		return arnLike(want, have)
	case "Bool":
		return strings.EqualFold(have, want)
	case "BinaryEquals":
		a, err1 := base64.StdEncoding.DecodeString(have)
		b, err2 := base64.StdEncoding.DecodeString(want)
		return err1 == nil && err2 == nil && bytes.Equal(a, b)
	case "IpAddress":
		ip := net.ParseIP(have)
		if ip == nil {
			return false
		}
		if !strings.Contains(want, "/") {
			return ip.Equal(net.ParseIP(want))
		}
		_, n, err := net.ParseCIDR(want)
		return err == nil && n.Contains(ip)
	}
	if strings.HasPrefix(op, "Numeric") {
		a, err1 := strconv.ParseFloat(have, 64)
		b, err2 := strconv.ParseFloat(want, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return ordered(strings.TrimPrefix(op, "Numeric"), a, b)
	}
	if strings.HasPrefix(op, "Date") {
		a, ok1 := parseDate(have)
		b, ok2 := parseDate(want)
		if !ok1 || !ok2 {
			return false
		}
		return ordered(strings.TrimPrefix(op, "Date"), float64(a.UnixNano()), float64(b.UnixNano()))
	}
	return false
}

func ordered(rel string, a, b float64) bool {
	switch rel {
	case "Equals":
		return a == b
	case "LessThan":
		return a < b
	case "LessThanEquals":
		return a <= b
	case "GreaterThan":
		return a > b
	case "GreaterThanEquals":
		return a >= b
	}
	return false
}

func parseDate(s string) (time.Time, bool) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), true
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// arnLike compares ARNs component-wise; each of the six components may use
// wildcards, and a wildcard never crosses a colon except in the last one.
func arnLike(pattern, arn string) bool {
	pp := strings.SplitN(pattern, ":", 6)
	ap := strings.SplitN(arn, ":", 6)
	if len(pp) != 6 || len(ap) != 6 {
		return Glob(pattern, arn, false)
	}
	for i := range pp {
		if !Glob(pp[i], ap[i], false) {
			return false
		}
	}
	return true
}
