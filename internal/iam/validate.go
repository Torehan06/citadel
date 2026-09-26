package iam

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Policy document validation, in the order IAM applies its checks. IAM
// reports only the first failing stage, each with a fixed message:
//
//  1. grammar ("Syntax errors in policy.")
//  2. version ("Policy document must be version 2012-10-17 or greater.")
//  3. the legacy parser: case-sensitive Effect, date conditions, resource ARNs
//  4. unique statement IDs, then actions present
//  5. resource ARN format errors, which carry the offending resource
//  6. action vendor prefixes
//  7. (identity policies) resources present; (trust policies) only STS
//     actions and no Resource element.

var (
	validTop        = set("Version", "Id", "Statement", "Conditions")
	validStatement  = set("Sid", "Action", "NotAction", "Resource", "NotResource", "Effect", "Principal", "NotPrincipal", "Condition")
	validConditions = set(
		"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
		"StringLike", "StringNotLike", "NumericEquals", "NumericNotEquals", "NumericLessThan",
		"NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals",
		"DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals",
		"Bool", "BinaryEquals", "IpAddress", "NotIpAddress", "ArnEquals", "ArnLike", "ArnNotEquals",
		"ArnNotLike", "Null")
	partitions     = set("aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-eusc")
	iamPathStarts  = []string{"user/", "federated-user/", "role/", "group/", "instance-profile/", "mfa/", "server-certificate/", "policy/", "sms-mfa/", "saml-provider/", "oidc-provider/", "report/", "access-report/"}
	trustActions   = set("sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:DecodeAuthorizationMessage", "sts:GetAccessKeyInfo", "sts:GetCallerIdentity", "sts:GetFederationToken", "sts:GetServiceBearerToken", "sts:GetSessionToken", "sts:SetSourceIdentity", "sts:TagSession")
	vendorInvalid  = regexp.MustCompile(`[^a-zA-Z0-9\-.]`)
	errLegacyParse = "The policy failed legacy parsing"
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

type validator struct {
	doc           map[string]any
	statements    []map[string]any
	resourceError string
}

// ValidatePolicy checks an identity-based (or managed) policy document.
func ValidatePolicy(doc string) error {
	v, err := validateBase(doc)
	if err != nil {
		return err
	}
	for _, st := range v.statements {
		if !elementPresent(st, "Resource", "NotResource") {
			return malformed("Policy statement must contain resources.")
		}
	}
	return nil
}

// ValidateTrustPolicy checks a role trust policy document.
func ValidateTrustPolicy(doc string) error {
	v, err := validateBase(doc)
	if err != nil {
		return err
	}
	for _, st := range v.statements {
		actions, ok := st["Action"]
		if !ok {
			return malformed("Trust Policy statement actions can only be sts:AssumeRole, sts:AssumeRoleWithSAML,  and sts:AssumeRoleWithWebIdentity")
		}
		for _, a := range stringsOf(actions) {
			if !trustActions[a] {
				return malformed("Trust Policy statement actions can only be sts:AssumeRole, sts:AssumeRoleWithSAML,  and sts:AssumeRoleWithWebIdentity")
			}
		}
	}
	for _, st := range v.statements {
		_, r := st["Resource"]
		_, nr := st["NotResource"]
		if r || nr {
			return malformed("Has prohibited field Resource.")
		}
	}
	return nil
}

func validateBase(doc string) (*validator, error) {
	v := &validator{}
	if !v.syntax(doc) {
		return nil, malformed("Syntax errors in policy.")
	}
	if ver, _ := v.doc["Version"].(string); ver != "2012-10-17" {
		return nil, malformed("Policy document must be version 2012-10-17 or greater.")
	}
	if !v.legacy() {
		return nil, malformed(errLegacyParse)
	}
	sids := map[string]bool{}
	for _, st := range v.statements {
		if sid, _ := st["Sid"].(string); sid != "" {
			if sids[sid] {
				return nil, malformed("Statement IDs (SID) in a single policy must be unique.")
			}
			sids[sid] = true
		}
	}
	for _, st := range v.statements {
		if !elementPresent(st, "Action", "NotAction") {
			return nil, malformed("Policy statement must contain actions.")
		}
	}
	if v.resourceError != "" {
		return nil, malformed(v.resourceError)
	}
	for _, key := range []string{"Action", "NotAction"} {
		for _, st := range v.statements {
			if a, ok := st[key]; ok {
				for _, action := range stringsOf(a) {
					if err := validateActionPrefix(action); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return v, nil
}

// elementPresent: the statement has key (or notKey), and a list value is not empty.
func elementPresent(st map[string]any, key, notKey string) bool {
	val, ok := st[key]
	nval, nok := st[notKey]
	if !ok && !nok {
		return false
	}
	if ok {
		if l, isList := val.([]any); isList {
			return len(l) > 0
		}
		return true
	}
	if l, isList := nval.([]any); isList {
		return len(l) > 0
	}
	return true
}

func stringsOf(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func validateActionPrefix(action string) error {
	parts := strings.Split(action, ":")
	if len(parts) == 1 && parts[0] != "*" {
		return malformed("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")
	}
	if len(parts) > 2 {
		return malformed("Actions/Condition can contain only one colon.")
	}
	if parts[0] != "*" && vendorInvalid.MatchString(parts[0]) {
		return malformed("Vendor " + parts[0] + " is not valid")
	}
	return nil
}

// ---------------------------------------------------------------- grammar

func (v *validator) syntax(doc string) bool {
	dec := json.NewDecoder(bytes.NewReader([]byte(doc)))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return false
	}
	if _, err := dec.Token(); err == nil {
		return false // trailing data
	}
	m, ok := root.(map[string]any)
	if !ok {
		return false
	}
	v.doc = m
	for k := range m {
		if !validTop[k] {
			return false
		}
	}
	if ver, ok := m["Version"]; ok {
		s, isStr := ver.(string)
		if !isStr || (s != "2008-10-17" && s != "2012-10-17") {
			return false
		}
	}
	if id, ok := m["Id"]; ok {
		if _, isStr := id.(string); !isStr {
			return false
		}
	}
	st, ok := m["Statement"]
	if !ok {
		return false
	}
	switch t := st.(type) {
	case map[string]any:
		v.statements = []map[string]any{t}
	case []any:
		for _, x := range t {
			s, isMap := x.(map[string]any)
			if !isMap {
				return false
			}
			v.statements = append(v.statements, s)
		}
	default:
		return false
	}
	if len(v.statements) == 0 {
		return false
	}
	for _, s := range v.statements {
		if !statementSyntax(s) {
			return false
		}
	}
	return true
}

func statementSyntax(st map[string]any) bool {
	for k := range st {
		if !validStatement[k] {
			return false
		}
	}
	if _, r := st["Resource"]; r {
		if _, nr := st["NotResource"]; nr {
			return false
		}
	}
	if _, a := st["Action"]; a {
		if _, na := st["NotAction"]; na {
			return false
		}
	}
	eff, ok := st["Effect"].(string)
	if !ok || (!strings.EqualFold(eff, "Allow") && !strings.EqualFold(eff, "Deny")) {
		return false
	}
	for _, key := range []string{"Action", "NotAction", "Resource", "NotResource"} {
		val, ok := st[key]
		if !ok {
			continue
		}
		switch t := val.(type) {
		case string:
		case []any:
			for _, x := range t {
				if _, isStr := x.(string); x != nil && !isStr {
					return false
				}
			}
		default:
			return false
		}
	}
	if cond, ok := st["Condition"]; ok {
		cm, isMap := cond.(map[string]any)
		if !isMap {
			return false
		}
		for op, block := range cm {
			bm, isMap := block.(map[string]any)
			if !isMap {
				return false
			}
			for _, val := range bm {
				switch val.(type) {
				case bool, []any, string:
				default:
					return false
				}
			}
			if !validConditions[stripCondition(op)] && len(bm) > 0 {
				return false
			}
		}
	}
	if sid, ok := st["Sid"]; ok {
		if _, isStr := sid.(string); !isStr {
			return false
		}
	}
	return true
}

// stripCondition removes one ForAnyValue:/ForAllValues: prefix and an IfExists suffix.
func stripCondition(op string) string {
	for _, p := range []string{"ForAnyValue:", "ForAllValues:"} {
		if strings.HasPrefix(op, p) {
			op = op[len(p):]
			break
		}
	}
	return strings.TrimSuffix(op, "IfExists")
}

// ---------------------------------------------------------------- legacy parser

func (v *validator) legacy() bool {
	for _, st := range v.statements {
		if eff := st["Effect"].(string); eff != "Allow" && eff != "Deny" {
			return false
		}
		if cond, ok := st["Condition"].(map[string]any); ok {
			for op, block := range cond {
				if !strings.HasPrefix(stripCondition(op), "Date") {
					continue
				}
				for _, val := range block.(map[string]any) {
					if !legacyDates(val) {
						return false
					}
				}
			}
		}
	}
	for _, key := range []string{"Resource", "NotResource"} {
		for _, st := range v.statements {
			val, ok := st[key]
			if !ok {
				continue
			}
			if s, isStr := val.(string); isStr {
				v.checkResource(s)
			} else {
				var rs []string
				for _, x := range val.([]any) {
					if s, _ := x.(string); s != "" {
						rs = append(rs, s)
					}
				}
				sort.Sort(sort.Reverse(sort.StringSlice(rs)))
				for _, r := range rs {
					v.checkResource(r)
				}
			}
			if v.resourceError == "" && !legacyResources(val) {
				return false
			}
		}
	}
	return true
}

func legacyDates(val any) bool {
	switch t := val.(type) {
	case string:
		return legacyDate(t)
	case []any:
		for _, x := range t {
			s, ok := x.(string)
			if !ok || !legacyDate(s) {
				return false
			}
		}
		return true
	}
	return false
}

func legacyDate(s string) bool {
	if strings.Contains(strings.ToLower(s), "t") || strings.Contains(s, "-") {
		return iso8601(strings.ToLower(s))
	}
	n, ok := pyInt(s)
	return ok && n >= 0
}

// pyInt parses an integer the way Python's int() does for these documents.
func pyInt(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil
}

func inRange(s string, lo, hi int64) bool {
	n, ok := pyInt(s)
	return ok && n >= lo && n <= hi
}

func iso8601(s string) bool {
	date, clock, _ := strings.Cut(s, "t")
	negative := strings.HasPrefix(date, "-")
	if negative {
		date = date[1:]
	}
	parts := strings.Split(date, "-")
	year := parts[0]
	if negative {
		year = "-" + year
	}
	if !inRange(year, -292275054, 292278993) {
		return false
	}
	if len(parts) > 1 && !inRange(parts[1], 1, 12) {
		return false
	}
	if len(parts) > 2 && !inRange(parts[2], 1, 31) {
		return false
	}
	if len(parts) >= 4 {
		return false
	}
	tp := strings.Split(clock, ":")
	if tp[0] != "" && !inRange(tp[0], 0, 23) {
		return false
	}
	if len(tp) > 1 && !inRange(tp[1], 0, 59) {
		return false
	}
	if len(tp) > 2 {
		secs := tp[2]
		switch {
		case strings.Contains(secs, "z"):
			var rest string
			secs, rest, _ = strings.Cut(secs, "z")
			if rest != "" {
				return false
			}
		case strings.Contains(secs, "+"):
			var zone string
			secs, zone, _ = strings.Cut(secs, "+")
			zh, zm, hasMin := strings.Cut(zone, ":")
			if len(zh) != 2 || !inRange(zh, 0, 23) {
				return false
			}
			if hasMin && (len(zm) != 2 || !inRange(zm, 0, 59)) {
				return false
			}
		}
		whole, frac, hasFrac := strings.Cut(secs, ".")
		if !inRange(whole, 0, 59) {
			return false
		}
		if hasFrac && !inRange(frac, 0, 999999999) {
			return false
		}
	}
	return true
}

func legacyResources(val any) bool {
	if s, ok := val.(string); ok {
		if s == "*" {
			return true
		}
		if strings.Count(s, ":") < 5 && strings.Contains(s, "::") {
			return false
		}
		parts := strings.Split(s, ":")
		return len(parts) > 2 && parts[2] != ""
	}
	for _, x := range val.([]any) {
		s, _ := x.(string)
		if s == "" || s == "*" {
			continue
		}
		if strings.Count(s, ":") < 5 && strings.Contains(s, "::") {
			return false
		}
		if len(s) < 3 {
			return false
		}
	}
	return true
}

// checkResource records the resource's format error, if any. Later errors
// replace earlier ones, as in IAM.
func (v *validator) checkResource(r string) {
	if r == "*" {
		return
	}
	_, rest, found := strings.Cut(r, ":")
	if !found {
		v.resourceError = `Resource ` + r + ` must be in ARN format or "*".`
		return
	}
	partition, rest, found := strings.Cut(rest, ":")
	if partition != "*" && !partitions[partition] {
		rem := strings.Split(rest, ":")
		get := func(i int) string {
			if len(rem) > i {
				return rem[i]
			}
			return "*"
		}
		a1 := get(0)
		if rem[0] == "" && len(rem) == 1 {
			a1 = "*"
		}
		a4 := "*"
		if len(rem) > 3 {
			a4 = strings.Join(rem[3:], ":")
		}
		v.resourceError = `Partition "` + partition + `" is not valid for resource "arn:` + partition + ":" + a1 + ":" + get(1) + ":" + get(2) + ":" + a4 + `".`
		return
	}
	if !found {
		v.resourceError = "Resource vendor must be fully qualified and cannot contain regexes."
		return
	}
	service, afterService, _ := strings.Cut(rest, ":")
	_, afterRegion, _ := strings.Cut(afterService, ":")
	_, resourceID, _ := strings.Cut(afterRegion, ":")
	if (service == "iam" || service == "s3") && !strings.HasPrefix(afterService, ":") {
		if !(service == "s3" && strings.HasPrefix(resourceID, "accesspoint/")) {
			if service == "iam" {
				v.resourceError = "IAM resource " + r + " cannot contain region information."
			} else {
				v.resourceError = "Resource " + r + " can not contain region information."
			}
			return
		}
	}
	if service == "iam" {
		for _, p := range iamPathStarts {
			if strings.HasPrefix(resourceID, p) {
				return
			}
		}
		v.resourceError = `IAM resource path must either be "*" or start with ` + strings.Join(iamPathStarts, ", ") + "."
	}
}
