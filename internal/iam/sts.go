package iam

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

var stsOps = map[string]opFunc{
	"GetCallerIdentity": getCallerIdentity,
	"AssumeRole":        assumeRole,
	"GetSessionToken":   getSessionToken,
	"GetAccessKeyInfo":  getAccessKeyInfo,
}

func getCallerIdentity(c *call) (obj, error) {
	arn, uid := Identity(&c.who)
	if c.who.Kind == "user" {
		if u, err := c.user(c.who.UserName); err == nil {
			uid, arn = u.ID, u.ARN
		}
	}
	return obj{{"UserId", uid}, {"Account", c.account}, {"Arn", arn}}, nil
}

func getAccessKeyInfo(c *call) (obj, error) {
	id := c.f.str("AccessKeyId")
	var acct string
	err := c.tx.QueryRowContext(c.ctx, `SELECT account_id FROM access_keys WHERE access_key=?`, id).Scan(&acct)
	if err != nil {
		return nil, newErr(400, "InvalidParameterValue", "The access key ID %s is not valid.", id)
	}
	return obj{{"Account", acct}}, nil
}

var sessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]*$`)

// roleARNPattern: arn:aws:iam::<account>:role/<path/><name>
var roleARNPattern = regexp.MustCompile(`^arn:aws[a-z-]*:iam::(\d{12}):role/(.+)$`)

func accessDenied(format string, args ...any) *apiError {
	return newErr(403, "AccessDenied", format, args...)
}

func assumeRole(c *call) (obj, error) {
	roleARN := c.f.str("RoleArn")
	session := c.f.str("RoleSessionName")
	if n := len(session); n < 2 || n > 64 || !sessionNamePattern.MatchString(session) {
		return nil, validationError("1 validation error detected: Value '%s' at 'roleSessionName' failed to satisfy constraint: Member must have length less than or equal to 64 and match pattern [\\w+=,.@-]*", session)
	}
	m := roleARNPattern.FindStringSubmatch(roleARN)
	if m == nil {
		return nil, validationError("%s is invalid", roleARN)
	}
	roleAcct, rolePath := m[1], m[2]
	callerARNs := PrincipalARNs(&c.who)
	callerARN, _ := Identity(&c.who)
	denied := accessDenied("User: %s is not authorized to perform: sts:AssumeRole on resource: %s", callerARN, roleARN)
	var r Role
	ok, err := load(c.ctx, c.tx, roleAcct, kRole, nameKey(rolePath[strings.LastIndexByte(rolePath, '/')+1:]), &r)
	if err != nil {
		return nil, err
	}
	if !ok || r.ARN != roleARN {
		return nil, denied
	}
	trust, err := ParseDocument(r.TrustPolicy)
	if err != nil {
		return nil, denied
	}
	req := &Request{Action: "sts:AssumeRole", Resource: roleARN, Principals: callerARNs, Context: baseContext(&c.who)}
	if ext := c.f.str("ExternalId"); ext != "" {
		req.Context["sts:externalid"] = []string{ext}
	}
	req.Context["sts:rolesessionname"] = []string{session}
	direct := trust.Evaluate(req) // does the trust policy name the caller itself?
	if direct == Deny {
		return nil, denied
	}
	req.Account = c.who.Account.ID
	viaAccount := trust.Evaluate(req)
	if viaAccount == Deny {
		return nil, denied
	}
	switch {
	case direct == Allow && c.who.Account.ID == roleAcct:
	case viaAccount == Allow:
		// The trust policy delegates to the caller's account, whose own
		// policies must then allow the call.
		d, err := c.h.Authorizer().Decide(c.ctx, &c.who, "sts:AssumeRole", roleARN, nil)
		if err != nil {
			return nil, err
		}
		if d != Allow {
			return nil, denied
		}
	default:
		return nil, denied
	}
	duration, err := c.f.intValue("DurationSeconds", 3600)
	if err != nil {
		return nil, err
	}
	if duration < 900 {
		return nil, validationError("1 validation error detected: Value '%d' at 'durationSeconds' failed to satisfy constraint: Member must have value greater than or equal to 900", duration)
	}
	if duration > r.maxSession() {
		return nil, validationError("The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
	}
	policy := c.f.str("Policy")
	if policy != "" {
		if _, err := ParseDocument(policy); err != nil {
			return nil, malformed("Syntax errors in policy.")
		}
	}
	var arns []string
	for _, s := range c.f.structs("PolicyArns") {
		arns = append(arns, s["arn"])
	}
	s := &Session{Kind: "role", RoleARN: r.ARN, RoleID: r.ID, RoleName: r.Name, SessionName: session, Policy: policy, PolicyARNs: arns, SourceARN: callerARN}
	creds, err := c.issue(roleAcct, r.Name, s, time.Duration(duration)*time.Second)
	if err != nil {
		return nil, err
	}
	now := c.now
	r.LastUsed, r.LastUsedRegion = &now, c.region
	if err := save(c.ctx, c.tx, roleAcct, kRole, nameKey(r.Name), &r); err != nil {
		return nil, err
	}
	return obj{{"Credentials", creds},
		{"AssumedRoleUser", obj{{"AssumedRoleId", r.ID + ":" + session}, {"Arn", "arn:aws:sts::" + roleAcct + ":assumed-role/" + r.Name + "/" + session}}},
		{"PackedPolicySize", len(policy) * 100 / 2048}}, nil
}

func getSessionToken(c *call) (obj, error) {
	if c.who.Kind == "session" {
		return nil, accessDenied("Cannot call GetSessionToken with session credentials")
	}
	duration, err := c.f.intValue("DurationSeconds", 43200)
	if err != nil {
		return nil, err
	}
	max := 129600
	if IsRoot(&c.who) {
		max = 3600
		if duration > max {
			duration = max
		}
	}
	if duration < 900 || duration > max {
		return nil, validationError("1 validation error detected: Value '%d' at 'durationSeconds' failed to satisfy constraint: Member must have value between 900 and 129600", duration)
	}
	s := &Session{Kind: "user"}
	if c.who.Kind == "user" {
		s.UserName = c.who.UserName
	}
	creds, err := c.issue(c.account, c.who.UserName, s, time.Duration(duration)*time.Second)
	if err != nil {
		return nil, err
	}
	return obj{{"Credentials", creds}}, nil
}

// issue stores new temporary credentials and returns their XML.
func (c *call) issue(account, name string, s *Session, d time.Duration) (obj, error) {
	id, secret := randomID("ASIA", 16), randomSecret(40)
	raw := make([]byte, 96)
	_, _ = rand.Read(raw)
	token := "IQoJb3JpZ2luX2Vj" + base64.StdEncoding.EncodeToString(raw)
	desc, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	expires := c.now.Add(d)
	if _, err := c.tx.ExecContext(c.ctx, `DELETE FROM access_keys WHERE kind='session' AND expires < ?`, c.now.Add(-time.Hour).UnixMilli()); err != nil {
		return nil, err
	}
	if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO access_keys(access_key, secret_key, account_id, user_name, status, created, kind, session_token, expires, principal)
		VALUES (?, ?, ?, ?, 'Active', ?, 'session', ?, ?, ?)`,
		id, secret, account, name, c.now.UnixMilli(), token, expires.UnixMilli(), string(desc)); err != nil {
		return nil, err
	}
	return obj{{"AccessKeyId", id}, {"SecretAccessKey", secret}, {"SessionToken", token}, {"Expiration", expires}}, nil
}
