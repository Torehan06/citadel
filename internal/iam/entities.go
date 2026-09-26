package iam

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Entity kinds stored in iam_entities.
const (
	kUser     = "user"
	kGroup    = "group"
	kRole     = "role"
	kPolicy   = "policy"  // key: policy ARN
	kProfile  = "profile" // instance profile
	kMFA      = "mfa"     // virtual MFA device, key: serial number
	kSAML     = "saml"    // key: ARN
	kOIDC     = "oidc"    // key: ARN
	kCert     = "cert"    // server certificate
	kAccount  = "account" // account-wide settings, key: "settings"
	kCredRept = "report"  // credential report, key: "credential"
)

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type execer interface {
	querier
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func nameKey(name string) string { return strings.ToLower(name) }

// load reads one entity document into out. It reports whether it existed.
func load(ctx context.Context, q querier, account, kind, key string, out any) (bool, error) {
	var doc string
	err := q.QueryRowContext(ctx, `SELECT doc FROM iam_entities WHERE account_id=? AND kind=? AND key=?`,
		account, kind, key).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(doc), out)
}

// save inserts or replaces an entity, keeping its insertion position (rowid)
// so lists stay in creation order.
func save(ctx context.Context, x execer, account, kind, key string, v any) error {
	doc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = x.ExecContext(ctx, `
		INSERT INTO iam_entities(account_id, kind, key, doc, created) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(account_id, kind, key) DO UPDATE SET doc=excluded.doc`,
		account, kind, key, string(doc), time.Now().UnixMilli())
	return err
}

func remove(ctx context.Context, x execer, account, kind, key string) error {
	_, err := x.ExecContext(ctx, `DELETE FROM iam_entities WHERE account_id=? AND kind=? AND key=?`, account, kind, key)
	return err
}

// rename moves an entity to a new key, keeping its position.
func rename(ctx context.Context, x execer, account, kind, oldKey, newKey string, v any) error {
	doc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = x.ExecContext(ctx, `UPDATE iam_entities SET key=?, doc=? WHERE account_id=? AND kind=? AND key=?`,
		newKey, string(doc), account, kind, oldKey)
	return err
}

// loadAll returns every entity of a kind in creation order.
func loadAll[T any](ctx context.Context, q querier, account, kind string) ([]*T, error) {
	rows, err := q.QueryContext(ctx, `SELECT doc FROM iam_entities WHERE account_id=? AND kind=? ORDER BY rowid`, account, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*T
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		v := new(T)
		if err := json.Unmarshal([]byte(doc), v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Tag is an IAM resource tag.
type Tag struct{ Key, Value string }

// User is an IAM user.
type User struct {
	Path, Name, ID, ARN string
	Created             time.Time
	Tags                []Tag             `json:",omitempty"`
	Inline              map[string]string `json:",omitempty"` // policy name → document
	InlineOrder         []string          `json:",omitempty"`
	Attached            []string          `json:",omitempty"` // managed policy ARNs
	Groups              []string          `json:",omitempty"` // group IDs
	Boundary            string            `json:",omitempty"`
	Login               *LoginProfile     `json:",omitempty"`
	SSHKeys             []SSHKey          `json:",omitempty"`
	MFA                 []MFABinding      `json:",omitempty"`
	SigningCerts        []SigningCert     `json:",omitempty"`
	PasswordLastUsed    *time.Time        `json:",omitempty"`
}

type LoginProfile struct {
	Created       time.Time
	ResetRequired bool
}

type SSHKey struct {
	ID, Body, Fingerprint, Status string
	Uploaded                      time.Time
}

type MFABinding struct {
	Serial  string
	Enabled time.Time
}

type SigningCert struct {
	ID, Body, Status string
	Uploaded         time.Time
}

// Group is an IAM group. Membership is stored on users (User.Groups).
type Group struct {
	Path, Name, ID, ARN string
	Created             time.Time
	Inline              map[string]string `json:",omitempty"`
	InlineOrder         []string          `json:",omitempty"`
	Attached            []string          `json:",omitempty"`
}

// Role is an IAM role.
type Role struct {
	Path, Name, ID, ARN string
	Created             time.Time
	TrustPolicy         string
	Description         *string           `json:",omitempty"`
	MaxSession          int               `json:",omitempty"`
	Tags                []Tag             `json:",omitempty"`
	Inline              map[string]string `json:",omitempty"`
	InlineOrder         []string          `json:",omitempty"`
	Attached            []string          `json:",omitempty"`
	Boundary            string            `json:",omitempty"`
	LastUsed            *time.Time        `json:",omitempty"`
	LastUsedRegion      string            `json:",omitempty"`
}

// Policy is a customer managed policy. AWS managed policies are built in
// (see awsmanaged.go) and never stored.
type Policy struct {
	Path, Name, ID, ARN string
	Description         string `json:",omitempty"`
	Created, Updated    time.Time
	Default             string
	Versions            []PolicyVersion
	NextVersion         int
	Tags                []Tag `json:",omitempty"`
}

type PolicyVersion struct {
	ID       string
	Document string
	Created  time.Time
}

// Profile is an instance profile.
type Profile struct {
	Path, Name, ID, ARN string
	Created             time.Time
	Roles               []string `json:",omitempty"` // role IDs
	Tags                []Tag    `json:",omitempty"`
}

func putInline(inline *map[string]string, order *[]string, name, doc string) {
	if *inline == nil {
		*inline = map[string]string{}
	}
	if _, ok := (*inline)[name]; !ok {
		*order = append(*order, name)
	}
	(*inline)[name] = doc
}

func deleteInline(inline map[string]string, order *[]string, name string) bool {
	if _, ok := inline[name]; !ok {
		return false
	}
	delete(inline, name)
	for i, n := range *order {
		if n == name {
			*order = append((*order)[:i:i], (*order)[i+1:]...)
			break
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func without(list []string, s string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
