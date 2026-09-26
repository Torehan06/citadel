package iam

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"citadel/internal/store"
)

const acct = "111122223333"

func testAuthorizer(t *testing.T) (*Authorizer, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir(), "test-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Authorizer{st: st}, st
}

func put(t *testing.T, st *store.Store, kind, key string, v any) {
	t.Helper()
	err := st.Update(context.Background(), func(tx *store.Tx) error {
		return save(context.Background(), tx, acct, kind, key, v)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func policyDoc(effect, action, resource string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect + `","Action":"` + action + `","Resource":"` + resource + `"}]}`
}

func TestAuthorizerUser(t *testing.T) {
	a, st := testAuthorizer(t)
	ctx := context.Background()
	managed := &Policy{Name: "sqs", ARN: "arn:aws:iam::" + acct + ":policy/sqs", Default: "v1",
		Versions: []PolicyVersion{{ID: "v1", Document: policyDoc("Allow", "sqs:*", "*")}}}
	put(t, st, kPolicy, managed.ARN, managed)
	put(t, st, kGroup, "devs", &Group{Name: "devs", ID: "G1", Attached: []string{managed.ARN}})
	put(t, st, kUser, "alice", &User{Name: "alice", Groups: []string{"G1"},
		Inline:      map[string]string{"s3": policyDoc("Allow", "s3:*", "arn:aws:s3:::data/*"), "deny": policyDoc("Deny", "s3:DeleteObject", "*")},
		InlineOrder: []string{"s3", "deny"}})
	alice := &store.Principal{Kind: "user", UserName: "alice", Account: store.Account{ID: acct}}

	cases := []struct {
		action, resource string
		want             Decision
	}{
		{"s3:GetObject", "arn:aws:s3:::data/x", Allow},
		{"s3:GetObject", "arn:aws:s3:::other/x", NoMatch},
		{"s3:DeleteObject", "arn:aws:s3:::data/x", Deny},
		{"sqs:SendMessage", "arn:aws:sqs:r:" + acct + ":q", Allow}, // through the group's managed policy
		{"dynamodb:GetItem", "*", NoMatch},
	}
	for _, tc := range cases {
		got, err := a.Decide(ctx, alice, tc.action, tc.resource, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s %s: got %v, want %v", tc.action, tc.resource, got, tc.want)
		}
	}

	// A permissions boundary caps what the identity policies grant.
	boundary := &Policy{Name: "b", ARN: "arn:aws:iam::" + acct + ":policy/b", Default: "v1",
		Versions: []PolicyVersion{{ID: "v1", Document: policyDoc("Allow", "s3:*", "*")}}}
	put(t, st, kPolicy, boundary.ARN, boundary)
	var u User
	if _, err := load(ctx, st.DB(), acct, kUser, "alice", &u); err != nil {
		t.Fatal(err)
	}
	u.Boundary = boundary.ARN
	put(t, st, kUser, "alice", &u)
	if got, _ := a.Decide(ctx, alice, "sqs:SendMessage", "*", nil); got != NoMatch {
		t.Errorf("boundary: sqs got %v, want NoMatch", got)
	}
	if got, _ := a.Decide(ctx, alice, "s3:GetObject", "arn:aws:s3:::data/x", nil); got != Allow {
		t.Errorf("boundary: s3 got %v, want Allow", got)
	}

	root := &store.Principal{Kind: "root", Account: store.Account{ID: acct}}
	if got, _ := a.Decide(ctx, root, "anything:AtAll", "*", nil); got != Allow {
		t.Errorf("root got %v", got)
	}
}

func TestAuthorizerRoleSession(t *testing.T) {
	a, st := testAuthorizer(t)
	ctx := context.Background()
	role := &Role{Name: "reader", ID: "AROAEXAMPLE", ARN: "arn:aws:iam::" + acct + ":role/reader",
		Inline: map[string]string{"p": policyDoc("Allow", "dynamodb:*", "*")}, InlineOrder: []string{"p"}}
	put(t, st, kRole, "reader", role)
	session := func(policy string) *store.Principal {
		s, _ := json.Marshal(Session{Kind: "role", RoleARN: role.ARN, RoleID: role.ID, RoleName: "reader", SessionName: "s", Policy: policy})
		return &store.Principal{Kind: "session", Account: store.Account{ID: acct}, Session: string(s), Expires: time.Now().Add(time.Hour).UnixMilli()}
	}
	if got, _ := a.Decide(ctx, session(""), "dynamodb:PutItem", "*", nil); got != Allow {
		t.Errorf("role policy: got %v", got)
	}
	// A session policy narrows the role's permissions.
	narrow := session(policyDoc("Allow", "dynamodb:GetItem", "*"))
	if got, _ := a.Decide(ctx, narrow, "dynamodb:PutItem", "*", nil); got != NoMatch {
		t.Errorf("session policy: PutItem got %v", got)
	}
	if got, _ := a.Decide(ctx, narrow, "dynamodb:GetItem", "*", nil); got != Allow {
		t.Errorf("session policy: GetItem got %v", got)
	}
	arn, uid := Identity(session(""))
	if arn != "arn:aws:sts::"+acct+":assumed-role/reader/s" || uid != "AROAEXAMPLE:s" {
		t.Errorf("identity %s %s", arn, uid)
	}
	// Deleting the role revokes its sessions.
	if err := st.Update(ctx, func(tx *store.Tx) error { return remove(ctx, tx, acct, kRole, "reader") }); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Decide(ctx, session(""), "dynamodb:PutItem", "*", nil); got != NoMatch {
		t.Errorf("deleted role: got %v", got)
	}
}
