package sigv4

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestSignVerifies(t *testing.T) {
	for _, tc := range []struct {
		name, method, target, ctype, token string
		body                               []byte
	}{
		{"get with query", "GET", "http://127.0.0.1:8420/bucket/a%20b?list-type=2&prefix=x", "", "", nil},
		{"query form post", "POST", "http://127.0.0.1:8420/", "application/x-www-form-urlencoded", "", []byte("Action=GetUser&Version=2010-05-08")},
		{"session token", "POST", "http://localhost/", "application/x-amz-json-1.0", "tok", []byte(`{}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, bytes.NewReader(tc.body))
			if tc.ctype != "" {
				r.Header.Set("Content-Type", tc.ctype)
			}
			Sign(r, Credentials{AccessKey: docAK, SecretKey: docSecret, SessionToken: tc.token}, "us-east-1", "iam", tc.body, docTime)
			a, err := docVerifier(docTime).Verify(r)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if a.AccessKey != docAK || a.Service != "iam" || a.Region != "us-east-1" || a.SessionToken != tc.token {
				t.Fatalf("auth = %+v", a)
			}
		})
	}
}
