package api

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(conformance bool) *httptest.Server {
	s := New(Config{Region: "tuchanka-1", Version: "test", Conformance: conformance,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return httptest.NewServer(s)
}

func TestDetectService(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *http.Request)
		want   string
	}{
		{"sigv4 s3", func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKID/20260925/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
		}, SvcS3},
		{"sigv4 dynamodb", func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKID/20260925/tuchanka-1/dynamodb/aws4_request,SignedHeaders=host,Signature=abc")
		}, SvcDynamoDB},
		{"presigned", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("X-Amz-Credential", "AKID/20260925/us-east-1/s3/aws4_request")
			r.URL.RawQuery = q.Encode()
		}, SvcS3},
		{"target sqs", func(r *http.Request) { r.Header.Set("X-Amz-Target", "AmazonSQS.SendMessage") }, SvcSQS},
		{"target ddb", func(r *http.Request) { r.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem") }, SvcDynamoDB},
		{"lambda path", func(r *http.Request) { r.URL.Path = "/2015-03-31/functions/f/invocations" }, SvcLambda},
		{"route53 path", func(r *http.Request) { r.URL.Path = "/2013-04-01/hostedzone" }, SvcRoute53},
		{"anonymous", func(r *http.Request) {}, SvcS3},
		{"malformed scope falls through", func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=garbage")
			r.Header.Set("X-Amz-Target", "AmazonSQS.ListQueues")
		}, SvcSQS},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			c.mutate(r)
			if got := DetectService(r); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(false)
	defer ts.Close()
	res, err := http.Get(ts.URL + "/_citadel/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || body["region"] != "tuchanka-1" {
		t.Fatalf("unexpected healthz: %d %v", res.StatusCode, body)
	}
}

func TestUnimplementedS3IsXML501(t *testing.T) {
	ts := newTestServer(false)
	defer ts.Close()
	res, err := http.Get(ts.URL + "/some-bucket")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status %d", res.StatusCode)
	}
	var e s3Error
	if err := xml.NewDecoder(res.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	if e.Code != "NotImplemented" || e.RequestID == "" {
		t.Fatalf("bad error body: %+v", e)
	}
}

func TestUnimplementedJSONProtocol(t *testing.T) {
	ts := newTestServer(false)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", strings.NewReader("{}"))
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810.ListTables")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode != http.StatusNotImplemented || !strings.HasSuffix(body["__type"], "#NotImplemented") {
		t.Fatalf("got %d %v", res.StatusCode, body)
	}
}

func TestMotoResetOnlyInConformanceMode(t *testing.T) {
	for _, conformance := range []bool{false, true} {
		ts := newTestServer(conformance)
		res, err := http.Post(ts.URL+"/moto-api/reset", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		ts.Close()
		if conformance && res.StatusCode != 200 {
			t.Fatalf("conformance mode: reset returned %d", res.StatusCode)
		}
		if !conformance && res.StatusCode == 200 {
			t.Fatal("reset endpoint must not exist outside conformance mode")
		}
	}
}
