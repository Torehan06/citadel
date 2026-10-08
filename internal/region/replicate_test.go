package region

import (
	"net/http"
	"testing"
	"time"
)

func TestDigestOrderIndependentAndDiff(t *testing.T) {
	entries := [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}, {"d\x00e", "4"}}
	var fwd, rev Digest
	for _, e := range entries {
		fwd.Add(e[0], e[1])
	}
	for i := len(entries) - 1; i >= 0; i-- {
		rev.Add(entries[i][0], entries[i][1])
	}
	if d := DiffLeaves(&fwd, rev.Hex()); len(d) != 0 {
		t.Fatalf("same set in another order differs in leaves %v", d)
	}
	var changed Digest
	for _, e := range entries {
		v := e[1]
		if e[0] == "b" {
			v = "newer"
		}
		changed.Add(e[0], v)
	}
	d := DiffLeaves(&fwd, changed.Hex())
	if len(d) != 1 || d[0] != LeafOf("b") {
		t.Fatalf("one changed entry: diff %v, want [%d]", d, LeafOf("b"))
	}
	if d := DiffLeaves(&fwd, nil); len(d) != Leaves {
		t.Fatalf("missing remote digest should differ everywhere, got %d leaves", len(d))
	}
	var empty Digest
	fwd.Add("a", "1") // XOR removes it again
	fwd.Add("b", "2")
	fwd.Add("c", "3")
	fwd.Add("d\x00e", "4")
	if d := DiffLeaves(&fwd, empty.Hex()); len(d) != 0 {
		t.Fatalf("adding every entry twice should cancel out, diff %v", d)
	}
}

func TestLagWindow(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newLagWindow(100)
	l.now = func() time.Time { return now }
	if s := l.summary(); s["lag_samples"] != 0 || s["lag_p99_ms"] != nil {
		t.Fatalf("empty window: %v", s)
	}
	for i := 1; i <= 250; i++ {
		l.add(time.Duration(i) * time.Millisecond)
	}
	s := l.summary()
	// The window holds the last 100 samples: 151..250 ms.
	if s["lag_samples"] != 100 || s["lag_p50_ms"] != int64(201) || s["lag_p99_ms"] != int64(250) ||
		s["lag_window_max_ms"] != int64(250) || s["lag_max_ms"] != int64(250) || s["lag_samples_1m"] != 100 {
		t.Fatalf("summary %v", s)
	}
	// Two minutes later only the new samples count as recent.
	now = now.Add(2 * time.Minute)
	for i := 0; i < 10; i++ {
		l.add(-time.Second) // clock skew never reports negative lag
	}
	s = l.summary()
	if s["lag_samples"] != 100 || s["lag_samples_1m"] != 10 || s["lag_p99_ms_1m"] != int64(0) || s["lag_p99_ms"] != int64(250) {
		t.Fatalf("summary after two minutes %v", s)
	}
}

func TestSignedRegion(t *testing.T) {
	cases := []struct{ auth, query, want string }{
		{"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261009/thessia-1/dynamodb/aws4_request, SignedHeaders=host, Signature=ab", "", "thessia-1"},
		{"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261009/us-east-1/s3/aws4_request,SignedHeaders=host,Signature=ab", "", "us-east-1"},
		{"", "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261009%2Fpalaven-1%2Fs3%2Faws4_request", "palaven-1"},
		{"AWS AKIAIOSFODNN7EXAMPLE:sig", "", ""},
		{"AWS4-HMAC-SHA256 Credential=broken", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		r, _ := http.NewRequest("GET", "http://x/b?"+c.query, nil)
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		if got := SignedRegion(r); got != c.want {
			t.Errorf("auth %q query %q: got %q, want %q", c.auth, c.query, got, c.want)
		}
	}
}
