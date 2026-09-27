package region

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"citadel/internal/store"
)

const testKey = "0123456789abcdef0123456789abcdef"

func writeRegistry(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "regions.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRegistry(t *testing.T) {
	const two = `{"home":"a-1","regions":[{"name":"a-1","endpoint":"http://127.0.0.1:1"},{"name":"b-1","endpoint":"http://127.0.0.1:2"}]%s}`
	for _, tc := range []struct {
		name, body, env, wantErr string
	}{
		{"ok with env key", strings.Replace(two, "%s", "", 1), testKey, ""},
		{"missing key", strings.Replace(two, "%s", "", 1), "", "shared key"},
		{"short key", strings.Replace(two, "%s", "", 1), "short", "shared key"},
		{"single region needs no key", `{"home":"a-1","regions":[{"name":"a-1","endpoint":"http://127.0.0.1:1"}]}`, "", ""},
		{"unknown home", `{"home":"z-1","regions":[{"name":"a-1","endpoint":"http://127.0.0.1:1"}]}`, "", "home region"},
		{"duplicate", `{"home":"a-1","regions":[{"name":"a-1","endpoint":"http://x"},{"name":"a-1","endpoint":"http://y"}]}`, testKey, "twice"},
		{"bad endpoint", `{"home":"a-1","regions":[{"name":"a-1","endpoint":"127.0.0.1:1"}]}`, "", "not an http"},
		{"no regions", `{"home":"a-1","regions":[]}`, "", "no regions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(KeyEnv, tc.env)
			_, err := Load(writeRegistry(t, tc.body))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Load: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Load error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadRegistryKeyFile(t *testing.T) {
	t.Setenv(KeyEnv, "")
	p := writeRegistry(t, `{"home":"a-1","key_file":"k","regions":[{"name":"a-1","endpoint":"http://h:1"},{"name":"b-1","endpoint":"http://h:2"}]}`)
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), "k"), []byte(testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.key) != testKey {
		t.Fatalf("key = %q", r.key)
	}
}

func testRegistry(endpoints map[string]string) *Registry {
	r := &Registry{Home: "home-1", key: []byte(testKey)}
	for _, n := range []string{"home-1", "follow-1"} {
		r.Regions = append(r.Regions, Region{Name: n, Endpoint: endpoints[n]})
	}
	return r
}

func TestRegionAuth(t *testing.T) {
	reg := testRegistry(nil)
	now := time.Unix(1_800_000_000, 0)
	signed := func() *http.Request {
		r := httptest.NewRequest("GET", "http://h"+ControlPath+"?since=4", nil)
		reg.sign(r, "follow-1", now)
		return r
	}
	for _, tc := range []struct {
		name   string
		mutate func(r *http.Request)
		at     time.Time
		ok     bool
	}{
		{"valid", func(*http.Request) {}, now, true},
		{"within skew", func(*http.Request) {}, now.Add(4 * time.Minute), true},
		{"too old", func(*http.Request) {}, now.Add(6 * time.Minute), false},
		{"tampered query", func(r *http.Request) { r.URL.RawQuery = "since=0" }, now, false},
		{"unknown region", func(r *http.Request) { r.Header.Set(hdrRegion, "rogue-1") }, now, false},
		{"other region's name", func(r *http.Request) { r.Header.Set(hdrRegion, "home-1") }, now, false},
		{"no signature", func(r *http.Request) { r.Header.Del(hdrSignature) }, now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := signed()
			tc.mutate(r)
			from, err := reg.verify(r, tc.at)
			if tc.ok != (err == nil) {
				t.Fatalf("verify = %q, %v; want ok=%v", from, err, tc.ok)
			}
			if tc.ok && from != "follow-1" {
				t.Fatalf("from = %q", from)
			}
		})
	}
	wrongKey := &Registry{Home: "home-1", Regions: reg.Regions, key: []byte("another key that is long enough")}
	if _, err := wrongKey.verify(signed(), now); err == nil {
		t.Fatal("verified with a different key")
	}
}

func openStore(t *testing.T, name string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addKey(t *testing.T, s *store.Store, ak string) {
	t.Helper()
	err := s.Update(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO accounts(id, canonical_id) VALUES ('111122223333', 'c')`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO access_keys(access_key, secret_key, account_id, user_name, created, kind) VALUES (?, 's', '111122223333', 'u', 1, 'user')`, ak)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFollowerPullsFeed(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	home, fol := openStore(t, "home-1"), openStore(t, "follow-1")
	reg := testRegistry(nil)
	srv := httptest.NewServer(FeedHandler(home, reg, "home-1", log))
	defer srv.Close()
	reg.Regions[0].Endpoint = srv.URL
	reg.Regions[1].Endpoint = "http://127.0.0.1:1"

	for i := range 7 {
		addKey(t, home, "KEY"+string(rune('A'+i)))
	}
	f := NewFollower(fol, reg, "follow-1", log)
	ctx := context.Background()
	// The account and seven keys fit in one page: one pull applies them all
	// and reports no backlog.
	more, err := f.pull(ctx)
	if err != nil || more {
		t.Fatalf("pull = %v, %v", more, err)
	}
	if _, _, err := fol.LookupKey(ctx, "KEYG"); err != nil {
		t.Fatalf("replicated key: %v", err)
	}
	f.record(nil)
	if st := f.Status(); st["control_seq"] != st["control_head"] || st["home_reachable"] != true {
		t.Fatalf("status = %v", st)
	}

	// A follower is not a feed source, and requests without the key are refused.
	for _, tc := range []struct {
		h    http.Handler
		sign bool
		want int
	}{
		{FeedHandler(fol, reg, "follow-1", log), true, http.StatusMisdirectedRequest},
		{FeedHandler(home, reg, "home-1", log), false, http.StatusForbidden},
	} {
		r := httptest.NewRequest("GET", ControlPath+"?since=0", nil)
		if tc.sign {
			reg.sign(r, "follow-1", time.Now())
		}
		w := httptest.NewRecorder()
		tc.h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("status %d, want %d", w.Code, tc.want)
		}
	}

	// Home unreachable: pull fails, status says so, the replica still serves.
	srv.Close()
	f.Client.Timeout = 200 * time.Millisecond
	_, err = f.pull(ctx)
	f.record(err)
	if err == nil || f.HomeUp() {
		t.Fatalf("pull against a closed home = %v, up %v", err, f.HomeUp())
	}
	if _, _, err := fol.LookupKey(ctx, "KEYA"); err != nil {
		t.Fatalf("replica lookup with home away: %v", err)
	}
}

func TestForwarder(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gotHost, gotBody string
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotHost, gotBody = r.Host, string(b)
		w.Header().Set("X-Home", "yes")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("from home"))
	}))
	defer home.Close()
	reg := testRegistry(map[string]string{"home-1": home.URL})
	local := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("local:" + string(b)))
	})
	up := true
	f := &Forwarder{Registry: reg, Local: local, HomeUp: func() bool { return up }, Client: &http.Client{Timeout: time.Second}, Logger: log}
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://follower.example:8440/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		return w
	}

	w := call("Action=CreateUser&UserName=a")
	if w.Code != 201 || w.Body.String() != "from home" || w.Header().Get("X-Home") != "yes" {
		t.Fatalf("forwarded: %d %q", w.Code, w.Body.String())
	}
	if gotHost != "follower.example:8440" || gotBody != "Action=CreateUser&UserName=a" {
		t.Fatalf("home saw host %q body %q", gotHost, gotBody)
	}

	up = false
	if w := call("Action=ListUsers"); w.Code != 200 || w.Body.String() != "local:Action=ListUsers" {
		t.Fatalf("read with home away: %d %q", w.Code, w.Body.String())
	}
	w = call("Action=CreateUser&UserName=b")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "<Code>ServiceUnavailable</Code>") {
		t.Fatalf("write with home away: %d %q", w.Code, w.Body.String())
	}

	// Home believed up but gone: the attempt fails over the same way.
	up = true
	home.Close()
	if w := call("Action=GetUser"); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "local:") {
		t.Fatalf("read after failed forward: %d %q", w.Code, w.Body.String())
	}
}
