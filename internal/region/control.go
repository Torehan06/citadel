package region

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"citadel/internal/store"
)

// ControlPath is where the home region serves its control-plane feed.
const ControlPath = "/_citadel/repl/control"

const (
	defaultBatch = 500
	maxBatch     = 2000
)

// feedPage is one response of the control feed.
type feedPage struct {
	Home    string               `json:"home"`
	Epoch   string               `json:"epoch"`
	Head    int64                `json:"head"` // newest seq in the home region's log
	Entries []store.ControlEntry `json:"entries"`
}

// FeedHandler serves GET ControlPath?since=<seq>&epoch=<epoch>&limit=<n> to
// the other regions. A follower whose epoch is not this database's gets the
// feed from the start: its cursor counts in a log that no longer exists.
func FeedHandler(st *store.Store, reg *Registry, self string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		from, err := reg.verify(r, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if self != reg.Home {
			http.Error(w, fmt.Sprintf("%s is not the home region (%s is)", self, reg.Home), http.StatusMisdirectedRequest)
			return
		}
		q := r.URL.Query()
		since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = defaultBatch
		}
		limit = min(limit, maxBatch)
		epoch, err := st.ControlEpoch(r.Context())
		if err != nil {
			logger.Error("control feed", "from", from, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if q.Get("epoch") != epoch {
			since = 0
		}
		entries, head, err := st.ControlSince(r.Context(), since, limit)
		if err != nil {
			logger.Error("control feed", "from", from, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []store.ControlEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(feedPage{Home: reg.Home, Epoch: epoch, Head: head, Entries: entries})
	})
}

// Follower replays the home region's control feed into this region's store.
// It pulls every Interval while it keeps up, straight away while a backlog
// remains, and backs off up to MaxBackoff while the home region is away.
// Serving never waits for it: requests read the local replica (static
// stability), so a stopped home region only delays new global changes.
type Follower struct {
	Store      *store.Store
	Registry   *Registry
	Self       string
	Logger     *slog.Logger
	Client     *http.Client
	Interval   time.Duration
	MaxBackoff time.Duration

	mu       sync.Mutex
	up       bool
	lastOK   time.Time
	lastErr  string
	head     int64
	cursor   store.ControlCursor
	failures int
}

// NewFollower returns a follower with the default timings.
func NewFollower(st *store.Store, reg *Registry, self string, logger *slog.Logger) *Follower {
	return &Follower{
		Store: st, Registry: reg, Self: self, Logger: logger,
		Client:     &http.Client{Timeout: 3 * time.Second},
		Interval:   250 * time.Millisecond,
		MaxBackoff: 5 * time.Second,
	}
}

// Run pulls until ctx ends.
func (f *Follower) Run(ctx context.Context) {
	if cur, err := f.Store.ControlCursor(ctx); err == nil {
		f.mu.Lock()
		f.cursor = cur
		f.mu.Unlock()
	}
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		more, err := f.pull(ctx)
		f.record(err)
		switch {
		case err != nil:
			f.mu.Lock()
			n := f.failures
			f.mu.Unlock()
			wait = min(f.Interval<<min(n, 10), f.MaxBackoff)
		case more:
			wait = 0
		default:
			wait = f.Interval
		}
	}
}

// pull fetches and applies one page; more reports a remaining backlog.
func (f *Follower) pull(ctx context.Context) (more bool, err error) {
	cur, err := f.Store.ControlCursor(ctx)
	if err != nil {
		return false, err
	}
	home := f.Registry.HomeRegion()
	q := url.Values{"since": {strconv.FormatInt(cur.Seq, 10)}, "epoch": {cur.Epoch}, "limit": {strconv.Itoa(defaultBatch)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, home.Endpoint+ControlPath+"?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	f.Registry.sign(req, f.Self, time.Now())
	resp, err := f.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("home region %s answered %s", home.Name, resp.Status)
	}
	var page feedPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return false, fmt.Errorf("decode control feed: %w", err)
	}
	if err := f.Store.ApplyControl(ctx, page.Epoch, page.Entries); err != nil {
		return false, err
	}
	cur, err = f.Store.ControlCursor(ctx)
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	f.cursor, f.head = cur, page.Head
	f.mu.Unlock()
	return cur.Seq < page.Head, nil
}

func (f *Follower) record(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		if !f.up {
			f.Logger.Info("home region reachable", "home", f.Registry.Home, "seq", f.cursor.Seq)
		}
		f.up, f.lastOK, f.lastErr, f.failures = true, time.Now(), "", 0
		return
	}
	f.failures++
	if f.up || f.failures == 1 {
		f.Logger.Warn("home region unreachable; serving from the local replica", "home", f.Registry.Home, "err", err)
	}
	f.up, f.lastErr = false, err.Error()
}

// HomeUp reports whether the last pull reached the home region.
func (f *Follower) HomeUp() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up
}

// Status describes the follower for /_citadel/healthz.
func (f *Follower) Status() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := map[string]any{
		"role": "follower", "home": f.Registry.Home, "home_reachable": f.up,
		"control_seq": f.cursor.Seq, "control_head": f.head,
	}
	if !f.lastOK.IsZero() {
		st["last_sync"] = f.lastOK.UTC().Format(time.RFC3339Nano)
	}
	if f.lastErr != "" {
		st["last_error"] = f.lastErr
	}
	return st
}
