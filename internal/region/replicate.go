package region

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	"citadel/internal/store"
)

// Data-plane replication (ARCHITECTURE.md §8). The source region tails its
// change log once per destination region, with a durable cursor each, and
// hands every batch to the services (Shippers). A service picks the changes
// that concern that destination and pushes their current state over
// /_citadel/repl/... . The cursor only moves once every service has shipped
// the batch, so a destination that is down or asleep just accumulates a
// backlog that drains when it returns. Applies are idempotent (versions by
// ID, items last-writer-wins), so re-sending a batch after a failure is safe.

// Peer is another region as a replication destination.
type Peer struct {
	Name     string
	Endpoint string

	reg    *Registry
	self   string
	client *http.Client
}

// Do sends a signed request to the peer. path is under /_citadel/.
func (p *Peer) Do(ctx context.Context, method, path string, q url.Values, body io.Reader, hdr http.Header) (*http.Response, error) {
	u := p.Endpoint + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	p.reg.sign(req, p.self, time.Now())
	return p.client.Do(req)
}

// Region returns the peer's name.
func (p *Peer) Region() string { return p.Name }

// Shipper is a service that replicates what its changes did.
type Shipper interface {
	// Ship pushes to peer the effect of the changes (oldest first) that
	// concern it and returns the ones it delivered. An error means the batch
	// is retried later from its start.
	Ship(ctx context.Context, peer *Peer, changes []store.Change) (delivered []store.Change, err error)
}

// Repairer is a service that can compare its replicated state with a peer's
// and repair the differences (anti-entropy).
type Repairer interface {
	Repair(ctx context.Context, peer *Peer) error
}

// Replicator runs one worker per destination region.
type Replicator struct {
	Store    *store.Store
	Registry *Registry
	Self     string
	Logger   *slog.Logger
	Shippers []Shipper
	// Interval is how often an idle worker looks for new changes;
	// MaxBackoff caps the wait after failures; AntiEntropy is the period
	// of digest comparisons with each peer (0 disables them).
	Interval    time.Duration
	MaxBackoff  time.Duration
	AntiEntropy time.Duration

	workers []*worker
	kick    chan string
}

// NewReplicator returns a replicator with the default timings.
func NewReplicator(st *store.Store, reg *Registry, self string, logger *slog.Logger, shippers ...Shipper) *Replicator {
	r := &Replicator{
		Store: st, Registry: reg, Self: self, Logger: logger, Shippers: shippers,
		Interval: 100 * time.Millisecond, MaxBackoff: 5 * time.Second, AntiEntropy: time.Minute,
		kick: make(chan string, 16),
	}
	for _, g := range reg.Regions {
		if g.Name == self {
			continue
		}
		p := &Peer{Name: g.Name, Endpoint: g.Endpoint, reg: reg, self: self,
			client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
				MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: 10 * time.Second,
				ExpectContinueTimeout: time.Second,
			}}}
		r.workers = append(r.workers, &worker{r: r, peer: p, lag: newLagWindow(2048)})
	}
	return r
}

// Peer returns the named destination region.
func (r *Replicator) Peer(name string) (*Peer, bool) {
	for _, w := range r.workers {
		if w.peer.Name == name {
			return w.peer, true
		}
	}
	return nil, false
}

// Peers returns every other region.
func (r *Replicator) Peers() []*Peer {
	out := make([]*Peer, len(r.workers))
	for i, w := range r.workers {
		out[i] = w.peer
	}
	return out
}

// Repair asks for an anti-entropy pass against one peer soon (for example
// right after a new replica was added). Unknown names are ignored.
func (r *Replicator) Repair(peer string) {
	select {
	case r.kick <- peer:
	default:
	}
}

// Run starts the workers and blocks until ctx ends.
func (r *Replicator) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, w := range r.workers {
		wg.Add(1)
		go func() { defer wg.Done(); w.run(ctx) }()
	}
	if r.AntiEntropy > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); r.antiEntropy(ctx) }()
	}
	wg.Wait()
}

func (r *Replicator) antiEntropy(ctx context.Context) {
	repairers := []Repairer{}
	for _, s := range r.Shippers {
		if rp, ok := s.(Repairer); ok {
			repairers = append(repairers, rp)
		}
	}
	pass := func(w *worker) {
		for _, rp := range repairers {
			if err := rp.Repair(ctx, w.peer); err != nil && ctx.Err() == nil {
				r.Logger.Debug("anti-entropy", "dest", w.peer.Name, "err", err)
				w.aeFailed(err)
				return
			}
		}
		w.aeDone()
	}
	// Stagger the first pass so regions started together don't all compare at once.
	tick := time.NewTimer(r.AntiEntropy/4 + rand.N(r.AntiEntropy/4+1))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case name := <-r.kick:
			for _, w := range r.workers {
				if w.peer.Name == name {
					pass(w)
				}
			}
		case <-tick.C:
			for _, w := range r.workers {
				pass(w)
			}
			tick.Reset(r.AntiEntropy)
		}
	}
}

// Status describes every destination for /_citadel/healthz.
func (r *Replicator) Status(ctx context.Context) map[string]any {
	var head int64
	_ = r.Store.DB().QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM changes`).Scan(&head)
	out := map[string]any{}
	for _, w := range r.workers {
		out[w.peer.Name] = w.status(head)
	}
	return out
}

type worker struct {
	r    *Replicator
	peer *Peer
	lag  *lagWindow

	mu        sync.Mutex
	cursor    int64
	failures  int
	lastErr   string
	lastOK    time.Time
	delivered int64
	aeOK      time.Time
	aeErr     string
}

func (w *worker) cursorName() string { return "repl:" + w.peer.Name }

// loadCursor returns the last change handled for this destination, starting
// at the head of the log the first time: what happened before replication
// was set up is anti-entropy's business, not the stream's.
func (w *worker) loadCursor(ctx context.Context) (int64, error) {
	var seq int64
	err := w.r.Store.DB().QueryRowContext(ctx, `SELECT seq FROM feed_cursors WHERE name = ?`, w.cursorName()).Scan(&seq)
	if err == nil {
		return seq, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err := w.r.Store.DB().QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM changes`).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, w.saveCursor(ctx, seq)
}

func (w *worker) saveCursor(ctx context.Context, seq int64) error {
	return w.r.Store.Update(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO feed_cursors(name, seq) VALUES (?, ?)
			ON CONFLICT(name) DO UPDATE SET seq = excluded.seq`, w.cursorName(), seq)
		return err
	})
}

func (w *worker) run(ctx context.Context) {
	var cursor int64
	for {
		c, err := w.loadCursor(ctx)
		if err == nil {
			cursor = c
			break
		}
		w.r.Logger.Error("replication cursor", "dest", w.peer.Name, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	w.mu.Lock()
	w.cursor = cursor
	w.mu.Unlock()
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		next, more, err := w.step(ctx, cursor)
		if ctx.Err() != nil {
			return
		}
		w.record(err)
		switch {
		case err != nil:
			w.mu.Lock()
			n := w.failures
			w.mu.Unlock()
			wait = min(w.r.Interval<<min(n, 10), w.r.MaxBackoff)
		case more:
			wait = 0
		default:
			wait = w.r.Interval
		}
		cursor = next
	}
}

const shipBatch = 256

// step ships the next batch after cursor and returns the new cursor.
func (w *worker) step(ctx context.Context, cursor int64) (next int64, more bool, err error) {
	changes, err := w.r.Store.ChangesSince(ctx, cursor, shipBatch)
	if err != nil || len(changes) == 0 {
		return cursor, false, err
	}
	var delivered []store.Change
	for _, s := range w.r.Shippers {
		d, err := s.Ship(ctx, w.peer, changes)
		if err != nil {
			return cursor, false, fmt.Errorf("ship to %s: %w", w.peer.Name, err)
		}
		delivered = append(delivered, d...)
	}
	next = changes[len(changes)-1].Seq
	if err := w.saveCursor(ctx, next); err != nil {
		return cursor, false, err
	}
	now := time.Now()
	for _, c := range delivered {
		w.lag.add(now.Sub(c.HLC.Time()))
	}
	w.mu.Lock()
	w.cursor = next
	w.delivered += int64(len(delivered))
	w.mu.Unlock()
	return next, len(changes) == shipBatch, nil
}

func (w *worker) record(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err == nil {
		if w.failures > 0 {
			w.r.Logger.Info("replication resumed", "dest", w.peer.Name, "cursor", w.cursor)
		}
		w.failures, w.lastErr, w.lastOK = 0, "", time.Now()
		return
	}
	w.failures++
	if w.failures == 1 {
		w.r.Logger.Warn("replication paused; retrying with backoff", "dest", w.peer.Name, "err", err)
	}
	w.lastErr = err.Error()
}

func (w *worker) aeDone() {
	w.mu.Lock()
	w.aeOK, w.aeErr = time.Now(), ""
	w.mu.Unlock()
}

func (w *worker) aeFailed(err error) {
	w.mu.Lock()
	w.aeErr = err.Error()
	w.mu.Unlock()
}

func (w *worker) status(head int64) map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := map[string]any{
		"cursor": w.cursor, "backlog": max(head-w.cursor, 0), "delivered": w.delivered,
		"healthy": w.failures == 0,
	}
	for k, v := range w.lag.summary() {
		st[k] = v
	}
	if !w.lastOK.IsZero() {
		st["last_ok"] = w.lastOK.UTC().Format(time.RFC3339Nano)
	}
	if w.lastErr != "" {
		st["last_error"] = w.lastErr
	}
	if !w.aeOK.IsZero() {
		st["anti_entropy_ok"] = w.aeOK.UTC().Format(time.RFC3339Nano)
	}
	if w.aeErr != "" {
		st["anti_entropy_error"] = w.aeErr
	}
	return st
}

// lagWindow keeps the most recent replication lags (commit in the source
// region to acknowledgement by the destination).
type lagWindow struct {
	mu   sync.Mutex
	buf  []time.Duration
	next int
	full bool
	max  time.Duration
}

func newLagWindow(n int) *lagWindow { return &lagWindow{buf: make([]time.Duration, n)} }

func (l *lagWindow) add(d time.Duration) {
	d = max(d, 0)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf[l.next] = d
	l.next++
	if l.next == len(l.buf) {
		l.next, l.full = 0, true
	}
	l.max = max(l.max, d)
}

// summary reports lag percentiles in milliseconds over the window.
func (l *lagWindow) summary() map[string]any {
	l.mu.Lock()
	n := l.next
	if l.full {
		n = len(l.buf)
	}
	s := slices.Clone(l.buf[:n])
	maxEver := l.max
	l.mu.Unlock()
	if n == 0 {
		return map[string]any{"lag_samples": 0}
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) int64 { return s[min(int(p*float64(n)), n-1)].Milliseconds() }
	return map[string]any{
		"lag_samples": n, "lag_p50_ms": q(0.50), "lag_p99_ms": q(0.99),
		"lag_window_max_ms": s[n-1].Milliseconds(), "lag_max_ms": maxEver.Milliseconds(),
	}
}

// Authenticate wraps an internal handler so only other regions of this
// registry can call it. The caller's region is passed on in X-Citadel-Region.
func (r *Registry) Authenticate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := r.verify(req, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, req)
	})
}

// CallerRegion returns the region an authenticated internal request came from.
func CallerRegion(req *http.Request) string { return req.Header.Get(hdrRegion) }
