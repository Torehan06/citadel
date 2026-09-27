package region

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"citadel/internal/api"
)

// hopHeaders are connection-scoped and never forwarded.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// Forwarder sends IAM calls that reach a follower to the home region, the one
// writer of global state, as AWS sends every IAM call to us-east-1. The request
// goes on byte for byte, Host header included, so the caller's SigV4
// signature still verifies there. If the home region can't be reached, reads
// (Get*, List*) are answered from the local replica and everything else fails
// with ServiceUnavailable until it returns.
type Forwarder struct {
	Registry *Registry
	Local    http.Handler // this region's IAM handler, for reads while home is away
	HomeUp   func() bool  // the follower's view; false skips the attempt
	Client   *http.Client
	Logger   *slog.Logger
}

func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		api.WriteError(w, r, api.SvcIAM, 400, "IncompleteBody", "The request body could not be read.")
		return
	}
	action := iamAction(r, body)
	if f.HomeUp == nil || f.HomeUp() {
		if f.forward(w, r, body) {
			return
		}
	}
	if isRead(action) {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		f.Local.ServeHTTP(w, r)
		return
	}
	api.WriteError(w, r, api.SvcIAM, http.StatusServiceUnavailable, "ServiceUnavailable",
		"IAM changes are made in the home region "+f.Registry.Home+", which is unreachable. Retry when it returns.")
}

// forward relays the request and reports whether a response came back.
func (f *Forwarder) forward(w http.ResponseWriter, r *http.Request, body []byte) bool {
	home := f.Registry.HomeRegion()
	out, err := http.NewRequestWithContext(r.Context(), r.Method, home.Endpoint+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return false
	}
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	out.Host = r.Host
	start := time.Now()
	resp, err := f.Client.Do(out)
	if err != nil {
		f.Logger.Warn("forward IAM call to the home region", "home", home.Name, "err", err, "ms", time.Since(start).Milliseconds())
		return false
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	for _, h := range hopHeaders {
		w.Header().Del(h)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	return true
}

// iamAction returns the query-protocol Action of an IAM request.
func iamAction(r *http.Request, body []byte) string {
	if vals, err := url.ParseQuery(string(body)); err == nil && vals.Get("Action") != "" {
		return vals.Get("Action")
	}
	return r.URL.Query().Get("Action")
}

// isRead reports whether an IAM action only reads state, so the local
// replica can answer it while the home region is away.
func isRead(action string) bool {
	return strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List")
}
