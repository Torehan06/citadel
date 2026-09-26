// Package api is the HTTP front door of a Citadel region: it identifies which
// AWS API a request targets and hands it to that service's handler.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"citadel/internal/bootstrap"
)

type Config struct {
	Region    string
	DataDir   string
	Version   string
	Bootstrap *bootstrap.File
	// Conformance enables test-only endpoints (e.g. moto's /moto-api/reset).
	// Never set it on a real region.
	Conformance bool
	Logger      *slog.Logger
}

type Server struct {
	cfg       Config
	started   time.Time
	handlers  map[string]http.Handler
	internals map[string]http.Handler // path prefix under /_citadel/ -> handler
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg, started: time.Now(), handlers: map[string]http.Handler{}, internals: map[string]http.Handler{}}
}

// HandleInternal serves a path prefix under /_citadel/ (for example Lambda's
// code download URLs, which are presigned and so carry no SigV4 header).
func (s *Server) HandleInternal(prefix string, h http.Handler) { s.internals[prefix] = h }

// Handle registers the handler for one AWS service (use the Svc* constants).
// Services without a handler answer NotImplemented in their own wire format.
func (s *Server) Handle(svc string, h http.Handler) { s.handlers[svc] = h }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := newRequestID()
	w.Header().Set("x-amz-request-id", reqID)
	w.Header().Set("x-amzn-RequestId", reqID)
	w.Header().Set("Server", "Citadel")

	// Internal endpoints live under /_citadel/, which is not a valid S3 bucket
	// name (underscore), so they can never collide with a bucket.
	if strings.HasPrefix(r.URL.Path, "/_citadel/") {
		s.internal(w, r)
		return
	}
	if s.cfg.Conformance && strings.HasPrefix(r.URL.Path, "/moto-api/") {
		s.motoAPI(w, r)
		return
	}

	svc := DetectService(r)
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	if h, ok := s.handlers[svc]; ok {
		h.ServeHTTP(rec, r)
	} else {
		NotImplemented(rec, r, svc)
	}
	s.cfg.Logger.Info("request",
		"svc", svc, "method", r.Method, "path", r.URL.Path,
		"status", rec.status, "ms", time.Since(start).Milliseconds(), "req_id", reqID)
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_citadel/healthz":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"region":  s.cfg.Region,
			"version": s.cfg.Version,
			"uptime":  time.Since(s.started).Round(time.Second).String(),
		})
	default:
		for prefix, h := range s.internals {
			if strings.HasPrefix(r.URL.Path, prefix) {
				h.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	}
}

// motoAPI implements the tiny slice of moto's server-mode control API that
// moto's own test suite calls between tests. Services must clear their state
// here once they exist (see AGENTS.md: reset must wipe state, nothing else).
func (s *Server) motoAPI(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/moto-api/reset", "/moto-api/reset-auth":
		for _, h := range s.handlers {
			if rs, ok := h.(interface{ Reset() }); ok {
				rs.Reset()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	default:
		http.NotFound(w, r)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming responses (long polls, large GETs) working through the recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}
