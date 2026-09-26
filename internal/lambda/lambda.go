// Package lambda implements AWS Lambda for a Citadel region: the REST-JSON
// control plane (functions, versions, aliases, event source mappings) and a
// WebAssembly runtime that runs each function's bootstrap.wasm under wazero
// (ARCHITECTURE.md §9). Function logs are kept as CloudWatch Logs streams,
// served by the minimal Logs API in logs.go.
package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"citadel/internal/iam"
	"citadel/internal/sigv4"
	"citadel/internal/store"
)

// ObjectOpener reads an S3 object on behalf of an account: Lambda fetches
// deployment packages named by S3Bucket/S3Key through it.
type ObjectOpener interface {
	OpenObject(ctx context.Context, account, bucket, key string) (io.ReadCloser, int64, error)
}

// Handler serves the Lambda API and owns the region's function runtime.
type Handler struct {
	st     *store.Store
	auth   *sigv4.Verifier
	region string
	log    *slog.Logger
	now    func() time.Time

	// IAM enforces identity policies for IAM users and role sessions; nil
	// allows every authenticated caller everything in its account.
	IAM *iam.Authorizer
	// S3 reads deployment packages from buckets; nil rejects S3 code.
	S3 ObjectOpener
	// SQS feeds event source mappings; nil leaves mappings idle.
	SQS QueueClient

	rt      *wasmRuntime
	running sync.Map // function key -> *int64 in-flight invocations

	mu      sync.Mutex
	pollers map[string]context.CancelFunc // ESM UUID -> stop
	wake    chan struct{}                 // async queue has work
	streams map[string]string             // "acct/region/fn/version/day" -> log stream name
	bg      context.Context
	stop    context.CancelFunc
}

// New creates the handler. dataDir holds the wazero compilation cache.
func New(st *store.Store, auth *sigv4.Verifier, region, dataDir string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{
		st: st, auth: auth, region: region, log: logger, now: time.Now,
		pollers: map[string]context.CancelFunc{},
		wake:    make(chan struct{}, 1),
		streams: map[string]string{},
	}
	h.rt = newRuntime(dataDir, logger)
	h.bg, h.stop = context.WithCancel(context.Background())
	return h
}

// apiError is a Lambda error: REST-JSON, with the type in x-amzn-ErrorType.
type apiError struct {
	Status  int
	Code    string
	Message string
	Extra   map[string]any // additional body members (e.g. Type, Reason)
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func errf(status int, code, format string, args ...any) *apiError {
	return &apiError{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}
func notFound(format string, args ...any) *apiError {
	return errf(404, "ResourceNotFoundException", format, args...)
}
func invalid(format string, args ...any) *apiError {
	return errf(400, "InvalidParameterValueException", format, args...)
}
func validation(format string, args ...any) *apiError {
	return errf(400, "ValidationException", format, args...)
}
func conflict(format string, args ...any) *apiError {
	return errf(409, "ResourceConflictException", format, args...)
}

func asAPIError(err error) *apiError {
	var e *apiError
	if errors.As(err, &e) {
		return e
	}
	var se *sigv4.Error
	if errors.As(err, &se) {
		return &apiError{Status: 403, Code: se.Code, Message: se.Message}
	}
	return &apiError{Status: 500, Code: "ServiceException", Message: "Internal server error"}
}

func writeError(w http.ResponseWriter, e *apiError) {
	body := map[string]any{"Type": "User", "message": e.Message}
	if e.Status >= 500 {
		body["Type"] = "Service"
	}
	for k, v := range e.Extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-ErrorType", e.Code)
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// call is one authenticated request.
type call struct {
	ctx     context.Context
	r       *http.Request
	who     *store.Principal
	account string
	region  string
	params  map[string]string // path parameters
	query   url.Values
	body    []byte
}

// partition returns the ARN partition a region belongs to.
func partition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	}
	return "aws"
}

// arnPrefix is "arn:aws:lambda:region:account:" for the call's account.
func (c *call) arnPrefix() string {
	return "arn:" + partition(c.region) + ":lambda:" + c.region + ":" + c.account + ":"
}

// decode unmarshals the JSON body into v; an empty body leaves v as is.
func (c *call) decode(v any) error {
	if len(strings.TrimSpace(string(c.body))) == 0 {
		return nil
	}
	if err := json.Unmarshal(c.body, v); err != nil {
		return errf(400, "SerializationException", "Could not parse request body into json: %v", err)
	}
	return nil
}

// result is a successful response: a status, optional headers and a body
// (JSON-encoded unless raw is set).
type result struct {
	status int
	header http.Header
	body   any
	raw    []byte
}

func ok(status int, body any) *result { return &result{status: status, body: body} }

// route maps a REST path template to an operation.
type route struct {
	method string
	path   []string // segments; "{x}" captures a parameter
	op     string
	fn     func(h *Handler, c *call) (*result, error)
}

var routes []route

func handle(method, path, op string, fn func(h *Handler, c *call) (*result, error)) {
	routes = append(routes, route{method: method, path: strings.Split(strings.Trim(path, "/"), "/"), op: op, fn: fn})
}

func match(r *http.Request) (*route, map[string]string) {
	raw := strings.Trim(r.URL.EscapedPath(), "/")
	segs := strings.Split(raw, "/")
	for i := range routes {
		rt := &routes[i]
		if rt.method != r.Method || len(rt.path) != len(segs) {
			continue
		}
		params := map[string]string{}
		okay := true
		for j, p := range rt.path {
			seg, err := url.PathUnescape(segs[j])
			if err != nil {
				okay = false
				break
			}
			if strings.HasPrefix(p, "{") {
				params[p[1:len(p)-1]] = seg
			} else if p != seg {
				okay = false
				break
			}
		}
		if okay {
			return rt, params
		}
	}
	return nil, nil
}

// ServeHTTP authenticates the request, routes it and writes the result.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, params := match(r)
	if rt == nil {
		writeError(w, errf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", r.Method, r.URL.Path))
		return
	}
	res, err := h.serve(r, rt, params)
	if err != nil {
		e := asAPIError(err)
		if e.Status == 500 {
			h.log.Error("lambda internal error", "op", rt.op, "err", err)
		}
		writeError(w, e)
		return
	}
	for k, vs := range res.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if res.raw != nil {
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(res.status)
		_, _ = w.Write(res.raw)
		return
	}
	if res.body == nil {
		w.WriteHeader(res.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.status)
	_ = json.NewEncoder(w).Encode(res.body)
}

// maxRequest bounds a request body: a 50 MB zip, base64-encoded, plus JSON.
const maxRequest = 70 << 20

func (h *Handler) serve(r *http.Request, rt *route, params map[string]string) (*result, error) {
	auth, err := h.auth.Verify(r)
	if err != nil {
		return nil, err
	}
	if auth.Anonymous {
		return nil, errf(403, "MissingAuthenticationTokenException", "Missing Authentication Token")
	}
	_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return nil, errf(403, "UnrecognizedClientException", "The security token included in the request is invalid.")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRequest {
		return nil, errf(413, "RequestEntityTooLargeException", "Request must be smaller than %d bytes for the %s operation", maxRequest, rt.op)
	}
	c := &call{
		ctx: r.Context(), r: r, who: &who, account: who.Account.ID, region: auth.Region,
		params: params, query: r.URL.Query(), body: body,
	}
	if c.region == "" {
		c.region = h.region
	}
	return rt.fn(h, c)
}

// authorize checks the caller's identity policies for a Lambda action on a
// resource ARN ("*" for account-level operations).
func (h *Handler) authorize(c *call, action, resource string) error {
	if h.IAM == nil || iam.IsRoot(c.who) {
		return nil
	}
	d, err := h.IAM.Require(c.ctx, c.who, "lambda:"+action, []string{resource}, nil)
	if err != nil {
		return err
	}
	if d != nil {
		return errf(403, "AccessDeniedException", "%s", iam.DeniedMessage(c.who, d.Action, d.Resource, d.Explicit))
	}
	return nil
}

// Reset wipes all Lambda and CloudWatch Logs state (moto's /moto-api/reset).
func (h *Handler) Reset() {
	h.mu.Lock()
	for id, stop := range h.pollers {
		stop()
		delete(h.pollers, id)
	}
	h.streams = map[string]string{}
	h.mu.Unlock()
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		for _, t := range []string{"lambda_functions", "lambda_esm", "lambda_async", "logs_groups"} {
			if _, err := tx.Exec(`DELETE FROM ` + t); err != nil {
				return err
			}
		}
		return tx.Change("lambda", "Reset", "", nil)
	})
	if err != nil {
		h.log.Error("reset lambda", "err", err)
	}
}

// Close stops background work (pollers, the async queue).
func (h *Handler) Close() {
	h.stop()
	h.rt.close()
}

func isoMillis(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000-0700") }

func intParam(q url.Values, name string, def int) (int, error) {
	v := q.Get(name)
	if v == "" {
		return def, nil
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return 0, invalid("Invalid value for %s: %s", name, v)
	}
	return n, nil
}
