// Package lambda implements the Lambda REST-JSON API and runs functions as
// WebAssembly modules on wazero (ARCHITECTURE.md §9).
package lambda

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"citadel/internal/logs"
	"citadel/internal/sigv4"
	"citadel/internal/store"
)

// CodeSource reads deployment packages from S3 (CreateFunction and
// UpdateFunctionCode with S3Bucket/S3Key).
type CodeSource interface {
	OpenObject(ctx context.Context, account, bucket, key, version string) (io.ReadCloser, int64, error)
}

// QueueService runs SQS operations on an account's behalf (event source
// mappings, destinations, dead-letter queues).
type QueueService interface {
	Call(ctx context.Context, account, region, op string, in map[string]any) (map[string]any, error)
}

type Handler struct {
	st      *store.Store
	auth    *sigv4.Verifier
	region  string
	log     *slog.Logger
	now     func() time.Time
	secret  []byte // signs code download URLs
	envID   string // this process's "execution environment", named in log streams
	runtime *Runtime

	// IAM enforces identity policies for IAM users and role sessions.
	IAM  *iam.Authorizer
	Logs *logs.Handler
	S3   CodeSource
	SQS  QueueService

	mu       sync.Mutex
	inflight map[string]int // function key -> running invocations
	total    int
	pollers  map[string]*poller // event source mapping UUID -> poller
	wake     chan struct{}      // async queue has new work
	ctx      context.Context    // background work (pollers, async workers)
}

func New(st *store.Store, auth *sigv4.Verifier, region, dataDir string, logger *slog.Logger) (*Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cacheDir := ""
	if dataDir != "" {
		cacheDir = dataDir + "/wasm-cache"
	}
	rt, err := NewRuntime(cacheDir)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	env := make([]byte, 16)
	_, _ = rand.Read(env)
	return &Handler{
		st: st, auth: auth, region: region, log: logger, now: time.Now, secret: secret,
		envID: hex.EncodeToString(env), runtime: rt,
		inflight: map[string]int{}, pollers: map[string]*poller{}, wake: make(chan struct{}, 1),
		ctx: context.Background(),
	}, nil
}

// Start runs the region's background work until ctx ends: event source
// mapping pollers and the asynchronous invocation queue.
func (h *Handler) Start(ctx context.Context) {
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
	h.syncPollers()
	for i := 0; i < asyncWorkers; i++ {
		go h.asyncWorker(ctx)
	}
	go func() {
		<-ctx.Done()
		h.stopPollers()
		h.runtime.Close()
	}()
}

// Reset wipes every function, mapping and queued invocation.
func (h *Handler) Reset() {
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		for _, t := range []string{"lambda_functions", "lambda_mappings", "lambda_async"} {
			if _, err := tx.Exec(`DELETE FROM ` + t); err != nil {
				return err
			}
		}
		return tx.Change("lambda", "Reset", "", nil)
	})
	if err != nil {
		h.log.Error("reset lambda", "err", err)
	}
	h.stopPollers()
}

// ---- errors ---------------------------------------------------------------------

type serviceError struct {
	Status        int
	Code, Message string
	Header        http.Header
}

func (e *serviceError) Error() string { return e.Code + ": " + e.Message }

func errorf(status int, code, format string, args ...any) *serviceError {
	return &serviceError{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

func invalidParam(format string, args ...any) *serviceError {
	return errorf(400, "InvalidParameterValueException", format, args...)
}

// validation is AWS's single-field constraint message.
func validation(value, field, constraint string) *serviceError {
	return errorf(400, "ValidationException", "1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: %s", value, field, constraint)
}

func notFound(format string, args ...any) *serviceError {
	return errorf(404, "ResourceNotFoundException", format, args...)
}

func conflict(format string, args ...any) *serviceError {
	return errorf(409, "ResourceConflictException", format, args...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var e *serviceError
	if !errors.As(err, &e) {
		var se *sigv4.Error
		if errors.As(err, &se) {
			e = &serviceError{Status: 403, Code: se.Code, Message: se.Message}
		} else {
			h.log.Error("lambda internal error", "method", r.Method, "path", r.URL.Path, "err", err)
			e = &serviceError{Status: 500, Code: "ServiceException", Message: "Internal server error"}
		}
	}
	for k, v := range e.Header {
		w.Header()[k] = v
	}
	w.Header().Set("x-amzn-ErrorType", e.Code)
	body := map[string]string{"Type": errType(e.Status), "message": e.Message}
	var th *throttled
	if errors.As(err, &th) {
		body["Reason"] = th.reason
	}
	writeJSON(w, e.Status, body)
}

func errType(status int) string {
	if status >= 500 {
		return "Service"
	}
	return "User"
}

// ---- requests -------------------------------------------------------------------

type call struct {
	ctx             context.Context
	r               *http.Request
	w               http.ResponseWriter
	account, region string
	who             *store.Principal
	host, scheme    string
}

func (c *call) query(k string) string { return c.r.URL.Query().Get(k) }

// decode reads a JSON request body into v (an empty body is an empty object).
func (c *call) decode(v any, limit int64) error {
	body, err := io.ReadAll(io.LimitReader(c.r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errorf(413, "RequestEntityTooLargeException", "Request must be smaller than %d bytes for the %s operation", limit, "request")
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return invalidParam("Could not parse request body into json: %v", err)
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serve(w, r); err != nil {
		h.writeError(w, r, err)
	}
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) error {
	auth, err := h.auth.Verify(r)
	if err != nil {
		return err
	}
	if auth.Anonymous {
		return errorf(403, "MissingAuthenticationTokenException", "Missing Authentication Token")
	}
	_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return errorf(403, "UnrecognizedClientException", "The security token included in the request is invalid.")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	c := &call{ctx: r.Context(), r: r, w: w, account: who.Account.ID, region: auth.Region, who: &who, host: r.Host, scheme: scheme}
	if c.region == "" {
		c.region = h.region
	}
	var segs []string
	for _, s := range strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/") {
		u, err := url.PathUnescape(s)
		if err != nil {
			return invalidParam("Invalid path")
		}
		segs = append(segs, u)
	}
	return h.route(c, segs)
}

// route dispatches on the API version prefix and the resource path.
func (h *Handler) route(c *call, p []string) error {
	m := c.r.Method
	at := func(i int) string {
		if i < len(p) {
			return p[i]
		}
		return ""
	}
	n := len(p)
	switch at(0) {
	case "2015-03-31":
		switch at(1) {
		case "functions":
			switch {
			case n == 2 && m == http.MethodPost:
				return h.createFunction(c)
			case n == 2 && m == http.MethodGet:
				return h.listFunctions(c)
			case n == 3 && m == http.MethodGet:
				return h.getFunction(c, p[2])
			case n == 3 && m == http.MethodDelete:
				return h.deleteFunction(c, p[2])
			case n == 4 && p[3] == "configuration" && m == http.MethodGet:
				return h.getFunctionConfiguration(c, p[2])
			case n == 4 && p[3] == "configuration" && m == http.MethodPut:
				return h.updateFunctionConfiguration(c, p[2])
			case n == 4 && p[3] == "code" && m == http.MethodPut:
				return h.updateFunctionCode(c, p[2])
			case n == 4 && p[3] == "versions" && m == http.MethodPost:
				return h.publishVersion(c, p[2])
			case n == 4 && p[3] == "versions" && m == http.MethodGet:
				return h.listVersions(c, p[2])
			case n == 4 && p[3] == "aliases" && m == http.MethodPost:
				return h.createAlias(c, p[2])
			case n == 4 && p[3] == "aliases" && m == http.MethodGet:
				return h.listAliases(c, p[2])
			case n == 5 && p[3] == "aliases":
				return h.alias(c, p[2], p[4])
			case n == 4 && p[3] == "invocations" && m == http.MethodPost:
				return h.invoke(c, p[2])
			case n == 4 && p[3] == "policy" && m == http.MethodPost:
				return h.addPermission(c, p[2])
			case n == 4 && p[3] == "policy" && m == http.MethodGet:
				return h.getPolicy(c, p[2])
			case n == 5 && p[3] == "policy" && m == http.MethodDelete:
				return h.removePermission(c, p[2], p[4])
			}
		case "event-source-mappings":
			switch {
			case n == 2 && m == http.MethodPost:
				return h.createMapping(c)
			case n == 2 && m == http.MethodGet:
				return h.listMappings(c)
			case n == 3:
				return h.mapping(c, p[2])
			}
		}
	case "2014-11-13":
		if n == 4 && at(1) == "functions" && p[3] == "invoke-async" && m == http.MethodPost {
			return h.invokeAsyncLegacy(c, p[2])
		}
	case "2017-03-31":
		if n == 3 && at(1) == "tags" {
			return h.tags(c, p[2])
		}
	case "2017-10-31":
		if n == 4 && at(1) == "functions" && p[3] == "concurrency" {
			return h.concurrency(c, p[2])
		}
	case "2019-09-30":
		if n == 4 && at(1) == "functions" && p[3] == "concurrency" && m == http.MethodGet {
			return h.concurrency(c, p[2])
		}
	case "2019-09-25":
		if at(1) == "functions" && at(3) == "event-invoke-config" {
			if n == 5 && p[4] == "list" && m == http.MethodGet {
				return h.listEventInvokeConfigs(c, p[2])
			}
			if n == 4 {
				return h.eventInvokeConfig(c, p[2])
			}
		}
	case "2021-10-31":
		if n == 4 && at(1) == "functions" && p[3] == "url" {
			return h.urlConfig(c, p[2])
		}
		if n == 4 && at(1) == "functions" && p[3] == "urls" && m == http.MethodGet {
			return h.listURLConfigs(c, p[2])
		}
	case "2020-06-30":
		if n == 4 && at(1) == "functions" && p[3] == "code-signing-config" {
			return h.codeSigning(c, p[2])
		}
	case "2016-08-19":
		if at(1) == "account-settings" && m == http.MethodGet {
			return h.accountSettings(c)
		}
	}
	return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", m, c.r.URL.Path)
}

// authorize checks the caller's identity policies for a Lambda action.
func (h *Handler) authorize(c *call, action, resource string) error {
	if h.IAM == nil || iam.IsRoot(c.who) {
		return nil
	}
	d, err := h.IAM.Require(c.ctx, c.who, "lambda:"+action, []string{resource}, nil)
	if err != nil {
		return err
	}
	if d != nil {
		return errorf(403, "AccessDeniedException", "%s", iam.DeniedMessage(c.who, d.Action, d.Resource, d.Explicit))
	}
	return nil
}

func (h *Handler) accountSettings(c *call) error {
	if err := h.authorize(c, "GetAccountSettings", "*"); err != nil {
		return err
	}
	var count, size int64
	err := h.st.DB().QueryRowContext(c.ctx, `SELECT COUNT(DISTINCT f.id), COALESCE(SUM(json_extract(v.config, '$.CodeSize')), 0)
		FROM lambda_functions f JOIN lambda_versions v ON v.function_id = f.id WHERE f.account=? AND f.region=?`,
		c.account, c.region).Scan(&count, &size)
	if err != nil {
		return err
	}
	var reserved int64
	_ = h.st.DB().QueryRowContext(c.ctx, `SELECT COALESCE(SUM(concurrency), 0) FROM lambda_functions WHERE account=? AND region=?`,
		c.account, c.region).Scan(&reserved)
	writeJSON(c.w, 200, map[string]any{
		"AccountLimit": map[string]any{
			"TotalCodeSize": int64(80) << 30, "CodeSizeUnzipped": maxWasmSize, "CodeSizeZipped": maxZipSize,
			"ConcurrentExecutions": accountConcurrency, "UnreservedConcurrentExecutions": accountConcurrency - reserved,
		},
		"AccountUsage": map[string]any{"TotalCodeSize": size, "FunctionCount": count},
	})
	return nil
}

// Internal serves /_citadel/lambda/: code download URLs and function URLs.
func (h *Handler) Internal() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/_citadel/lambda/code/"):
			h.ServeCode(w, r)
		case strings.HasPrefix(r.URL.Path, "/_citadel/lambda/url/"):
			h.serveURL(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
