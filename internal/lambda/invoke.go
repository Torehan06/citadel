package lambda

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func init() {
	handle("POST", "/2015-03-31/functions/{FunctionName}/invocations", "Invoke", (*Handler).invokeOp)
}

// Payload limits from the Lambda quotas page.
const (
	maxSyncPayload  = 6 << 20 // request and response, RequestResponse
	maxAsyncPayload = 1 << 20 // Event
	maxLogTail      = 4 << 10 // X-Amz-Log-Result
)

type invokeOpts struct {
	source    string // "api", "sqs", "event", "s3"
	requestID string
	tail      bool // collect the log tail for LogType=Tail
}

type invokeResult struct {
	requestID     string
	version       string // executed version
	payload       []byte
	functionError string // "" or "Unhandled"
	logTail       []byte
}

func (h *Handler) invokeOp(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "InvokeFunction", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	kind := c.r.Header.Get("X-Amz-Invocation-Type")
	if kind == "" {
		kind = "RequestResponse"
	}
	logType := c.r.Header.Get("X-Amz-Log-Type")
	if logType != "" && logType != "None" && logType != "Tail" {
		return nil, constraint(logType, "logType", "Member must satisfy enum value set: [Tail, None]")
	}
	payload := c.body
	if len(bytes.TrimSpace(payload)) == 0 {
		payload = []byte("{}")
	}
	if !json.Valid(payload) {
		return nil, errf(400, "InvalidRequestContentException", "Could not parse request body into json: Could not parse payload into json: Unexpected character: was expecting a JSON value")
	}
	switch kind {
	case "DryRun":
		if _, _, err := resolve(c.ctx, h.st.DB(), ref); err != nil {
			return nil, err
		}
		return ok(http.StatusNoContent, nil), nil
	case "Event":
		if len(payload) > maxAsyncPayload {
			return nil, errf(413, "RequestTooLargeException", "Request must be smaller than %d bytes for the InvokeAsync operation", maxAsyncPayload)
		}
		v, _, err := resolve(c.ctx, h.st.DB(), ref)
		if err != nil {
			return nil, err
		}
		id := newUUID()
		if err := h.enqueue(c.ctx, ref, payload, id, 0); err != nil {
			return nil, err
		}
		hdr := http.Header{"X-Amz-Executed-Version": {v.Version}}
		hdr.Set("x-amzn-RequestId", id)
		return &result{status: http.StatusAccepted, header: hdr, raw: []byte{}}, nil
	case "RequestResponse":
	default:
		return nil, constraint(kind, "invocationType", "Member must satisfy enum value set: [Event, RequestResponse, DryRun]")
	}
	if len(payload) > maxSyncPayload {
		return nil, errf(413, "RequestTooLargeException", "Request must be smaller than %d bytes for the InvokeFunction operation", maxSyncPayload)
	}
	res, err := h.invoke(c.ctx, ref, payload, invokeOpts{source: "api", tail: logType == "Tail"})
	if err != nil {
		return nil, err
	}
	hdr := http.Header{"X-Amz-Executed-Version": {res.version}}
	if res.functionError != "" {
		hdr.Set("X-Amz-Function-Error", res.functionError)
	}
	if logType == "Tail" {
		hdr.Set("X-Amz-Log-Result", base64.StdEncoding.EncodeToString(res.logTail))
	}
	return &result{status: 200, header: hdr, raw: res.payload}, nil
}

// pickVersion applies an alias's weighted routing.
func pickVersion(a *alias) string {
	weights, _ := a.RoutingConfig["AdditionalVersionWeights"].(map[string]any)
	r := rand.Float64()
	for _, v := range sortedKeys(weights) {
		w, _ := weights[v].(float64)
		if r < w {
			return v
		}
		r -= w
	}
	return a.FunctionVersion
}

// inFlight returns the counter of running invocations of a function.
func (h *Handler) inFlight(key string) *int64 {
	v, _ := h.running.LoadOrStore(key, new(int64))
	return v.(*int64)
}

var totalInFlight int64

// invoke runs one invocation of the version a reference resolves to.
func (h *Handler) invoke(ctx context.Context, ref fnRef, payload []byte, opts invokeOpts) (*invokeResult, error) {
	db := h.st.DB()
	f, err := loadFunction(ctx, db, ref)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, functionNotFound(ref, ref.qualifier)
	}
	target := ref
	if ref.qualifier != "" {
		if _, isVersion := versionNumber(ref.qualifier); !isVersion {
			a, err := loadAlias(ctx, db, ref, ref.qualifier)
			if err != nil {
				return nil, err
			}
			if a == nil {
				return nil, functionNotFound(ref, ref.qualifier)
			}
			target.qualifier = pickVersion(a)
		}
	}
	v, _, err := resolve(ctx, db, target)
	if err != nil {
		return nil, err
	}

	// Concurrency: a function's reservation caps it; the account quota caps
	// everything else.
	counter := h.inFlight(ref.key())
	n := atomic.AddInt64(counter, 1)
	defer atomic.AddInt64(counter, -1)
	total := atomic.AddInt64(&totalInFlight, 1)
	defer atomic.AddInt64(&totalInFlight, -1)
	if f.Reserved != nil && n > int64(*f.Reserved) {
		return nil, &apiError{Status: 429, Code: "TooManyRequestsException", Message: "Rate Exceeded.",
			Extra: map[string]any{"Reason": "ReservedFunctionConcurrentInvocationLimitExceeded"}}
	}
	if total > accountConcurrency {
		return nil, &apiError{Status: 429, Code: "TooManyRequestsException", Message: "Rate Exceeded.",
			Extra: map[string]any{"Reason": "ConcurrentInvocationLimitExceeded"}}
	}

	id := opts.requestID
	if id == "" {
		id = newUUID()
	}
	res := &invokeResult{requestID: id, version: v.Version}
	logs := &logBuffer{}
	fmt.Fprintf(logs, "START RequestId: %s Version: %s\n", id, v.Version)
	start := time.Now()
	out, fnErr, report := h.execute(ctx, ref, v, payload, id, logs)
	if out == nil && fnErr == nil {
		return nil, ctx.Err()
	}
	dur := time.Since(start)
	fmt.Fprintf(logs, "END RequestId: %s\n", id)
	billed := (dur.Milliseconds() + 1)
	fmt.Fprintf(logs, "REPORT RequestId: %s\tDuration: %.2f ms\tBilled Duration: %d ms\tMemory Size: %d MB\tMax Memory Used: %d MB",
		id, float64(dur.Microseconds())/1000, billed, v.MemorySize, (report.memoryUsed+(1<<20)-1)>>20)
	if report.cold {
		fmt.Fprintf(logs, "\tInit Duration: %.2f ms", float64(report.initTime.Microseconds())/1000)
	}
	logs.WriteString("\n")
	if fnErr != nil {
		res.functionError = "Unhandled"
		res.payload = fnErr
	} else {
		res.payload = out
	}
	if opts.tail {
		t := logs.Bytes()
		if len(t) > maxLogTail {
			t = t[len(t)-maxLogTail:]
		}
		res.logTail = t
	}
	h.writeLogs(ctx, ref, v, logs.lines(start))
	return res, nil
}

// execute runs the function and returns either its response or an error
// payload ({"errorType", "errorMessage"}), plus runtime details for the report.
func (h *Handler) execute(ctx context.Context, ref fnRef, v *version, payload []byte, id string, logs *logBuffer) ([]byte, []byte, runOutcome) {
	fail := func(typ, msg string) ([]byte, []byte, runOutcome) {
		fmt.Fprintf(logs, "%s\n", msg)
		return nil, []byte(jsonString(map[string]string{"errorType": typ, "errorMessage": msg})), runOutcome{}
	}
	if v.PackageType == "Image" {
		return fail("Runtime.InvalidEntrypoint", "RequestId: "+id+" Error: Citadel runs WebAssembly modules; container image functions cannot be invoked")
	}
	f, err := h.st.Blobs.Open(v.Blob)
	if err != nil {
		return fail("Runtime.Unknown", "RequestId: "+id+" Error: deployment package unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fail("Runtime.Unknown", "RequestId: "+id+" Error: deployment package unavailable")
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return fail("Runtime.InvalidEntrypoint", "RequestId: "+id+" Error: could not unzip deployment package")
	}
	entry := findBootstrap(zr)
	if entry == nil {
		return fail("Runtime.InvalidEntrypoint", "RequestId: "+id+" Error: Couldn't find valid bootstrap(s): [/var/task/bootstrap.wasm]")
	}
	stdout := &capped{limit: maxSyncPayload}
	spec := runSpec{
		codeKey: v.Blob,
		wasm: func() ([]byte, error) {
			rc, err := entry.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxUnzipped))
		},
		task:    zr,
		pages:   memoryPages(v.MemorySize),
		timeout: time.Duration(v.Timeout) * time.Second,
		env:     h.environment(ref, v),
		stdin:   payload,
		stdout:  stdout,
		stderr:  logs,
	}
	oc, err := h.rt.run(ctx, spec)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, oc
		}
		if _, bad := err.(*invalidModule); bad {
			out, e, _ := fail("Runtime.InvalidEntrypoint", "RequestId: "+id+" Error: "+err.Error())
			return out, e, oc
		}
		out, e, _ := fail("Runtime.Unknown", "RequestId: "+id+" Error: "+err.Error())
		return out, e, oc
	}
	errPayload := func(typ, msg string) ([]byte, []byte, runOutcome) {
		out, e, _ := fail(typ, msg)
		return out, e, oc
	}
	switch {
	case oc.timedOut:
		return errPayload("Sandbox.Timedout", fmt.Sprintf("%s %s Task timed out after %.2f seconds", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), id, float64(v.Timeout)))
	case oc.trap != nil:
		return errPayload("Runtime.ExitError", "RequestId: "+id+" Error: Runtime exited with error: "+oc.trap.Error())
	case stdout.over:
		return errPayload("Function.ResponseSizeTooLarge", fmt.Sprintf("Response payload size exceeded maximum allowed payload size (%d bytes).", maxSyncPayload))
	case oc.exitCode != 0:
		// A function reports its own error by printing an error object and
		// exiting non-zero; anything else is a crash.
		var reported struct {
			ErrorMessage *string `json:"errorMessage"`
		}
		if b := bytes.TrimSpace(stdout.Bytes()); json.Unmarshal(b, &reported) == nil && reported.ErrorMessage != nil {
			return nil, b, oc
		}
		return errPayload("Runtime.ExitError", fmt.Sprintf("RequestId: %s Error: Runtime exited with error: exit status %d", id, oc.exitCode))
	}
	out := bytes.TrimRight(stdout.Bytes(), "\n")
	if len(bytes.TrimSpace(out)) == 0 {
		out = []byte("null")
	}
	return out, nil, oc
}

// findBootstrap finds the module to run: bootstrap.wasm at the root of the
// package (or a root "bootstrap" that is itself a wasm module).
func findBootstrap(zr *zip.Reader) *zip.File {
	var alt *zip.File
	for _, f := range zr.File {
		switch f.Name {
		case "bootstrap.wasm":
			return f
		case "bootstrap":
			alt = f
		}
	}
	if alt != nil {
		rc, err := alt.Open()
		if err == nil {
			var magic [4]byte
			_, err = io.ReadFull(rc, magic[:])
			rc.Close()
			if err == nil && string(magic[:]) == "\x00asm" {
				return alt
			}
		}
	}
	return nil
}

// environment is the function's variables plus the reserved ones Lambda sets.
func (h *Handler) environment(ref fnRef, v *version) map[string]string {
	env := map[string]string{}
	if v.Environment != nil {
		for k, val := range v.Environment.Variables {
			env[k] = val
		}
	}
	group := v.LoggingConfig["LogGroup"]
	if group == "" {
		group = "/aws/lambda/" + ref.name
	}
	for k, val := range map[string]string{
		"AWS_LAMBDA_FUNCTION_NAME":        ref.name,
		"AWS_LAMBDA_FUNCTION_VERSION":     v.Version,
		"AWS_LAMBDA_FUNCTION_MEMORY_SIZE": strconv.Itoa(v.MemorySize),
		"AWS_LAMBDA_LOG_GROUP_NAME":       group,
		"AWS_LAMBDA_LOG_STREAM_NAME":      h.streamName(ref, v.Version),
		"AWS_REGION":                      ref.region,
		"AWS_DEFAULT_REGION":              ref.region,
		"AWS_EXECUTION_ENV":               "AWS_Lambda_" + strings.ReplaceAll(v.Runtime, ".", ""),
		"LAMBDA_TASK_ROOT":                "/var/task",
		"_HANDLER":                        v.Handler,
		"TZ":                              ":UTC",
	} {
		env[k] = val
	}
	return env
}

// capped is a buffer that stops growing past limit and remembers it overflowed.
type capped struct {
	bytes.Buffer
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.limit {
		c.over = true
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

// logBuffer collects an invocation's log output (runtime lines and stderr).
type logBuffer struct {
	bytes.Buffer
}

const maxLogBytes = 1 << 20

func (l *logBuffer) Write(p []byte) (int, error) {
	if l.Len() >= maxLogBytes {
		return len(p), nil
	}
	return l.Buffer.Write(p)
}

// lines splits the log into events, one per line, stamped from start.
func (l *logBuffer) lines(start time.Time) []logEvent {
	var out []logEvent
	ts := start.UnixMilli()
	for _, line := range strings.SplitAfter(l.String(), "\n") {
		if line == "" {
			continue
		}
		out = append(out, logEvent{Timestamp: ts, Message: line})
	}
	if n := len(out); n > 0 {
		out[n-1].Timestamp = time.Now().UnixMilli()
	}
	return out
}
