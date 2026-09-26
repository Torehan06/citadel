package lambda

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"citadel/internal/logs"
	"citadel/internal/store"
)

const (
	maxAsyncPayload = 1 << 20 // asynchronous invocation payload limit
	asyncWorkers    = 4
)

// result is one completed invocation.
type result struct {
	Payload       []byte
	FunctionError string // "" or "Unhandled"
	Version       string // executed version
	Log           []byte // the invocation's log lines (START ... REPORT)
	RequestID     string
}

func newRequestID() string { return newRevision() }

// target is a resolved function version ready to run.
type target struct {
	fn      *function
	v       *version
	alias   string
	arn     string // the ARN the caller invoked (qualified if they qualified it)
	account string
	region  string
}

// pickVersion applies an alias's weighted routing.
func (c *call) pickVersion(q querier, fn *function, f fnRef) (*version, string, error) {
	v, alias, err := c.resolve(q, fn, f)
	if err != nil || alias == "" {
		return v, alias, err
	}
	a, err := loadAlias(c.ctx, q, fn.ID, alias)
	if err != nil || a == nil || a.RoutingConfig == nil {
		return v, alias, err
	}
	roll := rand.Float64()
	keys := make([]string, 0, len(a.RoutingConfig.AdditionalVersionWeights))
	for k := range a.RoutingConfig.AdditionalVersionWeights {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w := a.RoutingConfig.AdditionalVersionWeights[k]
		if roll < w {
			n, _ := strconv.Atoi(k)
			if alt, err := loadVersion(c.ctx, q, fn.ID, n); err == nil && alt != nil {
				return alt, alias, nil
			}
			break
		}
		roll -= w
	}
	return v, alias, nil
}

func (h *Handler) target(c *call, raw string) (*target, error) {
	f, err := c.ref(raw)
	if err != nil {
		return nil, err
	}
	return h.targetRef(c, f)
}

func (h *Handler) targetRef(c *call, f fnRef) (*target, error) {
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return nil, err
	}
	v, alias, err := c.pickVersion(h.st.DB(), fn, f)
	if err != nil {
		return nil, err
	}
	return &target{fn: fn, v: v, alias: alias, arn: c.refARN(fnRef{name: fn.Name, qualifier: f.qualifier}), account: c.account, region: c.region}, nil
}

func (h *Handler) invoke(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "InvokeFunction", c.refARN(f)); err != nil {
		return err
	}
	kind := c.r.Header.Get("X-Amz-Invocation-Type")
	if kind == "" {
		kind = "RequestResponse"
	}
	if kind != "RequestResponse" && kind != "Event" && kind != "DryRun" {
		return validation(kind, "invocationType", "Member must satisfy enum value set: [Event, RequestResponse, DryRun]")
	}
	logType := c.r.Header.Get("X-Amz-Log-Type")
	if logType != "" && logType != "None" && logType != "Tail" {
		return validation(logType, "logType", "Member must satisfy enum value set: [Tail, None]")
	}
	limit := int64(maxResponseSize)
	if kind == "Event" {
		limit = maxAsyncPayload
	}
	payload, err := io.ReadAll(io.LimitReader(c.r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > limit {
		return errorf(413, "RequestEntityTooLargeException", "Request must be smaller than %d bytes for the InvokeFunction operation", limit)
	}
	if len(bytes.TrimSpace(payload)) > 0 && !json.Valid(payload) {
		return errorf(400, "InvalidRequestContentException", "Could not parse request body into json: Could not parse payload into json: Unexpected character: was expecting a JSON value")
	}
	t, err := h.targetRef(c, f)
	if err != nil {
		return err
	}
	switch kind {
	case "DryRun":
		writeJSON(c.w, 204, nil)
		return nil
	case "Event":
		id, err := h.enqueue(c.ctx, t, f.qualifier, payload, "")
		if err != nil {
			return err
		}
		c.w.Header().Set("x-amzn-RequestId", id)
		writeJSON(c.w, 202, nil)
		return nil
	}
	res, err := h.execute(c.ctx, t, payload, "")
	if err != nil {
		return err
	}
	w := c.w
	w.Header().Set("X-Amz-Executed-Version", res.Version)
	w.Header().Set("x-amzn-RequestId", res.RequestID)
	if res.FunctionError != "" {
		w.Header().Set("X-Amz-Function-Error", res.FunctionError)
	}
	if logType == "Tail" {
		tail := res.Log
		if len(tail) > 4096 {
			tail = tail[len(tail)-4096:]
		}
		w.Header().Set("X-Amz-Log-Result", base64.StdEncoding.EncodeToString(tail))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(res.Payload)
	return nil
}

// invokeAsyncLegacy is the deprecated InvokeAsync API (202, {"Status": 202}).
func (h *Handler) invokeAsyncLegacy(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "InvokeFunction", c.refARN(f)); err != nil {
		return err
	}
	payload, err := io.ReadAll(io.LimitReader(c.r.Body, maxAsyncPayload+1))
	if err != nil {
		return err
	}
	if len(payload) > maxAsyncPayload {
		return errorf(413, "RequestEntityTooLargeException", "Request must be smaller than %d bytes for the InvokeAsync operation", maxAsyncPayload)
	}
	t, err := h.targetRef(c, f)
	if err != nil {
		return err
	}
	if _, err := h.enqueue(c.ctx, t, f.qualifier, payload, ""); err != nil {
		return err
	}
	writeJSON(c.w, 202, map[string]int{"Status": 202})
	return nil
}

// throttle reserves a concurrency slot for a function, or reports that its
// reserved concurrency (or the account's) is used up.
func (h *Handler) throttle(t *target) (release func(), err error) {
	key := t.account + "/" + t.region + "/" + t.fn.Name
	h.mu.Lock()
	defer h.mu.Unlock()
	if t.fn.Concurrency.Valid && int64(h.inflight[key]) >= t.fn.Concurrency.Int64 {
		e := errorf(429, "TooManyRequestsException", "Rate Exceeded.")
		e.Header = http.Header{"Retry-After": {"1"}}
		e.Message = "Rate Exceeded."
		return nil, &throttled{e, "ReservedFunctionConcurrentInvocationLimitExceeded"}
	}
	if h.total >= accountConcurrency {
		return nil, &throttled{errorf(429, "TooManyRequestsException", "Rate Exceeded."), "ConcurrentInvocationLimitExceeded"}
	}
	h.inflight[key]++
	h.total++
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.inflight[key]--
		if h.inflight[key] == 0 {
			delete(h.inflight, key)
		}
		h.total--
	}, nil
}

// throttled is a 429 that carries the Reason field Lambda's error adds.
type throttled struct {
	*serviceError
	reason string
}

func (t *throttled) Unwrap() error { return t.serviceError }

// execute runs one invocation synchronously and records its log.
func (h *Handler) execute(ctx context.Context, t *target, payload []byte, requestID string) (*result, error) {
	release, err := h.throttle(t)
	if err != nil {
		return nil, err
	}
	defer release()
	if requestID == "" {
		requestID = newRequestID()
	}
	cfg := t.v.Config
	ver := versionName(t.v.Num)
	res := &result{Version: ver, RequestID: requestID}
	started := h.now()
	stream := fmt.Sprintf("%s/[%s]%s", started.UTC().Format("2006/01/02"), ver, h.envID)
	env := map[string]string{
		"AWS_REGION": t.region, "AWS_DEFAULT_REGION": t.region,
		"AWS_LAMBDA_FUNCTION_NAME": cfg.FunctionName, "AWS_LAMBDA_FUNCTION_VERSION": ver,
		"AWS_LAMBDA_FUNCTION_MEMORY_SIZE": strconv.Itoa(cfg.MemorySize),
		"AWS_LAMBDA_LOG_GROUP_NAME":       cfg.LoggingConfig.LogGroup, "AWS_LAMBDA_LOG_STREAM_NAME": stream,
		"AWS_LAMBDA_INITIALIZATION_TYPE": "on-demand", "AWS_EXECUTION_ENV": "AWS_Lambda_" + cfg.Runtime,
		"_HANDLER": cfg.Handler, "TZ": ":UTC", "LANG": "en_US.UTF-8",
		// The Runtime API's per-invocation headers, as variables: WASI has no sockets.
		"LAMBDA_RUNTIME_AWS_REQUEST_ID":       requestID,
		"LAMBDA_RUNTIME_INVOKED_FUNCTION_ARN": t.arn,
		"LAMBDA_RUNTIME_DEADLINE_MS":          strconv.FormatInt(started.Add(time.Duration(cfg.Timeout)*time.Second).UnixMilli(), 10),
	}
	if cfg.Environment != nil {
		for k, v := range cfg.Environment.Variables {
			env[k] = v
		}
	}
	var logLines []string
	logLines = append(logLines, fmt.Sprintf("START RequestId: %s Version: %s", requestID, ver))
	fail := func(errType, msg string) {
		res.FunctionError = "Unhandled"
		res.Payload, _ = json.Marshal(map[string]any{"errorType": errType, "errorMessage": msg})
	}
	var out *Outcome
	switch {
	case t.v.ImageURI != "":
		fail("Runtime.InvalidEntrypoint", fmt.Sprintf("RequestId: %s Error: Citadel runs WebAssembly packages only; container images cannot be invoked", requestID))
	default:
		out, err = h.runtime.Run(ctx, t.v.CodeBlob, h.loadCode(t.v.CodeBlob), Execution{
			MemoryMB: cfg.MemorySize, Timeout: time.Duration(cfg.Timeout) * time.Second, Env: env, Event: payload,
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			fail("Runtime.InvalidEntrypoint", fmt.Sprintf("RequestId: %s Error: %v", requestID, err))
			logLines = append(logLines, fmt.Sprintf("%s\t%s\tError: %v", timestamp(h.now()), requestID, err))
		}
	}
	if out != nil {
		for _, line := range strings.Split(strings.TrimRight(string(out.Log), "\n"), "\n") {
			if line != "" {
				logLines = append(logLines, line)
			}
		}
		switch {
		case out.TimedOut:
			msg := fmt.Sprintf("Task timed out after %.2f seconds", float64(cfg.Timeout))
			logLines = append(logLines, fmt.Sprintf("%s %s %s", timestamp(h.now()), requestID, msg))
			fail("Sandbox.Timedout", fmt.Sprintf("RequestId: %s Error: %s", requestID, msg))
		case out.Overflow:
			fail("Function.ResponseSizeTooLarge", fmt.Sprintf("Response payload size exceeded maximum allowed payload size (%d bytes).", maxResponseSize))
		case out.ExitCode != 0:
			var reported struct{ ErrorMessage *string }
			if json.Unmarshal(out.Payload, &reported) == nil && reported.ErrorMessage != nil {
				res.FunctionError, res.Payload = "Unhandled", bytes.TrimSpace(out.Payload)
			} else {
				fail("Runtime.ExitError", fmt.Sprintf("RequestId: %s Error: Runtime exited with error: exit status %d", requestID, out.ExitCode))
			}
		default:
			res.Payload = bytes.TrimRight(out.Payload, "\r\n")
			if len(res.Payload) == 0 {
				res.Payload = []byte("null")
			}
		}
	}
	elapsed := h.now().Sub(started)
	ms := float64(elapsed.Microseconds()) / 1000
	used := 0
	if out != nil {
		used = int(out.MaxMemory >> 20)
	}
	logLines = append(logLines, "END RequestId: "+requestID,
		fmt.Sprintf("REPORT RequestId: %s\tDuration: %.2f ms\tBilled Duration: %d ms\tMemory Size: %d MB\tMax Memory Used: %d MB\t",
			requestID, ms, int64(ms)+1, cfg.MemorySize, used))
	res.Log = []byte(strings.Join(logLines, "\n") + "\n")
	if h.Logs != nil {
		ts := started.UnixMilli()
		events := make([]logs.Event, 0, len(logLines))
		for _, l := range logLines {
			events = append(events, logs.Event{Timestamp: ts, Message: l + "\n"})
		}
		if err := h.Logs.Append(context.Background(), t.account, t.region, cfg.LoggingConfig.LogGroup, stream, events); err != nil {
			h.log.Warn("lambda: writing function log", "function", cfg.FunctionName, "err", err)
		}
	}
	return res, nil
}

// Invoke runs a function synchronously on behalf of a service (event source
// mappings, S3 notifications). qualified may be a name, ARN or name:qualifier.
func (h *Handler) Invoke(ctx context.Context, account, region, qualified string, payload []byte) (*result, error) {
	c := &call{ctx: ctx, account: account, region: region}
	f, err := parseRef(qualified)
	if err != nil {
		return nil, err
	}
	t, err := h.targetRef(c, f)
	if err != nil {
		return nil, err
	}
	return h.execute(ctx, t, payload, "")
}

// ---- asynchronous invocations ------------------------------------------------------------

// enqueue stores an Event invocation; a worker runs it and applies the
// function's retry and destination settings.
func (h *Handler) enqueue(ctx context.Context, t *target, qualifier string, payload []byte, requestID string) (string, error) {
	if requestID == "" {
		requestID = newRequestID()
	}
	now := h.now().UnixMilli()
	err := h.st.Update(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO lambda_async(account, region, function, qualifier, payload, request_id, next_at, created)
			VALUES (?,?,?,?,?,?,?,?)`, t.account, t.region, t.fn.Name, qualifier, payload, requestID, now, now); err != nil {
			return err
		}
		return tx.Change("lambda", "InvokeAsync", t.arn, map[string]string{"request": requestID})
	})
	if err != nil {
		return "", err
	}
	select {
	case h.wake <- struct{}{}:
	default:
	}
	return requestID, nil
}

// EnqueueEvent queues an asynchronous invocation on behalf of a service
// (S3 event notifications, Lambda destinations).
func (h *Handler) EnqueueEvent(ctx context.Context, account, region, qualified string, payload []byte) error {
	c := &call{ctx: ctx, account: account, region: region}
	f, err := parseRef(qualified)
	if err != nil {
		return err
	}
	t, err := h.targetRef(c, f)
	if err != nil {
		return err
	}
	_, err = h.enqueue(ctx, t, f.qualifier, payload, "")
	return err
}

type asyncItem struct {
	id                                   int64
	account, region, function, qualifier string
	payload                              []byte
	requestID                            string
	attempts                             int
	created                              int64
}

// retryDelays are AWS's pauses before the first and second retry.
var retryDelays = []time.Duration{time.Minute, 2 * time.Minute}

func (h *Handler) asyncWorker(ctx context.Context) {
	for ctx.Err() == nil {
		item, next, err := h.claim(ctx)
		if err != nil {
			if ctx.Err() == nil {
				h.log.Warn("lambda: async queue", "err", err)
			}
			next = time.Second
		}
		if item != nil {
			h.runAsync(ctx, item)
			continue
		}
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-h.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// claim leases the oldest due invocation, or says how long until one is due.
func (h *Handler) claim(ctx context.Context) (*asyncItem, time.Duration, error) {
	var it *asyncItem
	next := 5 * time.Second
	now := h.now().UnixMilli()
	err := h.st.Update(ctx, func(tx *store.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT id, account, region, function, qualifier, payload, request_id, attempts, created
			FROM lambda_async WHERE next_at <= ? ORDER BY next_at, id LIMIT 1`, now)
		var a asyncItem
		if err := row.Scan(&a.id, &a.account, &a.region, &a.function, &a.qualifier, &a.payload, &a.requestID, &a.attempts, &a.created); err != nil {
			var due int64
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MIN(next_at), 0) FROM lambda_async`).Scan(&due); err == nil && due > 0 {
				if d := time.Duration(due-now) * time.Millisecond; d < next {
					next = max(d, 10*time.Millisecond)
				}
			}
			return nil
		}
		// Lease it for longer than any function can run; a crash mid-run
		// makes it due again afterwards.
		a.attempts++
		if _, err := tx.ExecContext(ctx, `UPDATE lambda_async SET attempts=?, next_at=? WHERE id=?`, a.attempts, now+int64(16*time.Minute/time.Millisecond), a.id); err != nil {
			return err
		}
		it = &a
		return nil
	})
	return it, next, err
}

func (h *Handler) runAsync(ctx context.Context, it *asyncItem) {
	c := &call{ctx: ctx, account: it.account, region: it.region}
	f := fnRef{name: it.function, qualifier: it.qualifier}
	done := func() {
		_ = h.st.Update(ctx, func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM lambda_async WHERE id=?`, it.id)
			return err
		})
	}
	t, err := h.targetRef(c, f)
	if err != nil {
		done() // the function is gone
		return
	}
	retries, maxAge, dest := invokeSettings(c, h.st.DB(), t.fn.ID, it.qualifier)
	age := h.now().Sub(time.UnixMilli(it.created))
	if age > maxAge {
		h.deliverFailure(c, t, it, dest, "EventAgeExceeded", nil)
		done()
		return
	}
	res, err := h.execute(ctx, t, it.payload, it.requestID)
	var th *throttled
	if errors.As(err, &th) {
		// Throttled events wait and retry for up to the maximum event age.
		_ = h.st.Update(ctx, func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE lambda_async SET attempts=attempts-1, next_at=? WHERE id=?`, h.now().Add(time.Second).UnixMilli(), it.id)
			return err
		})
		return
	}
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down: the lease expires and it runs again
		}
		res = &result{FunctionError: "Unhandled", Payload: []byte(`{"errorMessage":` + strconv.Quote(err.Error()) + `}`), Version: versionName(t.v.Num), RequestID: it.requestID}
	}
	if res.FunctionError == "" {
		h.deliver(c, t, it, dest.OnSuccess.Destination, "Success", res)
		done()
		return
	}
	if it.attempts <= retries {
		delay := retryDelays[min(it.attempts-1, len(retryDelays)-1)]
		_ = h.st.Update(ctx, func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE lambda_async SET next_at=? WHERE id=?`, h.now().Add(delay).UnixMilli(), it.id)
			return err
		})
		return
	}
	h.deliverFailure(c, t, it, dest, "RetriesExhausted", res)
	done()
}

// deliverFailure sends a failed event to the on-failure destination, or else
// to the function's dead-letter queue.
func (h *Handler) deliverFailure(c *call, t *target, it *asyncItem, dest destinationConfig, condition string, res *result) {
	if dest.OnFailure.Destination != "" {
		h.deliver(c, t, it, dest.OnFailure.Destination, condition, res)
		return
	}
	dlq := t.v.Config.DeadLetterConfig
	if dlq == nil || h.SQS == nil || !strings.Contains(dlq.TargetArn, ":sqs:") {
		return
	}
	attrs := map[string]any{"RequestID": map[string]string{"DataType": "String", "StringValue": it.requestID}}
	if res != nil {
		attrs["ErrorCode"] = map[string]string{"DataType": "Number", "StringValue": "200"}
		attrs["ErrorMessage"] = map[string]string{"DataType": "String", "StringValue": string(res.Payload)}
	}
	h.sendToQueue(c, dlq.TargetArn, string(it.payload), attrs)
}

// deliver sends an invocation record to a destination (SQS queue or function).
func (h *Handler) deliver(c *call, t *target, it *asyncItem, arn, condition string, res *result) {
	if arn == "" {
		return
	}
	record := map[string]any{
		"version":   "1.0",
		"timestamp": h.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"requestContext": map[string]any{
			"requestId": it.requestID, "functionArn": t.arn + ":" + versionName(t.v.Num),
			"condition": condition, "approximateInvokeCount": it.attempts,
		},
		"requestPayload": json.RawMessage(orNull(it.payload)),
	}
	if res != nil {
		rc := map[string]any{"statusCode": 200, "executedVersion": res.Version}
		if res.FunctionError != "" {
			rc["functionError"] = res.FunctionError
		}
		record["responseContext"] = rc
		if json.Valid(res.Payload) {
			record["responsePayload"] = json.RawMessage(res.Payload)
		} else {
			record["responsePayload"] = string(res.Payload)
		}
	}
	body, _ := json.Marshal(record)
	switch {
	case strings.Contains(arn, ":sqs:"):
		h.sendToQueue(c, arn, string(body), nil)
	case strings.Contains(arn, ":lambda:"):
		if err := h.EnqueueEvent(c.ctx, c.account, c.region, arn, body); err != nil {
			h.log.Warn("lambda: destination function", "arn", arn, "err", err)
		}
	default:
		h.log.Warn("lambda: destination type not supported", "arn", arn)
	}
}

func orNull(b []byte) []byte {
	if len(bytes.TrimSpace(b)) == 0 || !json.Valid(b) {
		return []byte("null")
	}
	return b
}

// sendToQueue sends a message to the queue an ARN names (same region).
func (h *Handler) sendToQueue(c *call, arn, body string, attrs map[string]any) {
	parts := strings.Split(arn, ":")
	if h.SQS == nil || len(parts) != 6 {
		return
	}
	in := map[string]any{"QueueUrl": queueURL(parts[4], parts[5]), "MessageBody": body}
	if len(attrs) > 0 {
		in["MessageAttributes"] = attrs
	}
	if _, err := h.SQS.Call(c.ctx, parts[4], parts[3], "SendMessage", in); err != nil {
		h.log.Warn("lambda: sending to queue", "arn", arn, "err", err)
	}
}

func queueURL(account, name string) string { return "http://sqs.localhost/" + account + "/" + name }
