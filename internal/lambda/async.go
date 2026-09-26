package lambda

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"citadel/internal/sqs"
	"citadel/internal/store"
)

// Asynchronous invocations (InvocationType=Event, S3 notifications, Lambda
// destinations) go through a durable queue in meta.db. A worker leases due
// jobs, runs them and either deletes them or reschedules a retry, so an
// accepted event survives a restart and runs at least once.

// Async retries: AWS waits one minute, then two, between attempts.
var retryDelays = []time.Duration{time.Minute, 2 * time.Minute}

const (
	asyncWorkers   = 8
	asyncLease     = 16 * time.Minute // longer than the longest timeout
	defaultRetries = 2
	defaultMaxAge  = 6 * time.Hour
)

type asyncJob struct {
	id       int64
	ref      fnRef
	request  string
	payload  []byte
	attempts int
	enqueued int64
}

// enqueue adds an asynchronous invocation to the queue.
func (h *Handler) enqueue(ctx context.Context, ref fnRef, payload []byte, requestID string, attempts int) error {
	now := h.now().UnixMilli()
	err := h.st.Update(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO lambda_async(request_id, account_id, region, name, qualifier, payload, attempts, next_at, enqueued)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, requestID, ref.account, ref.region, ref.name, ref.qualifier, payload, attempts, now, now); err != nil {
			return err
		}
		return tx.Change("lambda", "InvokeAsync", ref.qualifiedARN(ref.qualifier), map[string]string{"requestId": requestID})
	})
	if err == nil {
		select {
		case h.wake <- struct{}{}:
		default:
		}
	}
	return err
}

// StartAsync starts the worker that drains the async queue.
func (h *Handler) StartAsync() {
	go h.asyncLoop()
}

func (h *Handler) asyncLoop() {
	sem := make(chan struct{}, asyncWorkers)
	for h.bg.Err() == nil {
		job, wait, err := h.claim()
		if err != nil {
			if h.bg.Err() != nil {
				return
			}
			h.log.Error("lambda async queue", "err", err)
			wait = time.Second
		}
		if job == nil {
			t := time.NewTimer(wait)
			select {
			case <-h.bg.Done():
				t.Stop()
				return
			case <-h.wake:
			case <-t.C:
			}
			t.Stop()
			continue
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			h.runAsync(job)
		}()
	}
}

// claim leases the next due job, or says how long until one is due.
func (h *Handler) claim() (*asyncJob, time.Duration, error) {
	var job *asyncJob
	wait := 30 * time.Second
	now := h.now().UnixMilli()
	err := h.st.Update(h.bg, func(tx *store.Tx) error {
		var j asyncJob
		err := tx.QueryRowContext(h.bg, `SELECT id, request_id, account_id, region, name, qualifier, payload, attempts, enqueued
			FROM lambda_async WHERE next_at <= ? ORDER BY next_at, id LIMIT 1`, now).
			Scan(&j.id, &j.request, &j.ref.account, &j.ref.region, &j.ref.name, &j.ref.qualifier, &j.payload, &j.attempts, &j.enqueued)
		if errors.Is(err, sql.ErrNoRows) {
			var next sql.NullInt64
			if err := tx.QueryRowContext(h.bg, `SELECT MIN(next_at) FROM lambda_async`).Scan(&next); err != nil {
				return err
			}
			if next.Valid {
				wait = min(wait, time.Duration(next.Int64-now)*time.Millisecond)
			}
			return nil
		}
		if err != nil {
			return err
		}
		job = &j
		_, err = tx.ExecContext(h.bg, `UPDATE lambda_async SET next_at = ? WHERE id = ?`, now+asyncLease.Milliseconds(), j.id)
		return err
	})
	return job, max(wait, 10*time.Millisecond), err
}

func (h *Handler) finishJob(id int64) {
	err := h.st.Update(h.bg, func(tx *store.Tx) error {
		_, err := tx.ExecContext(h.bg, `DELETE FROM lambda_async WHERE id = ?`, id)
		return err
	})
	if err != nil {
		h.log.Error("lambda async queue: finish", "err", err)
	}
}

func (h *Handler) retryJob(j *asyncJob, delay time.Duration, attempts int) {
	err := h.st.Update(h.bg, func(tx *store.Tx) error {
		_, err := tx.ExecContext(h.bg, `UPDATE lambda_async SET next_at = ?, attempts = ? WHERE id = ?`,
			h.now().Add(delay).UnixMilli(), attempts, j.id)
		return err
	})
	if err != nil {
		h.log.Error("lambda async queue: retry", "err", err)
	}
}

func (h *Handler) runAsync(j *asyncJob) {
	f, err := loadFunction(h.bg, h.st.DB(), j.ref)
	if err != nil {
		return // the lease expires and the job is tried again
	}
	if f == nil {
		h.finishJob(j.id) // the function is gone
		return
	}
	cfg := f.EventInvoke[j.ref.qualifier]
	retries, maxAge := defaultRetries, defaultMaxAge
	if cfg != nil && cfg.MaximumRetryAttempts != nil {
		retries = *cfg.MaximumRetryAttempts
	}
	if cfg != nil && cfg.MaximumEventAgeInSeconds != nil {
		maxAge = time.Duration(*cfg.MaximumEventAgeInSeconds) * time.Second
	}
	age := h.now().Sub(time.UnixMilli(j.enqueued))
	if age > maxAge {
		h.deliver(j, f, cfg, nil, "EventAgeExceeded")
		h.finishJob(j.id)
		return
	}
	res, err := h.invoke(h.bg, j.ref, j.payload, invokeOpts{source: "event", requestID: j.request})
	if err != nil {
		var ae *apiError
		switch {
		case errors.As(err, &ae) && ae.Status == 429:
			h.retryJob(j, time.Minute, j.attempts) // throttles retry until the event is too old
		case errors.As(err, &ae) && ae.Status == 404:
			h.finishJob(j.id)
		default:
			h.log.Warn("lambda async invoke", "fn", j.ref.name, "err", err)
		}
		return
	}
	if res.functionError != "" && j.attempts < retries {
		delay := retryDelays[min(j.attempts, len(retryDelays)-1)]
		if age+delay <= maxAge {
			h.retryJob(j, delay, j.attempts+1)
			return
		}
		h.deliver(j, f, cfg, res, "EventAgeExceeded")
		h.finishJob(j.id)
		return
	}
	condition := "Success"
	if res.functionError != "" {
		condition = "RetriesExhausted"
	}
	h.deliver(j, f, cfg, res, condition)
	h.finishJob(j.id)
}

// deliver sends an invocation record to the OnSuccess or OnFailure
// destination, and a failed event to the version's dead-letter queue.
func (h *Handler) deliver(j *asyncJob, f *function, cfg *eventInvokeConfig, res *invokeResult, condition string) {
	key := "OnFailure"
	if condition == "Success" {
		key = "OnSuccess"
	}
	record := map[string]any{
		"version":   "1.0",
		"timestamp": h.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"requestContext": map[string]any{
			"requestId": j.request, "functionArn": j.ref.qualifiedARN(qualOrLatest(j.ref.qualifier)),
			"condition": condition, "approximateInvokeCount": j.attempts + 1,
		},
		"requestPayload": json.RawMessage(j.payload),
	}
	if res != nil {
		rc := map[string]any{"statusCode": 200, "executedVersion": res.version}
		if res.functionError != "" {
			rc["functionError"] = res.functionError
		}
		record["responseContext"] = rc
		if json.Valid(res.payload) {
			record["responsePayload"] = json.RawMessage(res.payload)
		}
	}
	if cfg != nil {
		if d, _ := cfg.DestinationConfig[key].(map[string]string); d["Destination"] != "" {
			h.sendTo(d["Destination"], j.ref, []byte(jsonString(record)))
		} else if d, _ := cfg.DestinationConfig[key].(map[string]any); d != nil {
			if arn, _ := d["Destination"].(string); arn != "" {
				h.sendTo(arn, j.ref, []byte(jsonString(record)))
			}
		}
	}
	if condition != "Success" {
		if v, _, err := resolve(h.bg, h.st.DB(), j.ref); err == nil && v.DeadLetterConfig != nil {
			if arn, _ := v.DeadLetterConfig["TargetArn"].(string); arn != "" {
				h.sendTo(arn, j.ref, j.payload)
			}
		}
	}
}

func qualOrLatest(q string) string {
	if q == "" {
		return "$LATEST"
	}
	return q
}

// sendTo delivers a message to an SQS queue or a Lambda function ARN.
func (h *Handler) sendTo(arn string, from fnRef, body []byte) {
	switch {
	case strings.Contains(arn, ":sqs:"):
		account, region, url, ok := sqs.QueueURL(arn)
		if !ok || h.SQS == nil {
			return
		}
		if _, err := h.SQS.Call(h.bg, account, region, "SendMessage", map[string]any{"QueueUrl": url, "MessageBody": string(body)}); err != nil {
			h.log.Warn("lambda destination", "arn", arn, "err", err)
		}
	case strings.Contains(arn, ":lambda:"):
		ref, err := parseFunctionARN(arn)
		if err != nil {
			return
		}
		if err := h.enqueue(h.bg, ref, body, newUUID(), 0); err != nil {
			h.log.Warn("lambda destination", "arn", arn, "err", err)
		}
	default:
		h.log.Warn("lambda destination type not supported yet", "arn", arn, "from", from.arn())
	}
}
