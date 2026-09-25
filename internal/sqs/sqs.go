// Package sqs implements SQS JSON and Query APIs using durable SQLite queues.
package sqs

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

	"citadel/internal/sigv4"
	"citadel/internal/store"
)

type Handler struct {
	st      *store.Store
	auth    *sigv4.Verifier
	region  string
	log     *slog.Logger
	mu      sync.Mutex
	notices map[int64]chan struct{}
	now     func() time.Time
}

func New(st *store.Store, auth *sigv4.Verifier, region string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{st: st, auth: auth, region: region, log: logger, notices: make(map[int64]chan struct{}), now: time.Now}
}

type call struct {
	ctx                                   context.Context
	account, region, host, scheme, sender string
}
type request struct {
	QueueName, QueueUrl, QueueOwnerAWSAccountId, QueueNamePrefix, NextToken     string
	Attributes                                                                  map[string]string
	Tags                                                                        map[string]string
	TagKeys, AttributeNames, MessageAttributeNames, MessageSystemAttributeNames []string
	MaxResults                                                                  *int
	MessageBody, MessageGroupId, MessageDeduplicationId, ReceiptHandle, Id      string
	MessageAttributes, MessageSystemAttributes                                  map[string]attribute
	DelaySeconds, VisibilityTimeout, WaitTimeSeconds, MaxNumberOfMessages       *int
	Entries                                                                     []request
	Label                                                                       string
	AWSAccountIds, Actions                                                      []string
}
type attribute struct {
	DataType         string
	StringValue      string   `json:",omitempty"`
	BinaryValue      []byte   `json:",omitempty"`
	StringListValues []string `json:",omitempty"`
	BinaryListValues [][]byte `json:",omitempty"`
}
type serviceError struct {
	Status        int
	Code, Message string
}

func (e *serviceError) Error() string { return e.Code + ": " + e.Message }
func fail(code, format string, args ...any) error {
	return &serviceError{400, code, fmt.Sprintf(format, args...)}
}
func missingQueue() error { return fail("QueueDoesNotExist", "The specified queue does not exist.") }
func asError(err error) *serviceError {
	var e *serviceError
	if errors.As(err, &e) {
		return e
	}
	var se *sigv4.Error
	if errors.As(err, &se) {
		return &serviceError{403, se.Code, se.Message}
	}
	return &serviceError{500, "InternalError", "Internal server error"}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := !strings.HasPrefix(r.Header.Get("X-Amz-Target"), "AmazonSQS.")
	op, out, err := h.serve(r, query)
	if err != nil {
		e := asError(err)
		if e.Status == 500 {
			h.log.Error("sqs internal error", "op", op, "err", err)
		}
		writeError(w, query, e)
		return
	}
	if query {
		writeQuery(w, op, out)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	_ = json.NewEncoder(w).Encode(out)
}
func (h *Handler) serve(r *http.Request, query bool) (string, map[string]any, error) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSQS.")
	auth, err := h.auth.Verify(r)
	if err != nil {
		return op, nil, err
	}
	if auth.Anonymous {
		return op, nil, fail("MissingAuthenticationToken", "Request must be signed.")
	}
	_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return op, nil, fail("InvalidClientTokenId", "The security token included in the request is invalid.")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 12<<20+1))
	if err != nil {
		return op, nil, err
	}
	if len(body) > 12<<20 {
		return op, nil, fail("RequestTooLong", "Request is too large.")
	}
	var req request
	if query {
		vals, e := url.ParseQuery(string(body))
		if e != nil {
			return op, nil, fail("InvalidParameterValue", "Invalid form encoding.")
		}
		for k, v := range r.URL.Query() {
			if _, ok := vals[k]; !ok {
				vals[k] = v
			}
		}
		op, req, err = decodeQuery(vals)
		if req.QueueUrl == "" && r.URL.Path != "/" {
			req.QueueUrl = "http://" + r.Host + r.URL.Path
		}
	} else {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		return op, nil, fail("InvalidParameterValue", "Invalid request: %v", err)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	c := &call{ctx: r.Context(), account: who.Account.ID, region: auth.Region, host: r.Host, scheme: scheme, sender: who.Account.ID}
	if c.region == "" {
		c.region = h.region
	}
	out, err := h.dispatch(c, op, &req)
	return op, out, err
}
func (h *Handler) dispatch(c *call, op string, r *request) (map[string]any, error) {
	switch op {
	case "SendMessage":
		return h.sendMessage(c, r)
	case "ReceiveMessage":
		return h.receiveMessage(c, r)
	case "DeleteMessage", "ChangeMessageVisibility":
		return h.receiptOperation(c, op, r)
	case "SendMessageBatch", "DeleteMessageBatch", "ChangeMessageVisibilityBatch":
		return h.batch(c, op, r)
	case "CreateQueue":
		return h.createQueue(c, r)
	case "GetQueueUrl":
		owner := r.QueueOwnerAWSAccountId
		if owner == "" {
			owner = c.account
		}
		if owner != c.account {
			return nil, missingQueue()
		}
		q, err := h.queueByName(c, owner, r.QueueName)
		if err != nil {
			return nil, err
		}
		return map[string]any{"QueueUrl": c.queueURL(q)}, nil
	case "ListQueues":
		return h.listQueues(c, r)
	case "DeleteQueue", "GetQueueAttributes", "SetQueueAttributes", "ListQueueTags", "TagQueue", "UntagQueue", "PurgeQueue", "ListDeadLetterSourceQueues":
		return h.queueOperation(c, op, r)
	default:
		return nil, &serviceError{501, "NotImplemented", "citadel: SQS " + op + " is not implemented yet"}
	}
}
func (c *call) queueURL(q *queue) string {
	return c.scheme + "://" + c.host + "/" + q.Account + "/" + q.Name
}
func (h *Handler) Reset() {
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.Exec(`DELETE FROM sqs_queues`); err != nil {
			return err
		}
		return tx.Change("sqs", "Reset", "", nil)
	})
	if err != nil {
		h.log.Error("reset sqs", "err", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ch := range h.notices {
		close(ch)
		delete(h.notices, id)
	}
}
func (h *Handler) notifier(id int64) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := h.notices[id]
	if ch == nil {
		ch = make(chan struct{})
		h.notices[id] = ch
	}
	return ch
}
func (h *Handler) notify(id int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch := h.notices[id]; ch != nil {
		close(ch)
		delete(h.notices, id)
	}
}
func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }
func intValue(p *int, fallback int) int {
	if p != nil {
		return *p
	}
	return fallback
}
