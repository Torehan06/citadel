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

func init() {
	handle("POST", "/2015-03-31/event-source-mappings", "CreateEventSourceMapping", (*Handler).createMapping)
	handle("GET", "/2015-03-31/event-source-mappings", "ListEventSourceMappings", (*Handler).listMappings)
	handle("GET", "/2015-03-31/event-source-mappings/{UUID}", "GetEventSourceMapping", (*Handler).getMapping)
	handle("PUT", "/2015-03-31/event-source-mappings/{UUID}", "UpdateEventSourceMapping", (*Handler).updateMappingOp)
	handle("DELETE", "/2015-03-31/event-source-mappings/{UUID}", "DeleteEventSourceMapping", (*Handler).deleteMapping)
}

// QueueClient is the slice of SQS that event source mappings use.
type QueueClient interface {
	Call(ctx context.Context, account, region, op string, req any) (map[string]any, error)
}

// mapping is an event source mapping. Doc holds every configuration member
// the caller set (echoed back as given); the fields here are the ones
// Citadel itself computes or acts on.
type mapping struct {
	UUID        string            `json:"UUID"`
	Account     string            `json:"Account"`
	Region      string            `json:"Region"`
	FunctionArn string            `json:"FunctionArn"`
	SourceArn   string            `json:"EventSourceArn"`
	Enabled     bool              `json:"Enabled"`
	Modified    float64           `json:"LastModified"`
	Result      string            `json:"LastProcessingResult"`
	Doc         map[string]any    `json:"Doc"`
	Tags        map[string]string `json:"Tags,omitempty"`
}

func (m *mapping) arn() string {
	return "arn:" + partition(m.Region) + ":lambda:" + m.Region + ":" + m.Account + ":event-source-mapping:" + m.UUID
}

func (m *mapping) isSQS() bool {
	return strings.HasPrefix(m.SourceArn, "arn:aws:sqs:") || strings.Contains(m.SourceArn, ":sqs:")
}

// out is the EventSourceMappingConfiguration response.
func (m *mapping) out(state string) map[string]any {
	o := map[string]any{}
	for k, v := range m.Doc {
		o[k] = v
	}
	if state == "" {
		state = "Disabled"
		if m.Enabled {
			state = "Enabled"
		}
	}
	o["UUID"] = m.UUID
	o["FunctionArn"] = m.FunctionArn
	o["EventSourceArn"] = m.SourceArn
	o["LastModified"] = m.Modified
	o["State"] = state
	o["StateTransitionReason"] = "USER_INITIATED"
	o["LastProcessingResult"] = m.Result
	o["EventSourceMappingArn"] = m.arn()
	return o
}

func loadMapping(ctx context.Context, q querier, account, id string) (*mapping, error) {
	var doc string
	err := q.QueryRowContext(ctx, `SELECT doc FROM lambda_esm WHERE uuid=? AND account_id=?`, id, account).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("The resource you requested does not exist.")
	}
	if err != nil {
		return nil, err
	}
	var m mapping
	return &m, json.Unmarshal([]byte(doc), &m)
}

func saveMapping(ctx context.Context, q querier, m *mapping) error {
	_, err := q.ExecContext(ctx, `INSERT INTO lambda_esm(uuid, account_id, region, function_arn, source_arn, enabled, doc) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uuid) DO UPDATE SET function_arn=excluded.function_arn, source_arn=excluded.source_arn, enabled=excluded.enabled, doc=excluded.doc`,
		m.UUID, m.Account, m.Region, m.FunctionArn, m.SourceArn, m.Enabled, jsonString(m))
	return err
}

// mappingFunction resolves a mapping's FunctionName to the ARN it reports:
// unqualified, or qualified by the version or alias the caller named.
func (h *Handler) mappingFunction(c *call, q querier, name string) (string, error) {
	ref, err := c.parseName(name, "")
	if err != nil {
		return "", err
	}
	if _, _, err := resolve(c.ctx, q, ref); err != nil {
		return "", err
	}
	return ref.qualifiedARN(ref.qualifier), nil
}

// defaultBatch is BatchSize when the caller sets none, per source type.
func defaultBatch(source string) int {
	if strings.Contains(source, ":sqs:") {
		return 10
	}
	return 100
}

func (h *Handler) createMapping(c *call) (*result, error) {
	if err := h.authorize(c, "CreateEventSourceMapping", "*"); err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := c.decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		doc = map[string]any{}
	}
	name, _ := doc["FunctionName"].(string)
	source, _ := doc["EventSourceArn"].(string)
	if name == "" {
		return nil, validation("1 validation error detected: Value null at 'functionName' failed to satisfy constraint: Member must not be null")
	}
	enabled := true
	if e, ok := doc["Enabled"].(bool); ok {
		enabled = e
	}
	tags := map[string]string{}
	if t, ok := doc["Tags"].(map[string]any); ok {
		for k, v := range t {
			s, _ := v.(string)
			tags[k] = s
		}
	}
	if err := checkTags(tags); err != nil {
		return nil, err
	}
	for _, k := range []string{"FunctionName", "EventSourceArn", "Enabled", "Tags"} {
		delete(doc, k)
	}
	if _, ok := doc["BatchSize"]; !ok {
		doc["BatchSize"] = defaultBatch(source)
	}
	if b, _ := doc["BatchSize"].(float64); b < 0 || b > 10000 {
		return nil, invalid("BatchSize must be between 1 and 10000.")
	}
	if _, ok := doc["MaximumBatchingWindowInSeconds"]; !ok && strings.Contains(source, ":sqs:") {
		doc["MaximumBatchingWindowInSeconds"] = 0
	}
	m := &mapping{
		UUID: newUUID(), Account: c.account, Region: c.region, SourceArn: source, Enabled: enabled,
		Modified: float64(h.now().UnixMilli()) / 1000, Result: "No records processed", Doc: doc,
	}
	if len(tags) > 0 {
		m.Tags = tags
	}
	if m.isSQS() && h.SQS != nil {
		if err := h.checkQueue(c, source); err != nil {
			return nil, err
		}
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		arn, err := h.mappingFunction(c, tx, name)
		if err != nil {
			return err
		}
		m.FunctionArn = arn
		if m.isSQS() {
			var existing string
			err := tx.QueryRowContext(c.ctx, `SELECT uuid FROM lambda_esm WHERE account_id=? AND source_arn=? AND function_arn=?`,
				c.account, source, arn).Scan(&existing)
			if err == nil {
				return conflict("An event source mapping with SQS arn (\" %s \") and function (\" %s \") already exists. Please update or delete the existing mapping with UUID %s", source, name, existing)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if err := saveMapping(c.ctx, tx, m); err != nil {
			return err
		}
		return tx.Change("lambda", "CreateEventSourceMapping", m.arn(), map[string]string{"source": source, "function": arn})
	})
	if err != nil {
		return nil, err
	}
	h.syncPoller(m)
	return ok(202, m.out("")), nil
}

// checkQueue verifies an SQS event source exists.
func (h *Handler) checkQueue(c *call, arn string) error {
	account, region, url, ok := sqs.QueueURL(arn)
	if !ok {
		return invalid("Invalid SQS queue ARN: %s", arn)
	}
	if _, err := h.SQS.Call(c.ctx, account, region, "GetQueueAttributes", map[string]any{"QueueUrl": url, "AttributeNames": []string{"QueueArn"}}); err != nil {
		return invalid("Error occurred while ReceiveMessage. SQS Error Code: AWS.SimpleQueueService.NonExistentQueue. SQS Error Message: The specified queue does not exist or you do not have access to it.")
	}
	return nil
}

func (h *Handler) listMappings(c *call) (*result, error) {
	if err := h.authorize(c, "ListEventSourceMappings", "*"); err != nil {
		return nil, err
	}
	q := `SELECT doc FROM lambda_esm WHERE account_id=? AND region=?`
	args := []any{c.account, c.region}
	if src := c.query.Get("EventSourceArn"); src != "" {
		q += ` AND source_arn=?`
		args = append(args, src)
	}
	if fn := c.query.Get("FunctionName"); fn != "" {
		ref, err := c.parseName(fn, "")
		if err != nil {
			return nil, err
		}
		q += ` AND (function_arn=? OR function_arn LIKE ?)`
		args = append(args, ref.qualifiedARN(ref.qualifier), ref.arn()+":%")
		if ref.qualifier != "" {
			args[len(args)-1] = ref.qualifiedARN(ref.qualifier)
		}
	}
	if marker := c.query.Get("Marker"); marker != "" {
		q += ` AND uuid > ?`
		args = append(args, marker)
	}
	maxItems, err := intParam(c.query, "MaxItems", 100)
	if err != nil {
		return nil, err
	}
	q += ` ORDER BY uuid LIMIT ?`
	args = append(args, maxItems+1)
	rows, err := h.st.DB().QueryContext(c.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []map[string]any{}
	out := map[string]any{}
	var last string
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		if len(list) == maxItems {
			out["NextMarker"] = last
			break
		}
		var m mapping
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			return nil, err
		}
		list = append(list, m.out(""))
		last = m.UUID
	}
	out["EventSourceMappings"] = list
	return ok(200, out), rows.Err()
}

func (h *Handler) getMapping(c *call) (*result, error) {
	if err := h.authorize(c, "GetEventSourceMapping", "*"); err != nil {
		return nil, err
	}
	m, err := loadMapping(c.ctx, h.st.DB(), c.account, c.params["UUID"])
	if err != nil {
		return nil, err
	}
	return ok(200, m.out("")), nil
}

// updateMapping applies fn to a stored mapping in a write transaction.
func (h *Handler) updateMapping(c *call, id string, fn func(m *mapping) error) error {
	var m *mapping
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		var err error
		if m, err = loadMapping(c.ctx, tx, c.account, id); err != nil {
			return err
		}
		if err := fn(m); err != nil {
			return err
		}
		if err := saveMapping(c.ctx, tx, m); err != nil {
			return err
		}
		return tx.Change("lambda", "UpdateEventSourceMapping", m.arn(), nil)
	})
	if err == nil {
		h.syncPoller(m)
	}
	return err
}

func (h *Handler) updateMappingOp(c *call) (*result, error) {
	if err := h.authorize(c, "UpdateEventSourceMapping", "*"); err != nil {
		return nil, err
	}
	var in map[string]any
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	var out map[string]any
	err := h.updateMapping(c, c.params["UUID"], func(m *mapping) error {
		if name, ok := in["FunctionName"].(string); ok && name != "" {
			arn, err := h.mappingFunction(c, h.st.DB(), name)
			if err != nil {
				return err
			}
			m.FunctionArn = arn
		}
		if e, ok := in["Enabled"].(bool); ok {
			m.Enabled = e
		}
		if b, ok := in["BatchSize"].(float64); ok && (b < 1 || b > 10000) {
			return invalid("BatchSize must be between 1 and 10000.")
		}
		for k, v := range in {
			switch k {
			case "FunctionName", "Enabled", "UUID":
			default:
				m.Doc[k] = v
			}
		}
		m.Modified = float64(h.now().UnixMilli()) / 1000
		out = m.out("")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(202, out), nil
}

func (h *Handler) deleteMapping(c *call) (*result, error) {
	if err := h.authorize(c, "DeleteEventSourceMapping", "*"); err != nil {
		return nil, err
	}
	id := c.params["UUID"]
	var out map[string]any
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		m, err := loadMapping(c.ctx, tx, c.account, id)
		if err != nil {
			return err
		}
		out = m.out("Deleting")
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_esm WHERE uuid=?`, id); err != nil {
			return err
		}
		return tx.Change("lambda", "DeleteEventSourceMapping", m.arn(), nil)
	})
	if err != nil {
		return nil, err
	}
	h.stopPoller(id)
	return ok(202, out), nil
}

// ---- SQS polling ----------------------------------------------------------------

// syncPoller starts or stops the poller of a mapping to match its state.
func (h *Handler) syncPoller(m *mapping) {
	if m == nil || !m.isSQS() || h.SQS == nil {
		return
	}
	h.stopPoller(m.UUID)
	if !m.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(h.bg)
	h.mu.Lock()
	h.pollers[m.UUID] = cancel
	h.mu.Unlock()
	go h.pollSQS(ctx, *m)
}

func (h *Handler) stopPoller(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if stop := h.pollers[id]; stop != nil {
		stop()
		delete(h.pollers, id)
	}
}

// sqsRecord is one message of an SQS event, as Lambda delivers it.
type sqsRecord struct {
	MessageID         string            `json:"messageId"`
	ReceiptHandle     string            `json:"receiptHandle"`
	Body              string            `json:"body"`
	Attributes        map[string]string `json:"attributes"`
	MessageAttributes map[string]any    `json:"messageAttributes"`
	MD5OfBody         string            `json:"md5OfBody"`
	EventSource       string            `json:"eventSource"`
	EventSourceARN    string            `json:"eventSourceARN"`
	AWSRegion         string            `json:"awsRegion"`
}

// pollSQS long-polls the mapping's queue and invokes the function with each
// batch. A successful invocation deletes the batch (or, with
// ReportBatchItemFailures, all but the failed items); a failed one leaves
// the messages to reappear when their visibility timeout ends, so the
// queue's redrive policy decides when they go to a dead-letter queue.
func (h *Handler) pollSQS(ctx context.Context, m mapping) {
	account, region, url, ok := sqs.QueueURL(m.SourceArn)
	if !ok {
		return
	}
	batch := 10
	if b, ok := m.Doc["BatchSize"].(float64); ok && b > 0 {
		batch = int(b)
	}
	window := 0.0
	if w, ok := m.Doc["MaximumBatchingWindowInSeconds"].(float64); ok {
		window = w
	}
	reportFailures := false
	if types, ok := m.Doc["FunctionResponseTypes"].([]any); ok {
		for _, t := range types {
			reportFailures = reportFailures || t == "ReportBatchItemFailures"
		}
	}
	ref, err := parseFunctionARN(m.FunctionArn)
	if err != nil {
		h.log.Error("event source mapping: bad function", "uuid", m.UUID, "err", err)
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		records, err := h.receiveBatch(ctx, account, region, url, m.SourceArn, batch, window)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			h.log.Warn("event source mapping: receive failed", "uuid", m.UUID, "err", err)
			sleep(ctx, backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if len(records) == 0 {
			continue
		}
		payload := jsonString(map[string]any{"Records": records})
		res, err := h.invoke(ctx, ref, []byte(payload), invokeOpts{source: "sqs"})
		failed := map[string]bool{}
		switch {
		case err != nil:
			h.log.Warn("event source mapping: invoke failed", "uuid", m.UUID, "err", err)
			h.setResult(m.UUID, "PROBLEM: Function call failed")
			sleep(ctx, time.Second)
			continue
		case res.functionError != "":
			h.setResult(m.UUID, "PROBLEM: Function call failed")
			continue
		case reportFailures:
			var resp struct {
				BatchItemFailures []struct {
					ItemIdentifier string `json:"itemIdentifier"`
				} `json:"batchItemFailures"`
			}
			if json.Unmarshal(res.payload, &resp) == nil {
				for _, f := range resp.BatchItemFailures {
					failed[f.ItemIdentifier] = true
				}
			}
		}
		h.setResult(m.UUID, "OK")
		var entries []map[string]string
		for i, r := range records {
			if !failed[r.MessageID] {
				entries = append(entries, map[string]string{"Id": itoa(i), "ReceiptHandle": r.ReceiptHandle})
			}
		}
		for len(entries) > 0 {
			n := min(len(entries), 10)
			if _, err := h.SQS.Call(ctx, account, region, "DeleteMessageBatch", map[string]any{"QueueUrl": url, "Entries": entries[:n]}); err != nil {
				h.log.Warn("event source mapping: delete failed", "uuid", m.UUID, "err", err)
			}
			entries = entries[n:]
		}
	}
}

// receiveBatch gathers up to batch messages, waiting at most the batching
// window for a batch to fill once the first message has arrived.
func (h *Handler) receiveBatch(ctx context.Context, account, region, url, arn string, batch int, window float64) ([]sqsRecord, error) {
	var records []sqsRecord
	deadline := time.Now().Add(time.Duration(window * float64(time.Second)))
	for len(records) < batch {
		wait := 20
		if len(records) > 0 {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			wait = min(20, int(left.Seconds()))
		}
		out, err := h.SQS.Call(ctx, account, region, "ReceiveMessage", map[string]any{
			"QueueUrl": url, "MaxNumberOfMessages": min(10, batch-len(records)), "WaitTimeSeconds": wait,
			"AttributeNames": []string{"All"}, "MessageAttributeNames": []string{"All"},
		})
		if err != nil {
			return records, err
		}
		msgs, _ := out["Messages"].([]map[string]any)
		if len(msgs) == 0 && len(records) > 0 {
			break
		}
		for _, raw := range msgs {
			var r sqsRecord
			b, _ := json.Marshal(raw)
			var wire struct {
				MessageId, ReceiptHandle, Body, MD5OfBody string
				Attributes                                map[string]string
				MessageAttributes                         map[string]map[string]any
			}
			_ = json.Unmarshal(b, &wire)
			r.MessageID, r.ReceiptHandle, r.Body, r.MD5OfBody = wire.MessageId, wire.ReceiptHandle, wire.Body, wire.MD5OfBody
			r.Attributes = wire.Attributes
			r.MessageAttributes = map[string]any{}
			for k, a := range wire.MessageAttributes {
				// Lambda's SQS event uses lower-camel attribute members.
				conv := map[string]any{"dataType": a["DataType"], "stringListValues": []any{}, "binaryListValues": []any{}}
				if v, ok := a["StringValue"]; ok {
					conv["stringValue"] = v
				}
				if v, ok := a["BinaryValue"]; ok {
					conv["binaryValue"] = v
				}
				r.MessageAttributes[k] = conv
			}
			r.EventSource, r.EventSourceARN, r.AWSRegion = "aws:sqs", arn, region
			records = append(records, r)
		}
		if window <= 0 {
			break
		}
	}
	return records, nil
}

func (h *Handler) setResult(id, result string) {
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		_, err := tx.Exec(`UPDATE lambda_esm SET doc = json_set(doc, '$.LastProcessingResult', ?) WHERE uuid = ?`, result, id)
		return err
	})
	if err != nil {
		h.log.Warn("event source mapping: record result", "uuid", id, "err", err)
	}
}

// StartPollers starts the pollers of every enabled SQS mapping (at startup).
func (h *Handler) StartPollers(ctx context.Context) error {
	rows, err := h.st.DB().QueryContext(ctx, `SELECT doc FROM lambda_esm WHERE enabled`)
	if err != nil {
		return err
	}
	var ms []*mapping
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			rows.Close()
			return err
		}
		var m mapping
		if err := json.Unmarshal([]byte(doc), &m); err == nil {
			ms = append(ms, &m)
		}
	}
	rows.Close()
	for _, m := range ms {
		h.syncPoller(m)
	}
	return rows.Err()
}

// parseFunctionARN splits a (possibly qualified) function ARN.
func parseFunctionARN(arn string) (fnRef, error) {
	p := strings.Split(arn, ":")
	if len(p) < 7 || p[0] != "arn" || p[2] != "lambda" || p[5] != "function" {
		return fnRef{}, invalid("invalid function ARN %s", arn)
	}
	ref := fnRef{account: p[4], region: p[3], name: p[6]}
	if len(p) == 8 {
		ref.qualifier = p[7]
	}
	return ref, nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
