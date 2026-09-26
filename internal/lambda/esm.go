package lambda

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"citadel/internal/store"
)

// Event source mappings. Only SQS sources are polled: a poller per enabled
// mapping long-polls its queue, invokes the function with a batch, and
// deletes the messages the function handled. Messages from a failed batch
// stay in the queue and come back when their visibility timeout ends (and
// move to the queue's dead-letter queue by its redrive policy).

// passthrough are the mapping settings stored and echoed as sent.
var passthrough = []string{
	"FilterCriteria", "ParallelizationFactor", "StartingPosition", "StartingPositionTimestamp", "DestinationConfig",
	"MaximumRecordAgeInSeconds", "BisectBatchOnFunctionError", "MaximumRetryAttempts", "TumblingWindowInSeconds",
	"Topics", "Queues", "SourceAccessConfigurations", "SelfManagedEventSource", "FunctionResponseTypes",
	"AmazonManagedKafkaEventSourceConfig", "SelfManagedKafkaEventSourceConfig", "ScalingConfig",
	"DocumentDBEventSourceConfig", "KMSKeyArn", "MetricsConfig", "ProvisionedPollerConfig",
}

type mapping struct {
	UUID, Account, Region  string
	FunctionArn, SourceArn string
	Enabled                bool
	Config                 map[string]any // BatchSize, MaximumBatchingWindowInSeconds and the passthrough settings
	Tags                   map[string]string
	Modified               int64
	Result                 string
}

func (m *mapping) arn() string {
	return "arn:" + partition(m.Region) + ":lambda:" + m.Region + ":" + m.Account + ":event-source-mapping:" + m.UUID
}

func (m *mapping) view(state string) map[string]any {
	out := map[string]any{}
	for k, v := range m.Config {
		out[k] = v
	}
	if state == "" {
		state = "Disabled"
		if m.Enabled {
			state = "Enabled"
		}
	}
	out["UUID"] = m.UUID
	out["EventSourceArn"] = m.SourceArn
	out["FunctionArn"] = m.FunctionArn
	out["State"] = state
	out["StateTransitionReason"] = "USER_INITIATED"
	out["LastModified"] = float64(m.Modified) / 1000
	out["EventSourceMappingArn"] = m.arn()
	if _, ok := out["FunctionResponseTypes"]; !ok {
		out["FunctionResponseTypes"] = []string{}
	}
	return out
}

func (m *mapping) intSetting(k string, def int) int {
	switch v := m.Config[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}

const mappingColumns = `uuid, account, region, function_arn, source_arn, enabled, config, tags, modified, result`

func scanMapping(row interface{ Scan(...any) error }) (*mapping, error) {
	var m mapping
	var cfg, tags string
	err := row.Scan(&m.UUID, &m.Account, &m.Region, &m.FunctionArn, &m.SourceArn, &m.Enabled, &cfg, &tags, &m.Modified, &m.Result)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("The resource you requested does not exist.")
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(cfg), &m.Config); err != nil {
		return nil, err
	}
	return &m, json.Unmarshal([]byte(tags), &m.Tags)
}

func saveMapping(ctx context.Context, tx *store.Tx, m *mapping) error {
	cfg, _ := json.Marshal(m.Config)
	tags, _ := json.Marshal(m.Tags)
	_, err := tx.ExecContext(ctx, `INSERT INTO lambda_mappings(`+mappingColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(uuid) DO UPDATE SET function_arn=excluded.function_arn, enabled=excluded.enabled, config=excluded.config,
		tags=excluded.tags, modified=excluded.modified`,
		m.UUID, m.Account, m.Region, m.FunctionArn, m.SourceArn, m.Enabled, string(cfg), string(tags), m.Modified, m.Result)
	return err
}

// sqsSource splits an SQS queue ARN into its region, account and name.
func sqsSource(arn string) (region, account, name string, ok bool) {
	p := strings.Split(arn, ":")
	if len(p) != 6 || p[0] != "arn" || p[2] != "sqs" {
		return "", "", "", false
	}
	return p[3], p[4], p[5], true
}

// applyMapping validates and applies create/update settings.
func (h *Handler) applyMapping(c *call, m *mapping, req map[string]any, creating bool) error {
	if v, ok := req["FunctionName"].(string); ok {
		f, err := parseRef(v)
		if err != nil {
			return err
		}
		fn, err := c.loadFunction(h.st.DB(), f)
		if err != nil {
			return err
		}
		if f.qualifier != "" {
			if _, _, err := c.resolve(h.st.DB(), fn, f); err != nil {
				return err
			}
		}
		m.FunctionArn = c.refARN(fnRef{name: fn.Name, qualifier: f.qualifier})
	} else if creating {
		return validation("null", "functionName", "Member must not be null")
	}
	if v, ok := req["Enabled"].(bool); ok {
		m.Enabled = v
	}
	fifo := strings.HasSuffix(m.SourceArn, ".fifo")
	batch := m.intSetting("BatchSize", 10)
	if v, ok := req["BatchSize"].(float64); ok {
		batch = int(v)
	}
	window := m.intSetting("MaximumBatchingWindowInSeconds", 0)
	if v, ok := req["MaximumBatchingWindowInSeconds"].(float64); ok {
		window = int(v)
	}
	switch {
	case batch < 1:
		return validation(strconv.Itoa(batch), "batchSize", "Member must have value greater than or equal to 1")
	case batch > 10000:
		return validation(strconv.Itoa(batch), "batchSize", "Member must have value less than or equal to 10000")
	case batch > 10 && (fifo || window == 0):
		return invalidParam("Maximum batch window in seconds must be greater than 0 if maximum batch size is greater than 10")
	case window < 0 || window > 300:
		return validation(strconv.Itoa(window), "maximumBatchingWindowInSeconds", "Member must have value less than or equal to 300")
	}
	m.Config["BatchSize"] = batch
	m.Config["MaximumBatchingWindowInSeconds"] = window
	for _, k := range passthrough {
		if v, ok := req[k]; ok {
			m.Config[k] = v
		}
	}
	if v, ok := m.Config["FunctionResponseTypes"].([]any); ok {
		for _, t := range v {
			if t != "ReportBatchItemFailures" {
				return validation("["+jsonString(t)+"]", "functionResponseTypes", "Member must satisfy constraint: [Member must satisfy enum value set: [ReportBatchItemFailures]]")
			}
		}
	}
	return nil
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }

func (h *Handler) createMapping(c *call) error {
	var req map[string]any
	if err := c.decode(&req, 1<<20); err != nil {
		return err
	}
	source, _ := req["EventSourceArn"].(string)
	if source == "" {
		return invalidParam("Unrecognized event source, must be kafka or specify an EventSourceArn")
	}
	if err := h.authorize(c, "CreateEventSourceMapping", "*"); err != nil {
		return err
	}
	region, account, name, ok := sqsSource(source)
	if !ok {
		return errorf(501, "NotImplemented", "citadel: event source mappings support SQS queues only, not %s", source)
	}
	if region != c.region || h.SQS == nil {
		return invalidParam("Error occurred while ReceiveMessage. SQS Error Code: AWS.SimpleQueueService.NonExistentQueue. SQS Error Message: The specified queue does not exist or you do not have access to it.")
	}
	if account != c.account {
		return invalidParam("The provided execution role does not have permissions to call ReceiveMessage on SQS")
	}
	if _, err := h.SQS.Call(c.ctx, account, region, "GetQueueAttributes", map[string]any{"QueueUrl": queueURL(account, name)}); err != nil {
		return invalidParam("Error occurred while ReceiveMessage. SQS Error Code: AWS.SimpleQueueService.NonExistentQueue. SQS Error Message: The specified queue does not exist or you do not have access to it.")
	}
	m := &mapping{UUID: newRevision(), Account: c.account, Region: c.region, SourceArn: source, Enabled: true,
		Config: map[string]any{}, Tags: map[string]string{}, Modified: h.now().UnixMilli(), Result: "No records processed"}
	if tags, ok := req["Tags"].(map[string]any); ok {
		for k, v := range tags {
			s, _ := v.(string)
			m.Tags[k] = s
		}
		if err := validateTags(m.Tags); err != nil {
			return err
		}
	}
	if err := h.applyMapping(c, m, req, true); err != nil {
		return err
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		var existing string
		err := tx.QueryRowContext(c.ctx, `SELECT uuid FROM lambda_mappings WHERE account=? AND region=? AND source_arn=? AND function_arn=?`,
			c.account, c.region, source, m.FunctionArn).Scan(&existing)
		if err == nil {
			return conflict("An event source mapping with SQS arn (\" %s \") and function (\" %s \") already exists. Please update or delete the existing mapping with UUID %s",
				source, m.FunctionArn[strings.LastIndex(m.FunctionArn, ":function:")+10:], existing)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := saveMapping(c.ctx, tx, m); err != nil {
			return err
		}
		return tx.Change("lambda", "CreateEventSourceMapping", m.arn(), map[string]any{"source": source, "function": m.FunctionArn})
	})
	if err != nil {
		return err
	}
	h.syncPollers()
	// The poller is running when this returns, so the mapping is already
	// Enabled rather than Creating.
	writeJSON(c.w, 202, m.view(""))
	return nil
}

func (h *Handler) loadMapping(c *call, q querier, uuid string) (*mapping, error) {
	return scanMapping(q.QueryRowContext(c.ctx, `SELECT `+mappingColumns+` FROM lambda_mappings WHERE uuid=? AND account=? AND region=?`,
		uuid, c.account, c.region))
}

func (h *Handler) mapping(c *call, uuid string) error {
	switch c.r.Method {
	case http.MethodGet:
		if err := h.authorize(c, "GetEventSourceMapping", "*"); err != nil {
			return err
		}
		m, err := h.loadMapping(c, h.st.DB(), uuid)
		if err != nil {
			return err
		}
		writeJSON(c.w, 200, m.view(""))
		return nil
	case http.MethodPut:
		if err := h.authorize(c, "UpdateEventSourceMapping", "*"); err != nil {
			return err
		}
		var req map[string]any
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
		m, err := h.loadMapping(c, h.st.DB(), uuid)
		if err != nil {
			return err
		}
		if err := h.applyMapping(c, m, req, false); err != nil {
			return err
		}
		m.Modified = h.now().UnixMilli()
		err = h.st.Update(c.ctx, func(tx *store.Tx) error {
			if _, err := h.loadMapping(c, tx, uuid); err != nil {
				return err
			}
			if err := saveMapping(c.ctx, tx, m); err != nil {
				return err
			}
			return tx.Change("lambda", "UpdateEventSourceMapping", m.arn(), map[string]any{"enabled": m.Enabled, "function": m.FunctionArn})
		})
		if err != nil {
			return err
		}
		h.syncPollers()
		writeJSON(c.w, 202, m.view(""))
		return nil
	case http.MethodDelete:
		if err := h.authorize(c, "DeleteEventSourceMapping", "*"); err != nil {
			return err
		}
		var m *mapping
		err := h.st.Update(c.ctx, func(tx *store.Tx) error {
			var err error
			if m, err = h.loadMapping(c, tx, uuid); err != nil {
				return err
			}
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_mappings WHERE uuid=?`, uuid); err != nil {
				return err
			}
			return tx.Change("lambda", "DeleteEventSourceMapping", m.arn(), nil)
		})
		if err != nil {
			return err
		}
		h.syncPollers()
		writeJSON(c.w, 202, m.view("Deleting"))
		return nil
	}
	return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
}

func (h *Handler) listMappings(c *call) error {
	if err := h.authorize(c, "ListEventSourceMappings", "*"); err != nil {
		return err
	}
	offset, limit, err := marker(c)
	if err != nil {
		return err
	}
	q := `SELECT ` + mappingColumns + ` FROM lambda_mappings WHERE account=? AND region=?`
	args := []any{c.account, c.region}
	if s := c.query("EventSourceArn"); s != "" {
		q += ` AND source_arn=?`
		args = append(args, s)
	}
	if s := c.query("FunctionName"); s != "" {
		f, err := parseRef(s)
		if err != nil {
			return err
		}
		arn := c.functionARN(f.name)
		if f.qualifier != "" {
			q += ` AND function_arn=?`
			args = append(args, arn+":"+f.qualifier)
		} else {
			q += ` AND (function_arn=? OR substr(function_arn, 1, ?)=?)`
			args = append(args, arn, len(arn)+1, arn+":")
		}
	}
	q += ` ORDER BY modified, uuid LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := h.st.DB().QueryContext(c.ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		m, err := scanMapping(rows)
		if err != nil {
			return err
		}
		list = append(list, m.view(""))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out := map[string]any{"EventSourceMappings": list}
	if len(list) > limit {
		out["EventSourceMappings"] = list[:limit]
		out["NextMarker"] = strconv.Itoa(offset + limit)
	}
	writeJSON(c.w, 200, out)
	return nil
}

// ---- pollers -----------------------------------------------------------------------

type poller struct {
	modified int64
	cancel   context.CancelFunc
}

// syncPollers starts a poller for every enabled mapping and stops pollers
// whose mapping was disabled, changed or deleted.
func (h *Handler) syncPollers() {
	h.mu.Lock()
	base := h.ctx
	h.mu.Unlock()
	if h.SQS == nil {
		return
	}
	rows, err := h.st.DB().QueryContext(base, `SELECT `+mappingColumns+` FROM lambda_mappings WHERE enabled=1`)
	if err != nil {
		h.log.Warn("lambda: loading event source mappings", "err", err)
		return
	}
	want := map[string]*mapping{}
	for rows.Next() {
		if m, err := scanMapping(rows); err == nil {
			want[m.UUID] = m
		}
	}
	rows.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, p := range h.pollers {
		if m, ok := want[id]; !ok || m.Modified != p.modified {
			p.cancel()
			delete(h.pollers, id)
		}
	}
	for id, m := range want {
		if _, ok := h.pollers[id]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(base)
		h.pollers[id] = &poller{modified: m.Modified, cancel: cancel}
		go h.poll(ctx, m)
	}
}

func (h *Handler) stopPollers() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, p := range h.pollers {
		p.cancel()
		delete(h.pollers, id)
	}
}

// poll is one mapping's SQS poller.
func (h *Handler) poll(ctx context.Context, m *mapping) {
	region, account, name, _ := sqsSource(m.SourceArn)
	url := queueURL(account, name)
	batch := m.intSetting("BatchSize", 10)
	window := time.Duration(m.intSetting("MaximumBatchingWindowInSeconds", 0)) * time.Second
	reportFailures := false
	if types, ok := m.Config["FunctionResponseTypes"].([]any); ok {
		for _, t := range types {
			reportFailures = reportFailures || t == "ReportBatchItemFailures"
		}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		var msgs []map[string]any
		deadline := time.Now().Add(window)
		for len(msgs) < batch && ctx.Err() == nil {
			wait := 20
			if len(msgs) > 0 {
				left := time.Until(deadline)
				if left <= 0 {
					break
				}
				wait = int((left + time.Second - 1) / time.Second)
			}
			out, err := h.SQS.Call(ctx, account, region, "ReceiveMessage", map[string]any{
				"QueueUrl": url, "MaxNumberOfMessages": min(10, batch-len(msgs)), "WaitTimeSeconds": wait,
				"AttributeNames": []string{"All"}, "MessageAttributeNames": []string{"All"}, "MessageSystemAttributeNames": []string{"All"},
			})
			if err != nil {
				if ctx.Err() == nil {
					h.log.Warn("lambda: polling queue", "mapping", m.UUID, "queue", m.SourceArn, "err", err)
					sleep(ctx, backoff)
					backoff = min(2*backoff, time.Minute)
				}
				break
			}
			backoff = time.Second
			got := decodeMessages(out)
			msgs = append(msgs, got...)
			if window == 0 || len(got) == 0 && len(msgs) == 0 {
				break
			}
		}
		if len(msgs) == 0 || ctx.Err() != nil {
			continue
		}
		h.deliverBatch(ctx, m, region, account, url, msgs, reportFailures)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// decodeMessages turns a ReceiveMessage result into plain JSON maps.
func decodeMessages(out map[string]any) []map[string]any {
	b, _ := json.Marshal(out["Messages"])
	var msgs []map[string]any
	_ = json.Unmarshal(b, &msgs)
	return msgs
}

// sqsRecord is a message as the SQS event source hands it to a function.
func sqsRecord(msg map[string]any, source, region string) map[string]any {
	attrs := map[string]any{}
	if a, ok := msg["Attributes"].(map[string]any); ok {
		attrs = a
	}
	mattrs := map[string]any{}
	if a, ok := msg["MessageAttributes"].(map[string]any); ok {
		for k, v := range a {
			av, _ := v.(map[string]any)
			rec := map[string]any{"dataType": av["DataType"], "stringListValues": []any{}, "binaryListValues": []any{}}
			if s, ok := av["StringValue"]; ok {
				rec["stringValue"] = s
			}
			if b, ok := av["BinaryValue"]; ok {
				rec["binaryValue"] = b
			}
			mattrs[k] = rec
		}
	}
	rec := map[string]any{
		"messageId": msg["MessageId"], "receiptHandle": msg["ReceiptHandle"], "body": msg["Body"],
		"attributes": attrs, "messageAttributes": mattrs, "md5OfBody": msg["MD5OfBody"],
		"eventSource": "aws:sqs", "eventSourceARN": source, "awsRegion": region,
	}
	if md5, ok := msg["MD5OfMessageAttributes"]; ok {
		rec["md5OfMessageAttributes"] = md5
	}
	return rec
}

func (h *Handler) deliverBatch(ctx context.Context, m *mapping, region, account, url string, msgs []map[string]any, reportFailures bool) {
	records := make([]map[string]any, 0, len(msgs))
	for _, msg := range msgs {
		records = append(records, sqsRecord(msg, m.SourceArn, region))
	}
	event, _ := json.Marshal(map[string]any{"Records": records})
	res, err := h.Invoke(ctx, m.Account, m.Region, m.FunctionArn, event)
	if err != nil || res.FunctionError != "" {
		reason := "function error"
		if err != nil {
			reason = err.Error()
		}
		h.log.Info("lambda: SQS batch failed; messages return after their visibility timeout", "mapping", m.UUID, "reason", reason)
		return
	}
	failed := map[string]bool{}
	if reportFailures {
		var resp struct {
			BatchItemFailures []struct{ ItemIdentifier string } `json:"batchItemFailures"`
		}
		if json.Unmarshal(res.Payload, &resp) == nil {
			for _, f := range resp.BatchItemFailures {
				failed[f.ItemIdentifier] = true
			}
		}
	}
	var entries []map[string]any
	for i, msg := range msgs {
		id, _ := msg["MessageId"].(string)
		if failed[id] {
			continue
		}
		entries = append(entries, map[string]any{"Id": strconv.Itoa(i), "ReceiptHandle": msg["ReceiptHandle"]})
	}
	for len(entries) > 0 {
		n := min(10, len(entries))
		if _, err := h.SQS.Call(ctx, account, region, "DeleteMessageBatch", map[string]any{"QueueUrl": url, "Entries": entries[:n]}); err != nil {
			h.log.Warn("lambda: deleting processed messages", "mapping", m.UUID, "err", err)
		}
		entries = entries[n:]
	}
}
