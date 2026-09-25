package sqs

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"citadel/internal/store"
)

type queue struct {
	ID                        int64
	Account, Region, Name     string
	Attrs, Tags               map[string]string
	Created, Modified, Purged int64
}

func (q *queue) fifo() bool          { return q.Attrs["FifoQueue"] == "true" }
func (q *queue) arn() string         { return "arn:aws:sqs:" + q.Region + ":" + q.Account + ":" + q.Name }
func (q *queue) number(k string) int { n, _ := strconv.Atoi(q.Attrs[k]); return n }

const queueColumns = "id,account,region,name,attrs,tags,created,modified,purged"

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func scanQueue(row interface{ Scan(...any) error }) (*queue, error) {
	var q queue
	var attrs, tags string
	err := row.Scan(&q.ID, &q.Account, &q.Region, &q.Name, &attrs, &tags, &q.Created, &q.Modified, &q.Purged)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, missingQueue()
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(attrs), &q.Attrs); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(tags), &q.Tags); err != nil {
		return nil, err
	}
	if q.Tags == nil {
		q.Tags = map[string]string{}
	}
	return &q, nil
}
func (h *Handler) queueByName(c *call, account, name string) (*queue, error) {
	return scanQueue(h.st.DB().QueryRowContext(c.ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? AND name=?`, account, c.region, name))
}
func loadQueue(db querier, c *call, raw string) (*queue, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, missingQueue()
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != c.account {
		return nil, missingQueue()
	}
	return scanQueue(db.QueryRowContext(c.ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? AND name=?`, parts[0], c.region, parts[1]))
}

var queueNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var numericAttrs = map[string][2]int{
	"DelaySeconds": {0, 900}, "MaximumMessageSize": {1024, 1048576}, "MessageRetentionPeriod": {60, 1209600},
	"ReceiveMessageWaitTimeSeconds": {0, 20}, "VisibilityTimeout": {0, 43200}, "KmsDataKeyReusePeriodSeconds": {60, 86400},
}

func defaults() map[string]string {
	return map[string]string{"DelaySeconds": "0", "MaximumMessageSize": "1048576", "MessageRetentionPeriod": "345600", "ReceiveMessageWaitTimeSeconds": "0", "VisibilityTimeout": "30", "SqsManagedSseEnabled": "true"}
}
func validateAttributes(db querier, c *call, attrs map[string]string, fifo bool) error {
	for key, val := range attrs {
		if bounds, ok := numericAttrs[key]; ok {
			n, err := strconv.Atoi(val)
			if err != nil || n < bounds[0] || n > bounds[1] {
				return fail("InvalidAttributeValue", "Invalid value for the parameter %s.", key)
			}
			continue
		}
		switch key {
		case "FifoQueue", "ContentBasedDeduplication", "SqsManagedSseEnabled":
			if val != "true" && val != "false" {
				return fail("InvalidAttributeValue", "Invalid value for the parameter %s.", key)
			}
			if key == "ContentBasedDeduplication" && !fifo {
				return fail("InvalidAttributeName", "Unknown Attribute %s.", key)
			}
		case "DeduplicationScope":
			if !fifo || (val != "queue" && val != "messageGroup") {
				return fail("InvalidAttributeValue", "Invalid value for the parameter %s.", key)
			}
		case "FifoThroughputLimit":
			if !fifo || (val != "perQueue" && val != "perMessageGroupId") {
				return fail("InvalidAttributeValue", "Invalid value for the parameter %s.", key)
			}
		case "Policy", "RedriveAllowPolicy":
			if val != "" {
				var doc map[string]any
				if json.Unmarshal([]byte(val), &doc) != nil || doc == nil {
					return fail("InvalidAttributeValue", "Invalid value for the parameter %s.", key)
				}
			}
		case "RedrivePolicy":
			if val == "" {
				continue
			}
			arn, n, err := redrive(val)
			if err != nil {
				return err
			}
			parts := strings.Split(arn, ":")
			if len(parts) != 6 || parts[0] != "arn" || parts[2] != "sqs" || parts[3] != c.region || parts[4] != c.account {
				return fail("InvalidParameterValue", "Invalid dead letter target ARN.")
			}
			target, err := scanQueue(db.QueryRowContext(c.ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? AND name=?`, parts[4], parts[3], parts[5]))
			if err != nil {
				return fail("InvalidParameterValue", "Value %s for parameter RedrivePolicy is invalid. Reason: Dead letter target does not exist.", val)
			}
			if target.fifo() != fifo {
				return fail("InvalidParameterValue", "Source queue and dead-letter queue must have the same type.")
			}
			var obj map[string]any
			_ = json.Unmarshal([]byte(val), &obj)
			if _, ok := obj["maxReceiveCount"].(string); ok {
				obj["maxReceiveCount"] = n
				attrs[key] = jsonText(obj)
			}
		case "KmsMasterKeyId":
		default:
			return fail("InvalidAttributeName", "Unknown Attribute %s.", key)
		}
	}
	return nil
}
func redrive(s string) (string, int, error) {
	var p struct {
		DeadLetterTargetArn string          `json:"deadLetterTargetArn"`
		MaxReceiveCount     json.RawMessage `json:"maxReceiveCount"`
	}
	if json.Unmarshal([]byte(s), &p) != nil {
		return "", 0, fail("InvalidParameterValue", "Invalid RedrivePolicy.")
	}
	n, err := strconv.Atoi(strings.Trim(string(p.MaxReceiveCount), `"`))
	if err != nil || n < 1 || n > 1000 || p.DeadLetterTargetArn == "" {
		return "", 0, fail("InvalidParameterValue", "RedrivePolicy requires deadLetterTargetArn and maxReceiveCount between 1 and 1000.")
	}
	return p.DeadLetterTargetArn, n, nil
}
func (h *Handler) createQueue(c *call, r *request) (map[string]any, error) {
	fifo := r.Attributes["FifoQueue"] == "true"
	name := r.QueueName
	if fifo {
		name = strings.TrimSuffix(name, ".fifo")
	}
	if !queueNameRE.MatchString(name) || len(r.QueueName) > 80 || (fifo && !strings.HasSuffix(r.QueueName, ".fifo")) {
		return nil, fail("InvalidParameterValue", "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length")
	}
	q := &queue{Account: c.account, Region: c.region, Name: r.QueueName, Attrs: defaults(), Tags: r.Tags, Created: h.now().Unix(), Modified: h.now().Unix()}
	if q.Tags == nil {
		q.Tags = map[string]string{}
	}
	if fifo {
		q.Attrs["FifoQueue"] = "true"
		q.Attrs["ContentBasedDeduplication"] = "false"
		q.Attrs["DeduplicationScope"] = "queue"
		q.Attrs["FifoThroughputLimit"] = "perQueue"
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		if err := validateAttributes(tx, c, r.Attributes, fifo); err != nil {
			return err
		}
		existing, err := scanQueue(tx.QueryRowContext(c.ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? AND name=?`, c.account, c.region, r.QueueName))
		if err == nil {
			for k, v := range r.Attributes {
				old := existing.Attrs[k]
				if k == "FifoQueue" && old == "" {
					old = "false"
				}
				if old != v {
					return fail("QueueNameExists", "A queue already exists with the same name and a different value for attribute %s", k)
				}
			}
			q = existing
			return nil
		}
		if e := asError(err); e.Code != "QueueDoesNotExist" {
			return err
		}
		for k, v := range r.Attributes {
			if v != "" {
				q.Attrs[k] = v
			}
		}
		result, err := tx.ExecContext(c.ctx, `INSERT INTO sqs_queues(account,region,name,attrs,tags,created,modified) VALUES(?,?,?,?,?,?,?)`, q.Account, q.Region, q.Name, jsonText(q.Attrs), jsonText(q.Tags), q.Created, q.Modified)
		if err != nil {
			return err
		}
		q.ID, err = result.LastInsertId()
		if err != nil {
			return err
		}
		return tx.Change("sqs", "CreateQueue", q.arn(), q)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"QueueUrl": c.queueURL(q)}, nil
}
func (h *Handler) listQueues(c *call, r *request) (map[string]any, error) {
	limit := intValue(r.MaxResults, 1000)
	if limit < 1 || limit > 1000 {
		return nil, fail("InvalidParameterValue", "MaxResults must be between 1 and 1000.")
	}
	after := ""
	if r.NextToken != "" {
		b, err := base64.RawURLEncoding.DecodeString(r.NextToken)
		if err != nil {
			return nil, fail("InvalidParameterValue", "Invalid NextToken.")
		}
		after = string(b)
	}
	rows, err := h.st.DB().QueryContext(c.ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? AND substr(name,1,?)=? AND name>? ORDER BY name LIMIT ?`, c.account, c.region, len(r.QueueNamePrefix), r.QueueNamePrefix, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]any{}
	urls := []string{}
	last := ""
	for rows.Next() {
		q, err := scanQueue(rows)
		if err != nil {
			return nil, err
		}
		if len(urls) == limit {
			if r.MaxResults != nil {
				out["NextToken"] = base64.RawURLEncoding.EncodeToString([]byte(last))
			}
			break
		}
		urls = append(urls, c.queueURL(q))
		last = q.Name
	}
	if len(urls) > 0 {
		out["QueueUrls"] = urls
	}
	return out, rows.Err()
}
func (h *Handler) queueOperation(c *call, op string, r *request) (map[string]any, error) {
	out := map[string]any{}
	var id int64
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		q, err := loadQueue(tx, c, r.QueueUrl)
		if err != nil {
			return err
		}
		id = q.ID
		switch op {
		case "GetQueueAttributes":
			attrs := map[string]string{}
			for k, v := range q.Attrs {
				attrs[k] = v
			}
			attrs["QueueArn"] = q.arn()
			attrs["CreatedTimestamp"] = strconv.FormatInt(q.Created, 10)
			attrs["LastModifiedTimestamp"] = strconv.FormatInt(q.Modified, 10)
			var visible, delayed, inflight int
			now := h.now().UnixMilli()
			err = tx.QueryRowContext(c.ctx, `SELECT COALESCE(SUM(visible_at<=?),0),COALESCE(SUM(visible_at>? AND receive_count=0),0),COALESCE(SUM(visible_at>? AND receive_count>0),0) FROM sqs_messages WHERE queue_id=? AND sent>?`, now, now, now, q.ID, now-int64(q.number("MessageRetentionPeriod"))*1000).Scan(&visible, &delayed, &inflight)
			if err != nil {
				return err
			}
			attrs["ApproximateNumberOfMessages"] = strconv.Itoa(visible)
			attrs["ApproximateNumberOfMessagesDelayed"] = strconv.Itoa(delayed)
			attrs["ApproximateNumberOfMessagesNotVisible"] = strconv.Itoa(inflight)
			selected := map[string]string{}
			for _, key := range r.AttributeNames {
				if key == "All" {
					for k, v := range attrs {
						selected[k] = v
					}
					continue
				}
				if v, ok := attrs[key]; ok {
					selected[key] = v
					continue
				}
				if _, ok := numericAttrs[key]; ok {
					continue
				}
				switch key {
				case "Policy", "RedrivePolicy", "RedriveAllowPolicy", "KmsMasterKeyId", "FifoQueue", "ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit":
				default:
					return fail("InvalidAttributeName", "Unknown Attribute %s.", key)
				}
			}
			if len(selected) > 0 {
				out["Attributes"] = selected
			}
			return nil
		case "ListQueueTags":
			if len(q.Tags) > 0 {
				out["Tags"] = q.Tags
			}
			return nil
		case "ListDeadLetterSourceQueues":
			rows, e := tx.QueryContext(c.ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? ORDER BY name`, c.account, c.region)
			if e != nil {
				return e
			}
			defer rows.Close()
			urls := []string{}
			for rows.Next() {
				source, e := scanQueue(rows)
				if e != nil {
					return e
				}
				arn, _, _ := redrive(source.Attrs["RedrivePolicy"])
				if arn == q.arn() {
					urls = append(urls, c.queueURL(source))
				}
			}
			out["queueUrls"] = urls
			return rows.Err()
		case "DeleteQueue":
			_, err = tx.ExecContext(c.ctx, `DELETE FROM sqs_queues WHERE id=?`, q.ID)
		case "PurgeQueue":
			now := h.now().UnixMilli()
			if q.Purged > 0 && now-q.Purged < 60000 {
				return fail("PurgeQueueInProgress", "Only one PurgeQueue operation on %s is allowed every 60 seconds.", q.Name)
			}
			if _, err = tx.ExecContext(c.ctx, `DELETE FROM sqs_messages WHERE queue_id=?`, q.ID); err != nil {
				return err
			}
			_, err = tx.ExecContext(c.ctx, `UPDATE sqs_queues SET purged=? WHERE id=?`, now, q.ID)
		case "SetQueueAttributes":
			if v, ok := r.Attributes["FifoQueue"]; ok && ((v == "true") != q.fifo()) {
				return fail("InvalidAttributeName", "The FifoQueue attribute cannot be changed.")
			}
			if err = validateAttributes(tx, c, r.Attributes, q.fifo()); err != nil {
				return err
			}
			for k, v := range r.Attributes {
				if v == "" {
					delete(q.Attrs, k)
				} else {
					q.Attrs[k] = v
				}
			}
			_, err = tx.ExecContext(c.ctx, `UPDATE sqs_queues SET attrs=?,modified=? WHERE id=?`, jsonText(q.Attrs), h.now().Unix(), q.ID)
		case "TagQueue", "UntagQueue":
			if op == "TagQueue" {
				if len(r.Tags) == 0 {
					return fail("MissingParameter", "The request must contain the parameter Tags")
				}
				for k, v := range r.Tags {
					q.Tags[k] = v
				}
			} else {
				if len(r.TagKeys) == 0 {
					return fail("InvalidParameterValue", "TagKeys must not be empty.")
				}
				for _, k := range r.TagKeys {
					delete(q.Tags, k)
				}
			}
			_, err = tx.ExecContext(c.ctx, `UPDATE sqs_queues SET tags=?,modified=? WHERE id=?`, jsonText(q.Tags), h.now().Unix(), q.ID)
		}
		if err != nil {
			return err
		}
		return tx.Change("sqs", op, q.arn(), r)
	})
	if err == nil {
		h.notify(id)
	}
	return out, err
}
