package sqs

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"citadel/internal/store"
)

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func bodyMD5(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
func attributeMD5(attrs map[string]attribute) string {
	names := make([]string, 0, len(attrs))
	for k := range attrs {
		names = append(names, k)
	}
	sort.Strings(names)
	h := md5.New()
	for _, name := range names {
		a := attrs[name]
		hashPart(h, []byte(name))
		hashPart(h, []byte(a.DataType))
		if strings.SplitN(a.DataType, ".", 2)[0] == "Binary" {
			_, _ = h.Write([]byte{2})
			hashPart(h, a.BinaryValue)
		} else {
			_, _ = h.Write([]byte{1})
			hashPart(h, []byte(a.StringValue))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
func hashPart(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

var attributeNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)

func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !(r == 9 || r == 10 || r == 13 || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff) {
			return false
		}
	}
	return true
}
func validateMessageAttributes(attrs map[string]attribute, system bool) (int, error) {
	if len(attrs) > 10 {
		return 0, fail("InvalidParameterValue", "Number of message attributes exceeds the allowed maximum.")
	}
	size := 0
	for name, a := range attrs {
		lower := strings.ToLower(name)
		if !attributeNameRE.MatchString(name) || strings.HasPrefix(lower, "aws.") || strings.HasPrefix(lower, "amazon.") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
			return 0, fail("InvalidParameterValue", "The message attribute name '%s' is invalid. Attribute name can contain A-Z, a-z, 0-9, underscore (_), hyphen (-), and period (.) characters.", name)
		}
		kind := strings.SplitN(a.DataType, ".", 2)[0]
		if (kind != "String" && kind != "Number" && kind != "Binary") || len(a.DataType) > 256 || !validText(a.DataType) {
			return 0, fail("InvalidParameterValue", "The message attribute '%s' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String.", name)
		}
		if len(a.StringListValues) > 0 || len(a.BinaryListValues) > 0 {
			return 0, fail("InvalidParameterValue", "List values are not supported.")
		}
		if kind == "Binary" {
			if len(a.BinaryValue) == 0 || a.StringValue != "" {
				return 0, fail("InvalidParameterValue", "The message attribute '%s' must contain a non-empty binary value.", name)
			}
			size += len(a.BinaryValue)
		} else {
			if a.StringValue == "" || !validText(a.StringValue) || len(a.BinaryValue) > 0 {
				return 0, fail("InvalidParameterValue", "The message attribute '%s' must contain a non-empty string value.", name)
			}
			if kind == "Number" {
				value, err := normalizeNumber(a.StringValue)
				if err != nil {
					return 0, fail("InvalidParameterValue", "The message attribute '%s' has an invalid Number value.", name)
				}
				a.StringValue = value
				attrs[name] = a
			}
			size += len(a.StringValue)
		}
		if system && (name != "AWSTraceHeader" || a.DataType != "String") {
			return 0, fail("InvalidParameterValue", "Unsupported message system attribute %s.", name)
		}
		size += len(name) + len(a.DataType)
	}
	return size, nil
}

// Normalize a decimal without converting its 38 significant digits to float64.
var decimalRE = regexp.MustCompile(`^([+-]?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$`)

func normalizeNumber(s string) (string, error) {
	m := decimalRE.FindStringSubmatch(s)
	if m == nil || m[2]+m[3] == "" {
		return "", fmt.Errorf("invalid number")
	}
	exponent := 0
	var err error
	if m[4] != "" {
		exponent, err = strconv.Atoi(m[4])
		if err != nil || exponent < -10000 || exponent > 10000 {
			return "", fmt.Errorf("number out of range")
		}
	}
	digits := strings.TrimLeft(m[2]+m[3], "0")
	scale := len(m[3]) - exponent
	if digits == "" {
		return "0", nil
	}
	trimmed := strings.TrimRight(digits, "0")
	scale -= len(digits) - len(trimmed)
	digits = trimmed
	magnitude := len(digits) - scale - 1
	if len(digits) > 38 || magnitude < -128 || magnitude > 126 {
		return "", fmt.Errorf("number out of range")
	}
	if scale <= 0 {
		digits += strings.Repeat("0", -scale)
	} else if scale >= len(digits) {
		digits = "0." + strings.Repeat("0", scale-len(digits)) + digits
	} else {
		digits = digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
	}
	if m[1] == "-" {
		digits = "-" + digits
	}
	return digits, nil
}
func (h *Handler) sendMessage(c *call, r *request) (map[string]any, error) {
	out := map[string]any{}
	var queueID int64
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		q, err := loadQueue(tx, c, r.QueueUrl)
		if err != nil {
			return err
		}
		queueID = q.ID
		if q.fifo() {
			return &serviceError{501, "NotImplemented", "citadel: FIFO delivery is not implemented yet"}
		}
		if r.MessageBody == "" {
			return fail("MissingParameter", "The request must contain the parameter MessageBody.")
		}
		if !validText(r.MessageBody) {
			return fail("InvalidMessageContents", "The message contains characters outside the allowed set.")
		}
		attrSize, err := validateMessageAttributes(r.MessageAttributes, false)
		if err != nil {
			return err
		}
		if _, err = validateMessageAttributes(r.MessageSystemAttributes, true); err != nil {
			return err
		}
		if len(r.MessageBody)+attrSize > q.number("MaximumMessageSize") {
			return fail("InvalidParameterValue", "One or more parameters are invalid. Reason: Message must be shorter than %d bytes.", q.number("MaximumMessageSize"))
		}
		delay := intValue(r.DelaySeconds, q.number("DelaySeconds"))
		if delay < 0 || delay > 900 {
			return fail("InvalidParameterValue", "Value %d for parameter DelaySeconds is invalid. Reason: DelaySeconds must be >= 0 and <= 900.", delay)
		}
		if r.MessageDeduplicationId != "" {
			return fail("InvalidParameterValue", "MessageDeduplicationId is valid only for FIFO queues.")
		}
		if len(r.MessageGroupId) > 128 || !validIdentifier(r.MessageGroupId) {
			return fail("InvalidParameterValue", "Invalid MessageGroupId.")
		}
		id := randomID()
		now := h.now().UnixMilli()
		result, err := tx.ExecContext(c.ctx, `INSERT INTO sqs_messages(queue_id,message_id,body,attrs,system_attrs,sender,sent,visible_at,group_id,dedup_id) VALUES(?,?,?,?,?,?,?,?,?,?)`, q.ID, id, r.MessageBody, jsonText(r.MessageAttributes), jsonText(r.MessageSystemAttributes), c.sender, now, now+int64(delay)*1000, r.MessageGroupId, r.MessageDeduplicationId)
		if err != nil {
			return err
		}
		seq, err := result.LastInsertId()
		if err != nil {
			return err
		}
		out = sendResult(r, id, seq, false)
		return tx.Change("sqs", "SendMessage", q.arn(), map[string]any{"sequence": seq, "messageId": id, "body": r.MessageBody, "attributes": r.MessageAttributes, "visibleAt": now + int64(delay)*1000})
	})
	if err == nil {
		h.notify(queueID)
	}
	return out, err
}
func validIdentifier(s string) bool {
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
func sendResult(r *request, id string, seq int64, fifo bool) map[string]any {
	out := map[string]any{"MessageId": id, "MD5OfMessageBody": bodyMD5(r.MessageBody)}
	if len(r.MessageAttributes) > 0 {
		out["MD5OfMessageAttributes"] = attributeMD5(r.MessageAttributes)
	}
	if len(r.MessageSystemAttributes) > 0 {
		out["MD5OfMessageSystemAttributes"] = attributeMD5(r.MessageSystemAttributes)
	}
	if fifo {
		out["SequenceNumber"] = strconv.FormatInt(seq, 10)
	}
	return out
}

type message struct {
	Seq                            int64
	ID, Body, Sender               string
	Attrs, System                  map[string]attribute
	Sent, Visible, First, Received int64
	Count                          int
	Receipt, Group, Dedup          string
}

const messageColumns = "seq,message_id,body,attrs,system_attrs,sender,sent,visible_at,receive_count,first_received,received,receipt,group_id,dedup_id"

func scanMessage(row interface{ Scan(...any) error }) (message, error) {
	var m message
	var attrs, system string
	err := row.Scan(&m.Seq, &m.ID, &m.Body, &attrs, &system, &m.Sender, &m.Sent, &m.Visible, &m.Count, &m.First, &m.Received, &m.Receipt, &m.Group, &m.Dedup)
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal([]byte(attrs), &m.Attrs); err != nil {
		return m, err
	}
	err = json.Unmarshal([]byte(system), &m.System)
	return m, err
}
func requested(name string, patterns []string) bool {
	for _, p := range patterns {
		if p == "All" || p == ".*" || name == p || strings.HasSuffix(p, ".*") && strings.HasPrefix(name, strings.TrimSuffix(p, ".*")) {
			return true
		}
	}
	return false
}
func (m *message) response(r *request, fifo bool) map[string]any {
	out := map[string]any{"MessageId": m.ID, "ReceiptHandle": m.Receipt, "MD5OfBody": bodyMD5(m.Body), "Body": m.Body}
	system := map[string]string{"SenderId": m.Sender, "SentTimestamp": strconv.FormatInt(m.Sent, 10), "ApproximateReceiveCount": strconv.Itoa(m.Count), "ApproximateFirstReceiveTimestamp": strconv.FormatInt(m.First, 10)}
	if m.Group != "" {
		system["MessageGroupId"] = m.Group
	}
	if fifo {
		system["MessageDeduplicationId"] = m.Dedup
		system["SequenceNumber"] = strconv.FormatInt(m.Seq, 10)
	}
	for k, a := range m.System {
		system[k] = a.StringValue
	}
	selected := map[string]string{}
	for k, v := range system {
		if requested(k, r.AttributeNames) || requested(k, r.MessageSystemAttributeNames) {
			selected[k] = v
		}
	}
	if len(selected) > 0 {
		out["Attributes"] = selected
	}
	attrs := map[string]attribute{}
	for k, v := range m.Attrs {
		if requested(k, r.MessageAttributeNames) {
			attrs[k] = v
		}
	}
	if len(attrs) > 0 {
		out["MessageAttributes"] = attrs
		out["MD5OfMessageAttributes"] = attributeMD5(attrs)
	}
	return out
}
func (h *Handler) receiveMessage(c *call, r *request) (map[string]any, error) {
	q, err := loadQueue(h.st.DB(), c, r.QueueUrl)
	if err != nil {
		return nil, err
	}
	wait := intValue(r.WaitTimeSeconds, q.number("ReceiveMessageWaitTimeSeconds"))
	max := intValue(r.MaxNumberOfMessages, 1)
	visibility := intValue(r.VisibilityTimeout, q.number("VisibilityTimeout"))
	if max < 1 || max > 10 {
		return nil, fail("InvalidParameterValue", "MaxNumberOfMessages must be between 1 and 10.")
	}
	if wait < 0 || wait > 20 {
		return nil, fail("InvalidParameterValue", "WaitTimeSeconds must be between 0 and 20.")
	}
	if visibility < 0 || visibility > 43200 {
		return nil, fail("InvalidParameterValue", "VisibilityTimeout must be between 0 and 43200.")
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		// Register before checking durable state, avoiding the lost-wakeup race.
		notice := h.notifier(q.ID)
		messages := []map[string]any{}
		next := int64(0)
		err = h.st.Update(c.ctx, func(tx *store.Tx) error {
			current, err := loadQueue(tx, c, r.QueueUrl)
			if err != nil {
				return err
			}
			q = current
			now := h.now().UnixMilli()
			expired, err := tx.ExecContext(c.ctx, `DELETE FROM sqs_messages WHERE queue_id=? AND sent<=?`, q.ID, now-int64(q.number("MessageRetentionPeriod"))*1000)
			if err != nil {
				return err
			}
			if count, _ := expired.RowsAffected(); count > 0 {
				if err = tx.Change("sqs", "ExpireMessages", q.arn(), map[string]any{"count": count}); err != nil {
					return err
				}
			}
			rows, err := tx.QueryContext(c.ctx, `SELECT `+messageColumns+` FROM sqs_messages WHERE queue_id=? AND visible_at<=? ORDER BY seq LIMIT ?`, q.ID, now, max)
			if err != nil {
				return err
			}
			var ready []message
			for rows.Next() {
				m, err := scanMessage(rows)
				if err != nil {
					_ = rows.Close()
					return err
				}
				ready = append(ready, m)
			}
			err = rows.Err()
			_ = rows.Close()
			if err != nil {
				return err
			}
			for _, m := range ready {
				m.Count++
				if m.First == 0 {
					m.First = now
				}
				m.Received = now
				m.Visible = now + int64(visibility)*1000
				var nonce [32]byte
				_, _ = rand.Read(nonce[:])
				m.Receipt = base64.RawStdEncoding.EncodeToString(nonce[:])
				_, err = tx.ExecContext(c.ctx, `UPDATE sqs_messages SET visible_at=?,receive_count=?,first_received=?,received=?,receipt=? WHERE seq=?`, m.Visible, m.Count, m.First, now, m.Receipt, m.Seq)
				if err != nil {
					return err
				}
				if _, err = tx.ExecContext(c.ctx, `INSERT INTO sqs_receipts(handle,queue_id,message_seq,created) VALUES(?,?,?,?)`, m.Receipt, q.ID, m.Seq, now); err != nil {
					return err
				}
				if err = tx.Change("sqs", "ReceiveMessage", q.arn(), map[string]any{"sequence": m.Seq, "receipt": m.Receipt, "visibleAt": m.Visible, "receiveCount": m.Count}); err != nil {
					return err
				}
				messages = append(messages, m.response(r, q.fifo()))
			}
			return tx.QueryRowContext(c.ctx, `SELECT COALESCE(MIN(visible_at),0) FROM sqs_messages WHERE queue_id=? AND visible_at>?`, q.ID, now).Scan(&next)
		})
		if err != nil {
			return nil, err
		}
		if len(messages) > 0 {
			return map[string]any{"Messages": messages}, nil
		}
		if wait == 0 || !time.Now().Before(deadline) {
			return map[string]any{}, nil
		}
		duration := time.Until(deadline)
		if next > 0 {
			until := time.Duration(next-h.now().UnixMilli()) * time.Millisecond
			if until < time.Millisecond {
				until = time.Millisecond
			}
			if until < duration {
				duration = until
			}
		}
		timer := time.NewTimer(duration)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return nil, c.ctx.Err()
		case <-notice:
			timer.Stop()
		case <-timer.C:
		}
	}
}
func (h *Handler) receiptOperation(c *call, op string, r *request) (map[string]any, error) {
	var id int64
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		q, err := loadQueue(tx, c, r.QueueUrl)
		if err != nil {
			return err
		}
		id = q.ID
		var seq int64
		if err = tx.QueryRowContext(c.ctx, `SELECT message_seq FROM sqs_receipts WHERE queue_id=? AND handle=?`, q.ID, r.ReceiptHandle).Scan(&seq); err != nil {
			return fail("ReceiptHandleIsInvalid", "The input receipt handle %q is not a valid receipt handle.", r.ReceiptHandle)
		}
		if op == "DeleteMessage" {
			_, err = tx.ExecContext(c.ctx, `DELETE FROM sqs_messages WHERE queue_id=? AND seq=? AND receipt=?`, q.ID, seq, r.ReceiptHandle)
		} else {
			timeout := intValue(r.VisibilityTimeout, -1)
			if timeout < 0 || timeout > 43200 {
				return fail("InvalidParameterValue", "VisibilityTimeout must be between 0 and 43200.")
			}
			var visible, received int64
			if err = tx.QueryRowContext(c.ctx, `SELECT visible_at,received FROM sqs_messages WHERE queue_id=? AND seq=? AND receipt=?`, q.ID, seq, r.ReceiptHandle).Scan(&visible, &received); err != nil {
				return fail("MessageNotInflight", "The specified message does not exist or is not available for visibility timeout change.")
			}
			now := h.now().UnixMilli()
			if visible <= now {
				return fail("MessageNotInflight", "The specified message does not exist or is not available for visibility timeout change.")
			}
			if now+int64(timeout)*1000 > received+43200000 {
				return fail("InvalidParameterValue", "VisibilityTimeout exceeds the maximum time left.")
			}
			_, err = tx.ExecContext(c.ctx, `UPDATE sqs_messages SET visible_at=? WHERE seq=?`, now+int64(timeout)*1000, seq)
		}
		if err != nil {
			return err
		}
		return tx.Change("sqs", op, q.arn(), r)
	})
	if err == nil {
		h.notify(id)
	}
	return map[string]any{}, err
}
