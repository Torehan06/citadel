package sqs

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"citadel/internal/store"
)

// dedupWindow is SQS's five-minute FIFO deduplication interval.
const dedupWindow = 5 * 60 * 1000

// fifoParameters checks FIFO-only send rules and resolves the deduplication ID,
// hashing the body when the queue uses content-based deduplication.
func fifoParameters(q *queue, r *request) (string, error) {
	if r.MessageGroupId == "" {
		return "", fail("MissingParameter", "The request must contain the parameter MessageGroupId.")
	}
	if r.DelaySeconds != nil && *r.DelaySeconds != 0 {
		return "", fail("InvalidParameterValue", "Value %d for parameter DelaySeconds is invalid. Reason: The request include parameter that is not valid for this queue type.", *r.DelaySeconds)
	}
	id := r.MessageDeduplicationId
	if id == "" {
		if q.Attrs["ContentBasedDeduplication"] != "true" {
			return "", fail("InvalidParameterValue", "The queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly")
		}
		sum := sha256.Sum256([]byte(r.MessageBody))
		id = hex.EncodeToString(sum[:])
	}
	if len(id) > 128 || !validIdentifier(id) {
		return "", fail("InvalidParameterValue", "Value %s for parameter MessageDeduplicationId is invalid.", id)
	}
	return id, nil
}

// dedupScope is the key space a deduplication ID lives in.
func dedupScope(q *queue, group string) string {
	if q.Attrs["DeduplicationScope"] == "messageGroup" {
		return group
	}
	return ""
}

// duplicate reports the message that an earlier send with the same
// deduplication ID created inside the window, if any.
func duplicate(ctx context.Context, tx *store.Tx, q *queue, scope, dedup string, now int64) (string, int64, bool, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sqs_dedup WHERE queue_id=? AND expires<=?`, q.ID, now); err != nil {
		return "", 0, false, err
	}
	var id string
	var seq int64
	err := tx.QueryRowContext(ctx, `SELECT message_id,sequence FROM sqs_dedup WHERE queue_id=? AND scope=? AND dedup_id=?`, q.ID, scope, dedup).Scan(&id, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	return id, seq, err == nil, err
}

// readyMessages returns up to limit deliverable messages in send order. On a
// FIFO queue a message is blocked while any message of its group is in
// flight, or while an earlier message of its group is not yet visible.
func readyMessages(ctx context.Context, tx *store.Tx, q *queue, now int64, limit int) ([]message, error) {
	query := `SELECT ` + messageColumns + ` FROM sqs_messages m WHERE m.queue_id=? AND m.visible_at<=? ORDER BY m.seq LIMIT ?`
	args := []any{q.ID, now, limit}
	if q.fifo() {
		query = `SELECT ` + messageColumns + ` FROM sqs_messages m WHERE m.queue_id=? AND m.visible_at<=? AND NOT EXISTS (
 SELECT 1 FROM sqs_messages o WHERE o.queue_id=m.queue_id AND o.group_id=m.group_id AND o.visible_at>? AND (o.seq<m.seq OR o.receive_count>0)
) ORDER BY m.seq LIMIT ?`
		args = []any{q.ID, now, now, limit}
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ready []message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		ready = append(ready, m)
	}
	return ready, rows.Err()
}

// redriveTarget returns the queue's dead-letter queue and maxReceiveCount, or
// nil when there is no redrive policy or its target no longer exists.
func redriveTarget(ctx context.Context, tx *store.Tx, q *queue) (*queue, int, error) {
	arn, max, err := redrive(q.Attrs["RedrivePolicy"])
	if err != nil {
		return nil, 0, nil
	}
	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return nil, 0, nil
	}
	target, err := scanQueue(tx.QueryRowContext(ctx, `SELECT `+queueColumns+` FROM sqs_queues WHERE account=? AND region=? AND name=?`, parts[4], parts[3], parts[5]))
	if err != nil {
		if asError(err).Code == "QueueDoesNotExist" {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return target, max, nil
}

// moveToDeadLetter transfers a message, keeping its ID, body, attributes and
// receive count. Standard queues keep the original retention clock; FIFO
// dead-letter queues restart it, as AWS does.
func moveToDeadLetter(ctx context.Context, tx *store.Tx, q, target *queue, m message, now int64) error {
	enqueued := m.Enqueued
	if target.fifo() {
		enqueued = now
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO sqs_messages(queue_id,message_id,body,attrs,system_attrs,sender,sent,enqueued,visible_at,receive_count,first_received,received,group_id,dedup_id)
 SELECT ?,message_id,body,attrs,system_attrs,sender,sent,?,?,receive_count,first_received,received,group_id,dedup_id FROM sqs_messages WHERE seq=?`, target.ID, enqueued, now, m.Seq)
	if err != nil {
		return err
	}
	seq, err := result.LastInsertId()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sqs_messages WHERE seq=?`, m.Seq); err != nil {
		return err
	}
	return tx.Change("sqs", "RedriveMessage", q.arn(), map[string]any{"sequence": m.Seq, "target": target.arn(), "targetSequence": seq, "messageId": m.ID})
}
