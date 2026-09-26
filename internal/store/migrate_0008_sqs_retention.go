package store

// 0008: an SQS message's retention clock is separate from its SentTimestamp,
// because moving a message to a FIFO dead-letter queue restarts the clock.
func init() {
	register(8, "sqs_retention", `
ALTER TABLE sqs_messages ADD COLUMN enqueued INTEGER NOT NULL DEFAULT 0;
UPDATE sqs_messages SET enqueued=sent;
`)
}
