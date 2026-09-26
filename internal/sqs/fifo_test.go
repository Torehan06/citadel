package sqs

import (
	"testing"
	"time"
)

func TestFIFODeduplicationWindow(t *testing.T) {
	h, c := testHandler(t)
	clock := time.Unix(1_700_000_000, 0)
	h.now = func() time.Time { return clock }
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "dedup.fifo", Attributes: map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true"}})["QueueUrl"].(string)
	first := invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "same", MessageGroupId: "g"})
	for _, tc := range []struct {
		name      string
		advance   time.Duration
		req       request
		duplicate bool
	}{
		{"same body, other group", 0, request{MessageBody: "same", MessageGroupId: "h"}, true},
		{"explicit id equal to the body hash", time.Minute, request{MessageBody: "other", MessageGroupId: "g", MessageDeduplicationId: "0967115f2813a3541eaef77de9d9d5773f1c0c04314b0bbfe4ff3b3b1c55b5d5"}, true},
		{"new explicit id", 0, request{MessageBody: "same", MessageGroupId: "g", MessageDeduplicationId: "fresh"}, false},
		{"window expired", 5 * time.Minute, request{MessageBody: "same", MessageGroupId: "g"}, false},
	} {
		clock = clock.Add(tc.advance)
		tc.req.QueueUrl = u
		out := invoke(t, h, c, "SendMessage", tc.req)
		if (out["MessageId"] == first["MessageId"]) != tc.duplicate || out["SequenceNumber"] == nil {
			t.Fatal(tc.name, out)
		}
	}
	if _, err := h.dispatch(c, "SendMessage", &request{QueueUrl: u, MessageBody: "x"}); asError(err).Code != "MissingParameter" {
		t.Fatal("missing group accepted", err)
	}
	if _, err := h.dispatch(c, "SendMessage", &request{QueueUrl: u, MessageBody: "x", MessageGroupId: "g", DelaySeconds: ptr(5)}); asError(err).Code != "InvalidParameterValue" {
		t.Fatal("per-message delay accepted", err)
	}
}

func TestFIFOGroupsDeliverInOrderOneLeaseAtATime(t *testing.T) {
	h, c := testHandler(t)
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "groups.fifo", Attributes: map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true"}})["QueueUrl"].(string)
	for _, m := range []struct{ body, group string }{{"a1", "a"}, {"a2", "a"}, {"b1", "b"}, {"a3", "a"}} {
		invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: m.body, MessageGroupId: m.group})
	}
	bodies := func(out map[string]any) (s []string) {
		for _, m := range messageList(out) {
			s = append(s, m["Body"].(string))
		}
		return s
	}
	first := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u, MaxNumberOfMessages: ptr(2)}))
	if len(first) != 2 || first[0]["Body"] != "a1" || first[1]["Body"] != "a2" {
		t.Fatal(first)
	}
	// Group a is leased, so only b is deliverable.
	if got := bodies(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u, MaxNumberOfMessages: ptr(10)})); len(got) != 1 || got[0] != "b1" {
		t.Fatal(got)
	}
	// Releasing a2 alone does not unlock the group while a1 is in flight.
	invoke(t, h, c, "ChangeMessageVisibility", request{QueueUrl: u, ReceiptHandle: first[1]["ReceiptHandle"].(string), VisibilityTimeout: ptr(0)})
	if got := bodies(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u})); len(got) != 0 {
		t.Fatal(got)
	}
	invoke(t, h, c, "DeleteMessage", request{QueueUrl: u, ReceiptHandle: first[0]["ReceiptHandle"].(string)})
	if got := bodies(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u, MaxNumberOfMessages: ptr(10)})); len(got) != 2 || got[0] != "a2" || got[1] != "a3" {
		t.Fatal(got)
	}
}

func TestRedriveMovesExhaustedMessages(t *testing.T) {
	for _, fifo := range []bool{false, true} {
		h, c := testHandler(t)
		clock := time.Unix(1_700_000_000, 0)
		h.now = func() time.Time { return clock }
		attrs, suffix := map[string]string{}, ""
		if fifo {
			attrs, suffix = map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true"}, ".fifo"
		}
		dlq := invoke(t, h, c, "CreateQueue", request{QueueName: "dead" + suffix, Attributes: attrs})["QueueUrl"].(string)
		source := map[string]string{"VisibilityTimeout": "10", "RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:test-region:987654321098:dead` + suffix + `","maxReceiveCount":2}`}
		for k, v := range attrs {
			source[k] = v
		}
		u := invoke(t, h, c, "CreateQueue", request{QueueName: "work" + suffix, Attributes: source})["QueueUrl"].(string)
		sent := invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "poison", MessageGroupId: "g"})
		for i := 0; i < 2; i++ {
			if got := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u})); len(got) != 1 {
				t.Fatal(fifo, i, got)
			}
			clock = clock.Add(11 * time.Second)
		}
		if got := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u})); len(got) != 0 {
			t.Fatal(fifo, "third receive delivered", got)
		}
		got := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: dlq, AttributeNames: []string{"All"}}))
		if len(got) != 1 || got[0]["MessageId"] != sent["MessageId"] || got[0]["Attributes"].(map[string]any)["ApproximateReceiveCount"] != "3" {
			t.Fatal(fifo, got)
		}
	}
}

func TestRetentionClock(t *testing.T) {
	h, c := testHandler(t)
	clock := time.Unix(1_700_000_000, 0)
	h.now = func() time.Time { return clock }
	fifo := map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true", "MessageRetentionPeriod": "60"}
	invoke(t, h, c, "CreateQueue", request{QueueName: "dead.fifo", Attributes: fifo})
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "work.fifo", Attributes: map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true", "MessageRetentionPeriod": "120", "VisibilityTimeout": "0",
		"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:test-region:987654321098:dead.fifo","maxReceiveCount":1}`}})["QueueUrl"].(string)
	invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "kept", MessageGroupId: "g"})
	invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u})
	// 50 s later the message moves; a FIFO dead-letter queue restarts its
	// 60 s retention, so it outlives the original enqueue time + 60 s.
	clock = clock.Add(50 * time.Second)
	invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u})
	clock = clock.Add(30 * time.Second)
	dlq := "http://localhost:8420/987654321098/dead.fifo"
	if got := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: dlq, VisibilityTimeout: ptr(0)})); len(got) != 1 {
		t.Fatal("expired too early", got)
	}
	clock = clock.Add(31 * time.Second)
	if got := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: dlq})); len(got) != 0 {
		t.Fatal("outlived retention", got)
	}
	attrs := invoke(t, h, c, "GetQueueAttributes", request{QueueUrl: dlq, AttributeNames: []string{"ApproximateNumberOfMessages"}})
	if attrs["Attributes"].(map[string]string)["ApproximateNumberOfMessages"] != "0" {
		t.Fatal(attrs)
	}
}
