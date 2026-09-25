package sqs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func ptr(n int) *int { return &n }
func messageList(out map[string]any) []map[string]any {
	b, _ := json.Marshal(out["Messages"])
	var messages []map[string]any
	_ = json.Unmarshal(b, &messages)
	return messages
}
func TestMessageLeaseAndReceipts(t *testing.T) {
	h, c := testHandler(t)
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "leases"})["QueueUrl"].(string)
	sent := invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "hello &\r\nworld", MessageAttributes: map[string]attribute{"kind": {DataType: "String", StringValue: "event"}}})
	first := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u, MessageAttributeNames: []string{"All"}}))
	if len(first) != 1 || first[0]["MessageId"] != sent["MessageId"] || first[0]["Body"] != "hello &\r\nworld" {
		t.Fatal(first)
	}
	if len(messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u}))) != 0 {
		t.Fatal("in-flight message was delivered")
	}
	handle := first[0]["ReceiptHandle"].(string)
	invoke(t, h, c, "ChangeMessageVisibility", request{QueueUrl: u, ReceiptHandle: handle, VisibilityTimeout: ptr(0)})
	second := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u, AttributeNames: []string{"All"}}))
	if len(second) != 1 || second[0]["ReceiptHandle"] == handle {
		t.Fatal(second)
	}
	if second[0]["Attributes"].(map[string]any)["ApproximateReceiveCount"] != "2" {
		t.Fatal(second)
	}
	invoke(t, h, c, "DeleteMessage", request{QueueUrl: u, ReceiptHandle: second[0]["ReceiptHandle"].(string)})
	if len(messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u}))) != 0 {
		t.Fatal("deleted message delivered")
	}
}
func TestMessageAttributeMD5(t *testing.T) {
	h, c := testHandler(t)
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "checksums"})["QueueUrl"].(string)
	for _, tc := range []struct {
		attrs map[string]attribute
		sum   string
	}{
		{map[string]attribute{"SOME_Valid.attribute-Name": {DataType: "Number", StringValue: "1493147359900"}}, "36655e7e9d7c0e8479fa3f3f42247ae7"},
		{map[string]attribute{"timestamp": {DataType: "Number.java.lang.Long", StringValue: "1493147359900"}}, "2e2e4876d8e0bd6b8c2c8f556831c349"},
	} {
		out := invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "derp", MessageAttributes: tc.attrs})
		if out["MD5OfMessageAttributes"] != tc.sum || out["MD5OfMessageBody"] != "58fd9edd83341c29f1aebba81c31e257" {
			t.Fatal(out)
		}
	}
	for _, name := range []string{"AWS.secret", "Amazon.name", ".start", "end.", "two..dots", "non ascii λ"} {
		if _, err := h.dispatch(c, "SendMessage", &request{QueueUrl: u, MessageBody: "ok", MessageAttributes: map[string]attribute{name: {DataType: "String", StringValue: "v"}}}); err == nil {
			t.Fatal("accepted", name)
		}
	}
	for _, body := range []string{"", "bad\x00", strings.Repeat("x", 1048577)} {
		if _, err := h.dispatch(c, "SendMessage", &request{QueueUrl: u, MessageBody: body}); err == nil {
			t.Fatal("invalid body accepted")
		}
	}
}
func TestLongPollWakeAndCancellation(t *testing.T) {
	h, c := testHandler(t)
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "poll"})["QueueUrl"].(string)
	done := make(chan error, 1)
	go func() {
		out, err := h.dispatch(c, "ReceiveMessage", &request{QueueUrl: u, WaitTimeSeconds: ptr(20)})
		if err == nil && len(messageList(out)) != 1 {
			err = errNoMessage{}
		}
		done <- err
	}()
	// A send before registration must also be observed by the next receive scan.
	invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "wake"})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll did not wake")
	}
	ctx, cancel := context.WithCancel(c.ctx)
	other := *c
	other.ctx = ctx
	cancel()
	if _, err := h.dispatch(&other, "ReceiveMessage", &request{QueueUrl: u, WaitTimeSeconds: ptr(20)}); err == nil {
		t.Fatal("cancel ignored")
	}
}

type errNoMessage struct{}

func (errNoMessage) Error() string { return "no message" }
func TestBatchPartialFailure(t *testing.T) {
	h, c := testHandler(t)
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "batch"})["QueueUrl"].(string)
	out := invoke(t, h, c, "SendMessageBatch", request{QueueUrl: u, Entries: []request{{Id: "good", MessageBody: "yes"}, {Id: "bad", MessageBody: "no", DelaySeconds: ptr(901)}}})
	b, _ := json.Marshal(out)
	var parsed struct{ Successful, Failed []struct{ Id string } }
	_ = json.Unmarshal(b, &parsed)
	if len(parsed.Successful) != 1 || len(parsed.Failed) != 1 || parsed.Successful[0].Id != "good" {
		t.Fatal(out)
	}
}

func TestLongPollVisibilityDeadline(t *testing.T) {
	h, c := testHandler(t)
	u := invoke(t, h, c, "CreateQueue", request{QueueName: "deadline"})["QueueUrl"].(string)
	invoke(t, h, c, "SendMessage", request{QueueUrl: u, MessageBody: "later", DelaySeconds: ptr(1)})
	start := time.Now()
	messages := messageList(invoke(t, h, c, "ReceiveMessage", request{QueueUrl: u, WaitTimeSeconds: ptr(3)}))
	if len(messages) != 1 || time.Since(start) >= 2500*time.Millisecond {
		t.Fatal("delay deadline missed", messages, time.Since(start))
	}
}
func TestNumbersAndAttributeFilters(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"0001.2300", "1.23"}, {"-0.0", "0"}, {"1e3", "1000"}, {".00012", "0.00012"}, {"99999999999999999999999999999999999999", "99999999999999999999999999999999999999"}} {
		got, err := normalizeNumber(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%s => %s, %v", tc.input, got, err)
		}
	}
	for _, s := range []string{"NaN", "1e999999", "1e-129", "999999999999999999999999999999999999999"} {
		if _, err := normalizeNumber(s); err == nil {
			t.Fatal("accepted", s)
		}
	}
	for _, tc := range []struct {
		name, pattern string
		want          bool
	}{{"Custom1", "Custom.*", true}, {"Other", "Custom.*", false}, {"Anything", ".*", true}, {"one", "two", false}} {
		if got := requested(tc.name, []string{tc.pattern}); got != tc.want {
			t.Fatal(tc)
		}
	}
}
