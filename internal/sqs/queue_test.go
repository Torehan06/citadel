package sqs

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"citadel/internal/store"
)

func testHandler(t *testing.T) (*Handler, *call) {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir(), "test-region")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, nil, "test-region", nil), &call{ctx: context.Background(), account: "987654321098", region: "test-region", host: "localhost:8420", scheme: "http"}
}
func invoke(t *testing.T, h *Handler, c *call, op string, r request) map[string]any {
	t.Helper()
	out, err := h.dispatch(c, op, &r)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	return out
}
func TestQueueLifecycleAndIsolation(t *testing.T) {
	h, c := testHandler(t)
	out := invoke(t, h, c, "CreateQueue", request{QueueName: "jobs"})
	u := out["QueueUrl"].(string)
	if u != "http://localhost:8420/987654321098/jobs" {
		t.Fatal(u)
	}
	attrs := invoke(t, h, c, "GetQueueAttributes", request{QueueUrl: u, AttributeNames: []string{"All"}})["Attributes"].(map[string]string)
	if attrs["MaximumMessageSize"] != "1048576" || attrs["VisibilityTimeout"] != "30" {
		t.Fatal(attrs)
	}
	if _, err := h.dispatch(c, "CreateQueue", &request{QueueName: "jobs", Attributes: map[string]string{"VisibilityTimeout": "5"}}); err == nil {
		t.Fatal("conflicting create accepted")
	}
	other := *c
	other.account = "111111111111"
	if _, err := h.dispatch(&other, "GetQueueAttributes", &request{QueueUrl: u}); err == nil {
		t.Fatal("cross-account access accepted")
	}
	invoke(t, h, c, "DeleteQueue", request{QueueUrl: u})
	if _, err := h.dispatch(c, "GetQueueUrl", &request{QueueName: "jobs"}); err == nil {
		t.Fatal("deleted queue exists")
	}
}
func TestQueueAttributeValidation(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"retention low", "MessageRetentionPeriod", "59"}, {"retention high", "MessageRetentionPeriod", "1209601"},
		{"wait high", "ReceiveMessageWaitTimeSeconds", "21"}, {"delay negative", "DelaySeconds", "-1"},
		{"size high", "MaximumMessageSize", "1048577"}, {"visibility high", "VisibilityTimeout", "43201"},
		{"boolean", "FifoQueue", "tru"}, {"unknown", "Bogus", "value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, c := testHandler(t)
			_, err := h.dispatch(c, "CreateQueue", &request{QueueName: "jobs", Attributes: map[string]string{tc.key: tc.value}})
			if err == nil {
				t.Fatal("invalid attribute accepted")
			}
		})
	}
}
func TestQueryDecodeMapsAndBatch(t *testing.T) {
	values := url.Values{"Action": {"SendMessageBatch"}, "QueueUrl": {"http://localhost/a/jobs"}, "SendMessageBatchRequestEntry.1.Id": {"first"}, "SendMessageBatchRequestEntry.1.MessageBody": {"hello & goodbye"}, "SendMessageBatchRequestEntry.1.MessageAttribute.1.Name": {"kind"}, "SendMessageBatchRequestEntry.1.MessageAttribute.1.Value.DataType": {"String"}, "SendMessageBatchRequestEntry.1.MessageAttribute.1.Value.StringValue": {"event"}}
	op, r, err := decodeQuery(values)
	if err != nil {
		t.Fatal(err)
	}
	if op != "SendMessageBatch" || len(r.Entries) != 1 || r.Entries[0].MessageBody != "hello & goodbye" || r.Entries[0].MessageAttributes["kind"].StringValue != "event" {
		b, _ := json.Marshal(r)
		t.Fatal(string(b))
	}
}

func TestQueryWireShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeQuery(w, "ReceiveMessage", map[string]any{"Messages": []map[string]any{{"Body": "a<&\r\nb", "MessageAttributes": map[string]attribute{"kind": {DataType: "Binary", BinaryValue: []byte{0, 1, 2}}}}}})
	var result struct {
		Result struct {
			Messages []struct {
				Body  string
				Attrs []struct {
					Name  string
					Value struct{ DataType, BinaryValue string }
				} `xml:"MessageAttribute"`
			} `xml:"Message"`
		} `xml:"ReceiveMessageResult"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Messages) != 1 || result.Result.Messages[0].Body != "a<&\r\nb" || result.Result.Messages[0].Attrs[0].Value.BinaryValue != "AAEC" {
		t.Fatal(w.Body.String())
	}
	for _, query := range []bool{false, true} {
		w = httptest.NewRecorder()
		writeError(w, query, asError(missingQueue()))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
		if query {
			if !strings.Contains(w.Body.String(), "AWS.SimpleQueueService.NonExistentQueue") {
				t.Fatal(w.Body.String())
			}
		} else if w.Header().Get("x-amzn-query-error") != "AWS.SimpleQueueService.NonExistentQueue;Sender" {
			t.Fatal(w.Header())
		}
	}
}
