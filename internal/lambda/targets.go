package lambda

import (
	"context"
	"errors"
	"strings"

	"citadel/internal/sqs"
)

// Targets is how other services in the region hand events to SQS queues and
// Lambda functions (S3 event notifications use it). It checks and delivers
// as the AWS service principal would: existence, then a send or an
// asynchronous invocation.
type Targets struct{ h *Handler }

// NotificationTargets returns the delivery side for S3 event notifications.
func (h *Handler) NotificationTargets() *Targets { return &Targets{h} }

func (t *Targets) QueueExists(ctx context.Context, arn string) bool {
	account, region, url, ok := sqs.QueueURL(arn)
	if !ok || t.h.SQS == nil {
		return false
	}
	_, err := t.h.SQS.Call(ctx, account, region, "GetQueueAttributes", map[string]any{"QueueUrl": url, "AttributeNames": []string{"QueueArn"}})
	return err == nil
}

func (t *Targets) FunctionExists(ctx context.Context, arn string) bool {
	ref, err := parseFunctionARN(arn)
	if err != nil {
		return false
	}
	_, _, err = resolve(ctx, t.h.st.DB(), ref)
	return err == nil
}

func (t *Targets) SendToQueue(ctx context.Context, arn, body string) error {
	account, region, url, ok := sqs.QueueURL(arn)
	if !ok || t.h.SQS == nil {
		return errors.New("not an SQS queue ARN: " + arn)
	}
	_, err := t.h.SQS.Call(ctx, account, region, "SendMessage", map[string]any{"QueueUrl": url, "MessageBody": body})
	return err
}

func (t *Targets) InvokeAsync(ctx context.Context, arn string, payload []byte) error {
	if !strings.Contains(arn, ":function:") {
		return errors.New("not a function ARN: " + arn)
	}
	ref, err := parseFunctionARN(arn)
	if err != nil {
		return err
	}
	return t.h.enqueue(ctx, ref, payload, newUUID(), 0)
}
