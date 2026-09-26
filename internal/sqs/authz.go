package sqs

import (
	"strings"

	"citadel/internal/iam"
	"citadel/internal/store"
)

// authorize checks the caller's identity policies for an SQS call on the
// queue it names (or "*" for ListQueues and CreateQueue without a name).
func (h *Handler) authorize(c *call, who *store.Principal, op string, r *request) error {
	if h.IAM == nil || iam.IsRoot(who) {
		return nil
	}
	name := r.QueueName
	if r.QueueUrl != "" {
		name = r.QueueUrl[strings.LastIndexByte(r.QueueUrl, '/')+1:]
	}
	resource := "*"
	if name != "" {
		resource = "arn:aws:sqs:" + c.region + ":" + c.account + ":" + name
	}
	d, err := h.IAM.Require(c.ctx, who, "sqs:"+op, []string{resource}, nil)
	if err != nil {
		return err
	}
	if d != nil {
		return &serviceError{403, "AccessDenied", iam.DeniedMessage(who, d.Action, d.Resource, d.Explicit)}
	}
	return nil
}
