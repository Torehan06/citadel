package sqs

import (
	"context"
	"encoding/json"
	"strings"
)

// Call runs an SQS operation on behalf of another service in the region:
// Lambda's event source mappings and destinations, S3 event notifications.
// req and the result use the JSON protocol's shapes. It skips signature and
// identity-policy checks: the calling service has already authorized the
// work, as AWS's own service principals are trusted by the queue.
func (h *Handler) Call(ctx context.Context, account, region, op string, req any) (map[string]any, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var r request
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	c := &call{ctx: ctx, account: account, region: region, host: "sqs." + region + ".citadel.internal", scheme: "http", sender: account}
	return h.dispatch(c, op, &r)
}

// QueueURL turns a queue ARN (arn:aws:sqs:region:account:name) into the
// account, region and URL that Call expects.
func QueueURL(arn string) (account, region, url string, ok bool) {
	p := strings.Split(arn, ":")
	if len(p) != 6 || p[0] != "arn" || p[2] != "sqs" {
		return "", "", "", false
	}
	return p[4], p[3], "http://sqs." + p[3] + ".citadel.internal/" + p[4] + "/" + p[5], true
}

// ErrorCode reports the SQS error code of an error returned by Call.
func ErrorCode(err error) string {
	if e := asError(err); e != nil {
		return e.Code
	}
	return ""
}
