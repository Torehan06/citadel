package sqs

import (
	"encoding/json"
	"fmt"
)

// grantable lists the actions AddPermission may share with other accounts;
// the rest (queue deletion, permissions, tags...) stay with the owner.
var grantable = map[string]bool{
	"*": true, "ChangeMessageVisibility": true, "DeleteMessage": true, "GetQueueAttributes": true,
	"GetQueueUrl": true, "ListDeadLetterSourceQueues": true, "PurgeQueue": true, "ReceiveMessage": true, "SendMessage": true,
}

// policy loads the queue's access policy, or a fresh default one.
func policy(q *queue) map[string]any {
	doc := map[string]any{}
	if raw := q.Attrs["Policy"]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &doc)
	}
	if doc["Version"] == nil {
		doc["Version"] = "2012-10-17"
	}
	if doc["Id"] == nil {
		doc["Id"] = q.arn() + "/SQSDefaultPolicy"
	}
	return doc
}
func statements(doc map[string]any) []any {
	switch s := doc["Statement"].(type) {
	case []any:
		return s
	case map[string]any:
		return []any{s}
	}
	return nil
}
func hasLabel(stmts []any, label string) int {
	for i, s := range stmts {
		if m, ok := s.(map[string]any); ok && m["Sid"] == label {
			return i
		}
	}
	return -1
}

// oneOrMany renders a policy element as AWS does: a string for one value.
func oneOrMany(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

// addPermission appends an Allow statement named Label to the queue policy.
func addPermission(q *queue, r *request) error {
	if r.Label == "" {
		return fail("MissingParameter", "The request must contain the parameter Label.")
	}
	if !queueNameRE.MatchString(r.Label) {
		return fail("InvalidParameterValue", "Value %s for parameter Label is invalid. Reason: Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length.", r.Label)
	}
	if len(r.Actions) == 0 {
		return fail("MissingParameter", "The request must contain the parameter Actions.")
	}
	if len(r.Actions) > 7 {
		return &serviceError{403, "OverLimit", fmt.Sprintf("%d Actions were found, maximum allowed is 7.", len(r.Actions))}
	}
	if len(r.AWSAccountIds) == 0 {
		return fail("InvalidParameterValue", "Value [] for parameter PrincipalId is invalid. Reason: Unable to verify.")
	}
	actions := make([]string, len(r.Actions))
	for i, a := range r.Actions {
		if !grantable[a] {
			return fail("InvalidParameterValue", "Value SQS:%s for parameter ActionName is invalid. Reason: Only the queue owner is allowed to invoke this action.", a)
		}
		actions[i] = "SQS:" + a
	}
	principals := make([]string, len(r.AWSAccountIds))
	for i, id := range r.AWSAccountIds {
		principals[i] = "arn:aws:iam::" + id + ":root"
	}
	doc := policy(q)
	stmts := statements(doc)
	if hasLabel(stmts, r.Label) >= 0 {
		return fail("InvalidParameterValue", "Value %s for parameter Label is invalid. Reason: Already exists.", r.Label)
	}
	doc["Statement"] = append(stmts, map[string]any{
		"Sid": r.Label, "Effect": "Allow", "Principal": map[string]any{"AWS": oneOrMany(principals)},
		"Action": oneOrMany(actions), "Resource": q.arn(),
	})
	q.Attrs["Policy"] = jsonText(doc)
	return nil
}

// removePermission drops the statement named Label from the queue policy.
func removePermission(q *queue, r *request) error {
	if r.Label == "" {
		return fail("MissingParameter", "The request must contain the parameter Label.")
	}
	doc := policy(q)
	stmts := statements(doc)
	i := hasLabel(stmts, r.Label)
	if i < 0 {
		return fail("InvalidParameterValue", "Value %s for parameter Label is invalid. Reason: can't find label on existing policy.", r.Label)
	}
	doc["Statement"] = append(stmts[:i:i], stmts[i+1:]...)
	q.Attrs["Policy"] = jsonText(doc)
	return nil
}
