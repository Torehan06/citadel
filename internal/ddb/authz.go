package ddb

import (
	"encoding/json"
	"sort"

	"citadel/internal/iam"
)

// authorize checks the caller's identity policies for a DynamoDB call. The
// resources are the tables the request names (every table of a batch or
// transaction), or "*" for account-wide operations such as ListTables.
func (h *Handler) authorize(c *call, name string) error {
	if h.IAM == nil || iam.IsRoot(&c.who) {
		return nil
	}
	var req struct {
		TableName     string
		ResourceArn   string
		RequestItems  map[string]json.RawMessage
		TransactItems []map[string]struct {
			TableName string
		}
	}
	_ = json.Unmarshal(c.body, &req) // malformed bodies fail later with the right error
	var resources []string
	add := func(table string) {
		if table != "" {
			resources = append(resources, h.arn(c.account, table))
		}
	}
	add(req.TableName)
	if req.ResourceArn != "" {
		resources = append(resources, req.ResourceArn)
	}
	tables := make([]string, 0, len(req.RequestItems))
	for t := range req.RequestItems {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		add(t)
	}
	for _, item := range req.TransactItems {
		for _, x := range item {
			add(x.TableName)
		}
	}
	d, err := h.IAM.Require(c.ctx, &c.who, "dynamodb:"+name, resources, nil)
	if err != nil {
		return err
	}
	if d != nil {
		return errf(400, "AccessDeniedException", "%s", iam.DeniedMessage(&c.who, d.Action, d.Resource, d.Explicit))
	}
	return nil
}
