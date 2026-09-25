package ddb

import (
	"encoding/json"
	"sort"
	"strings"

	"citadel/internal/ddb/expr"
	"citadel/internal/store"
)

// Single-item operations: PutItem, GetItem, DeleteItem, UpdateItem.

func init() {
	register("PutItem", (*Handler).putItem)
	register("GetItem", (*Handler).getItemOp)
	register("DeleteItem", (*Handler).deleteItem)
	register("UpdateItem", (*Handler).updateItem)
}

// exprInput holds the expression-related parameters shared by operations.
type exprInput struct {
	ExpressionAttributeNames  map[string]string      `json:"ExpressionAttributeNames"`
	ExpressionAttributeValues map[string]*expr.Value `json:"ExpressionAttributeValues"`
	ConditionExpression       *string                `json:"ConditionExpression"`
	ProjectionExpression      *string                `json:"ProjectionExpression"`
	// Legacy (non-expression) parameters.
	Expected            map[string]expectedAttr `json:"Expected"`
	ConditionalOperator *string                 `json:"ConditionalOperator"`
	AttributesToGet     []string                `json:"AttributesToGet"`

	ReturnConsumedCapacity              string `json:"ReturnConsumedCapacity"`
	ReturnItemCollectionMetrics         string `json:"ReturnItemCollectionMetrics"`
	ReturnValuesOnConditionCheckFailure string `json:"ReturnValuesOnConditionCheckFailure"`

	names, values bool // present in the request (even if empty)
	params        *expr.Params
}

// prepare validates the placeholder maps and creates the parse context.
func (in *exprInput) prepare(raw []byte) error {
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(raw, &probe)
	_, in.names = probe["ExpressionAttributeNames"]
	_, in.values = probe["ExpressionAttributeValues"]
	if in.names && len(in.ExpressionAttributeNames) == 0 {
		return validation("ExpressionAttributeNames must not be empty")
	}
	if in.values && len(in.ExpressionAttributeValues) == 0 {
		return validation("ExpressionAttributeValues must not be empty")
	}
	for k := range in.ExpressionAttributeNames {
		if !strings.HasPrefix(k, "#") || len(k) < 2 {
			return validation("ExpressionAttributeNames contains invalid key: Syntax error; key: \"%s\"", k)
		}
	}
	for k, v := range in.ExpressionAttributeValues {
		if !strings.HasPrefix(k, ":") || len(k) < 2 {
			return validation("ExpressionAttributeValues contains invalid key: Syntax error; key: \"%s\"", k)
		}
		if v == nil {
			return validation("ExpressionAttributeValues contains invalid value: Supplied AttributeValue is empty, must contain exactly one of the supported datatypes for key %s", k)
		}
	}
	in.params = expr.NewParams(in.ExpressionAttributeNames, in.ExpressionAttributeValues)
	return nil
}

// mixCheck rejects mixing expression and legacy parameters.
func mixCheck(legacy, modern map[string]bool) error {
	var l, m []string
	for k, v := range legacy {
		if v {
			l = append(l, k)
		}
	}
	for k, v := range modern {
		if v {
			m = append(m, k)
		}
	}
	if len(l) > 0 && len(m) > 0 {
		sort.Strings(l)
		sort.Strings(m)
		return validation("Can not use both expression and non-expression parameters in the same request: Non-expression parameters: {%s} Expression parameters: {%s}",
			strings.Join(l, ", "), strings.Join(m, ", "))
	}
	return nil
}

// placeholdersNeedExpressions: names/values without any expression is invalid.
func (in *exprInput) placeholdersNeedExpressions(anyExpr bool, which string) error {
	if anyExpr {
		return nil
	}
	if in.values {
		return validation("ExpressionAttributeValues can only be specified when using expressions: %s", which)
	}
	if in.names {
		return validation("ExpressionAttributeNames can only be specified when using expressions")
	}
	return nil
}

// condition parses ConditionExpression or converts Expected.
func (in *exprInput) condition() (*expr.Cond, error) {
	if in.ConditionExpression != nil {
		return expr.ParseCondition(*in.ConditionExpression, "ConditionExpression", in.params)
	}
	if in.Expected != nil {
		return expectedToCond(in.Expected, in.ConditionalOperator)
	}
	if in.ConditionalOperator != nil {
		return nil, validation("ConditionalOperator can only be used when Expected or QueryFilter or ScanFilter are specified")
	}
	return nil, nil
}

// projection parses ProjectionExpression or AttributesToGet.
func (in *exprInput) projection() ([]expr.Path, error) {
	if in.ProjectionExpression != nil {
		return expr.ParseProjection(*in.ProjectionExpression, in.params)
	}
	if in.AttributesToGet != nil {
		if len(in.AttributesToGet) == 0 {
			return nil, validation("1 validation error detected: Value '[]' at 'attributesToGet' failed to satisfy constraint: Member must have length greater than or equal to 1")
		}
		seen := map[string]bool{}
		var out []expr.Path
		for _, a := range in.AttributesToGet {
			if err := expr.CheckAttrName(a); err != nil {
				return nil, err
			}
			if seen[a] {
				return nil, validation("One or more parameter values were invalid: Duplicate value in attribute name: %s", a)
			}
			seen[a] = true
			out = append(out, expr.Path{{Name: a}})
		}
		return out, nil
	}
	return nil, nil
}

func checkCondition(c *expr.Cond, it expr.Item, returnOld string) error {
	if c == nil {
		return nil
	}
	ok, err := c.Eval(it, "ConditionExpression")
	if err != nil {
		return err
	}
	if !ok {
		e := conditionFailed()
		if returnOld == "ALL_OLD" && it != nil {
			e.Extra = map[string]any{"Item": it}
		}
		return e
	}
	return nil
}

func validReturnValues(rv string, allowed ...string) error {
	if rv == "" {
		return nil
	}
	for _, a := range allowed {
		if rv == a {
			return nil
		}
	}
	return validation("1 validation error detected: Value '%s' at 'returnValues' failed to satisfy constraint: Member must satisfy enum value set: [ALL_NEW, UPDATED_OLD, ALL_OLD, NONE, UPDATED_NEW]", rv)
}

// ---- PutItem --------------------------------------------------------------------

type putItemInput struct {
	TableName    string    `json:"TableName"`
	Item         expr.Item `json:"Item"`
	ReturnValues string    `json:"ReturnValues"`
	exprInput
}

func (h *Handler) putItem(c *call) (any, error) {
	var in putItemInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if err := in.prepare(c.body); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if in.Item == nil {
		return nil, validation("1 validation error detected: Value null at 'item' failed to satisfy constraint: Member must not be null")
	}
	if err := validReturnValues(in.ReturnValues, "NONE", "ALL_OLD"); err != nil {
		return nil, err
	}
	if in.ReturnValues != "" && in.ReturnValues != "NONE" && in.ReturnValues != "ALL_OLD" {
		return nil, validation("ReturnValues can only be ALL_OLD or NONE")
	}
	if err := mixCheck(map[string]bool{"Expected": in.Expected != nil}, map[string]bool{"ConditionExpression": in.ConditionExpression != nil}); err != nil {
		return nil, err
	}
	if err := in.placeholdersNeedExpressions(in.ConditionExpression != nil, "ConditionExpression"); err != nil {
		return nil, err
	}
	cond, err := in.condition()
	if err != nil {
		return nil, err
	}
	if err := in.params.CheckUnused(); err != nil {
		return nil, err
	}
	k, err := t.keyFromItem(in.Item)
	if err != nil {
		return nil, err
	}
	if err := validateItem(in.Item); err != nil {
		return nil, err
	}
	if err := t.validateIndexKeys(in.Item); err != nil {
		return nil, err
	}
	var old expr.Item
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if old, err = getItem(c.ctx, tx, t, k); err != nil {
			return err
		}
		if err := checkCondition(cond, old, in.ReturnValuesOnConditionCheckFailure); err != nil {
			return err
		}
		if err := writeItem(c.ctx, tx, t, k, old, in.Item); err != nil {
			return err
		}
		return tx.Change("dynamodb", "PutItem", t.desc.TableName, nil)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if in.ReturnValues == "ALL_OLD" && old != nil {
		out["Attributes"] = old
	}
	h.addCapacity(out, in.ReturnConsumedCapacity, t, writeUnits(in.Item, old), nil)
	return out, nil
}

// ---- GetItem --------------------------------------------------------------------

type getItemInput struct {
	TableName      string    `json:"TableName"`
	Key            expr.Item `json:"Key"`
	ConsistentRead bool      `json:"ConsistentRead"`
	exprInput
}

func (h *Handler) getItemOp(c *call) (any, error) {
	var in getItemInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if err := in.prepare(c.body); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if in.Key == nil {
		return nil, validation("1 validation error detected: Value null at 'key' failed to satisfy constraint: Member must not be null")
	}
	if err := mixCheck(map[string]bool{"AttributesToGet": in.AttributesToGet != nil}, map[string]bool{"ProjectionExpression": in.ProjectionExpression != nil}); err != nil {
		return nil, err
	}
	if in.values {
		return nil, validation("ExpressionAttributeValues can only be specified when using expressions: FilterExpression, KeyConditionExpression and ConditionExpression are null")
	}
	if err := in.placeholdersNeedExpressions(in.ProjectionExpression != nil, "ProjectionExpression"); err != nil {
		return nil, err
	}
	proj, err := in.projection()
	if err != nil {
		return nil, err
	}
	if err := in.params.CheckUnused(); err != nil {
		return nil, err
	}
	k, err := t.keyFromKey(in.Key)
	if err != nil {
		return nil, err
	}
	it, err := getItem(c.ctx, h.st.DB(), t, k)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if it != nil {
		if proj != nil {
			it = expr.Project(it, proj)
		}
		out["Item"] = it
	}
	h.addCapacity(out, in.ReturnConsumedCapacity, t, readUnits(it, in.ConsistentRead), nil)
	return out, nil
}

// ---- DeleteItem -------------------------------------------------------------------

type deleteItemInput struct {
	TableName    string    `json:"TableName"`
	Key          expr.Item `json:"Key"`
	ReturnValues string    `json:"ReturnValues"`
	exprInput
}

func (h *Handler) deleteItem(c *call) (any, error) {
	var in deleteItemInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if err := in.prepare(c.body); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if in.Key == nil {
		return nil, validation("1 validation error detected: Value null at 'key' failed to satisfy constraint: Member must not be null")
	}
	if err := validReturnValues(in.ReturnValues, "NONE", "ALL_OLD"); err != nil {
		return nil, err
	}
	if in.ReturnValues != "" && in.ReturnValues != "NONE" && in.ReturnValues != "ALL_OLD" {
		return nil, validation("ReturnValues can only be ALL_OLD or NONE")
	}
	if err := mixCheck(map[string]bool{"Expected": in.Expected != nil}, map[string]bool{"ConditionExpression": in.ConditionExpression != nil}); err != nil {
		return nil, err
	}
	if err := in.placeholdersNeedExpressions(in.ConditionExpression != nil, "ConditionExpression"); err != nil {
		return nil, err
	}
	cond, err := in.condition()
	if err != nil {
		return nil, err
	}
	if err := in.params.CheckUnused(); err != nil {
		return nil, err
	}
	k, err := t.keyFromKey(in.Key)
	if err != nil {
		return nil, err
	}
	var old expr.Item
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if old, err = getItem(c.ctx, tx, t, k); err != nil {
			return err
		}
		if err := checkCondition(cond, old, in.ReturnValuesOnConditionCheckFailure); err != nil {
			return err
		}
		if old == nil {
			return nil
		}
		if err := writeItem(c.ctx, tx, t, k, old, nil); err != nil {
			return err
		}
		return tx.Change("dynamodb", "DeleteItem", t.desc.TableName, nil)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if in.ReturnValues == "ALL_OLD" && old != nil {
		out["Attributes"] = old
	}
	h.addCapacity(out, in.ReturnConsumedCapacity, t, writeUnits(nil, old), nil)
	return out, nil
}

// ---- UpdateItem --------------------------------------------------------------------

type updateItemInput struct {
	TableName        string                     `json:"TableName"`
	Key              expr.Item                  `json:"Key"`
	ReturnValues     string                     `json:"ReturnValues"`
	UpdateExpression *string                    `json:"UpdateExpression"`
	AttributeUpdates map[string]attributeUpdate `json:"AttributeUpdates"`
	exprInput
}

func (h *Handler) updateItem(c *call) (any, error) {
	var in updateItemInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if err := in.prepare(c.body); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if in.Key == nil {
		return nil, validation("1 validation error detected: Value null at 'key' failed to satisfy constraint: Member must not be null")
	}
	if err := validReturnValues(in.ReturnValues, "NONE", "ALL_OLD", "UPDATED_OLD", "ALL_NEW", "UPDATED_NEW"); err != nil {
		return nil, err
	}
	if err := mixCheck(
		map[string]bool{"Expected": in.Expected != nil, "AttributeUpdates": in.AttributeUpdates != nil},
		map[string]bool{"ConditionExpression": in.ConditionExpression != nil, "UpdateExpression": in.UpdateExpression != nil}); err != nil {
		return nil, err
	}
	if err := in.placeholdersNeedExpressions(in.ConditionExpression != nil || in.UpdateExpression != nil, "UpdateExpression and ConditionExpression are null"); err != nil {
		return nil, err
	}
	var upd *expr.Update
	if in.UpdateExpression != nil {
		if upd, err = expr.ParseUpdate(*in.UpdateExpression, in.params); err != nil {
			return nil, err
		}
	}
	cond, err := in.condition()
	if err != nil {
		return nil, err
	}
	if err := in.params.CheckUnused(); err != nil {
		return nil, err
	}
	k, err := t.keyFromKey(in.Key)
	if err != nil {
		return nil, err
	}
	// Key attributes can't be changed.
	touched := map[string]bool{}
	if upd != nil {
		for _, a := range upd.Actions {
			touched[a.Path[0].Name] = true
		}
	}
	for name := range in.AttributeUpdates {
		touched[name] = true
	}
	for _, key := range []string{t.hashKey(), t.rangeKey()} {
		if key != "" && touched[key] {
			return nil, validation("One or more parameter values were invalid: Cannot update attribute %s. This attribute is part of the key", key)
		}
	}

	var old, new expr.Item
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if old, err = getItem(c.ctx, tx, t, k); err != nil {
			return err
		}
		if err := checkCondition(cond, old, in.ReturnValuesOnConditionCheckFailure); err != nil {
			return err
		}
		base := old
		if base == nil {
			base = in.Key.Clone()
		}
		switch {
		case upd != nil:
			new, err = upd.Apply(base)
		case in.AttributeUpdates != nil:
			new, err = applyAttributeUpdates(base, in.AttributeUpdates)
		default:
			new = base.Clone()
		}
		if err != nil {
			return err
		}
		if err := validateItem(new); err != nil {
			return err
		}
		if err := t.validateIndexKeys(new); err != nil {
			return err
		}
		if old == nil && len(new) == len(in.Key) && onlyRemovals(upd, in.AttributeUpdates) {
			new = nil // removing attributes from a missing item doesn't create it
			return nil
		}
		if err := writeItem(c.ctx, tx, t, k, old, new); err != nil {
			return err
		}
		return tx.Change("dynamodb", "UpdateItem", t.desc.TableName, nil)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	var attrs expr.Item
	switch in.ReturnValues {
	case "ALL_OLD":
		attrs = old
	case "ALL_NEW":
		attrs = new
	case "UPDATED_OLD", "UPDATED_NEW":
		src := old
		if in.ReturnValues == "UPDATED_NEW" {
			src = new
		}
		if src != nil {
			attrs = expr.Project(src, updatedPaths(upd, in.AttributeUpdates))
		}
	}
	if len(attrs) > 0 {
		out["Attributes"] = attrs
	}
	h.addCapacity(out, in.ReturnConsumedCapacity, t, writeUnits(new, old), nil)
	return out, nil
}

func onlyRemovals(u *expr.Update, au map[string]attributeUpdate) bool {
	if u != nil {
		for _, a := range u.Actions {
			if a.Kind != "REMOVE" && a.Kind != "DELETE" {
				return false
			}
		}
		return len(u.Actions) > 0
	}
	if len(au) == 0 {
		return false
	}
	for _, a := range au {
		if a.Action != "DELETE" {
			return false
		}
	}
	return true
}

func updatedPaths(u *expr.Update, au map[string]attributeUpdate) []expr.Path {
	if u != nil {
		return u.Paths()
	}
	var out []expr.Path
	for name := range au {
		out = append(out, expr.Path{{Name: name}})
	}
	return out
}
