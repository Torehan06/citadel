package ddb

import (
	"encoding/json"

	"citadel/internal/ddb/expr"
	"citadel/internal/store"
)

// BatchWriteItem and BatchGetItem. Citadel processes every request in one
// go, so UnprocessedItems/UnprocessedKeys are always empty.

func init() {
	register("BatchWriteItem", (*Handler).batchWriteItem)
	register("BatchGetItem", (*Handler).batchGetItem)
}

type writeRequest struct {
	PutRequest *struct {
		Item expr.Item `json:"Item"`
	} `json:"PutRequest"`
	DeleteRequest *struct {
		Key expr.Item `json:"Key"`
	} `json:"DeleteRequest"`
}

type batchWriteInput struct {
	RequestItems           map[string][]writeRequest `json:"RequestItems"`
	ReturnConsumedCapacity string                    `json:"ReturnConsumedCapacity"`
}

func (h *Handler) batchWriteItem(c *call) (any, error) {
	var in batchWriteInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if len(in.RequestItems) == 0 {
		return nil, validation("1 validation error detected: Value null at 'requestItems' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	total := 0
	for name, reqs := range in.RequestItems {
		if len(reqs) == 0 {
			return nil, validation("1 validation error detected: Value '{%s=[]}' at 'requestItems' failed to satisfy constraint: Map value must satisfy constraint: [Member must have length less than or equal to 25, Member must have length greater than or equal to 1]", name)
		}
		total += len(reqs)
	}
	if total > 25 {
		return nil, validation("Too many items requested for the BatchWriteItem call")
	}

	type op struct {
		t   *table
		k   itemKey
		put expr.Item // nil: delete
	}
	var ops []op
	for _, name := range sortedNames(in.RequestItems) {
		t, err := h.loadTable(c, name)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, r := range in.RequestItems[name] {
			var o op
			o.t = t
			switch {
			case r.PutRequest != nil && r.DeleteRequest == nil:
				if r.PutRequest.Item == nil {
					return nil, validation("1 validation error detected: Value null at 'requestItems.%s.member.putRequest.item' failed to satisfy constraint: Member must not be null", name)
				}
				if o.k, err = t.keyFromItem(r.PutRequest.Item); err != nil {
					return nil, err
				}
				if err := validateItem(r.PutRequest.Item); err != nil {
					return nil, err
				}
				if err := t.validateIndexKeys(r.PutRequest.Item); err != nil {
					return nil, err
				}
				o.put = r.PutRequest.Item
			case r.DeleteRequest != nil && r.PutRequest == nil:
				if r.DeleteRequest.Key == nil {
					return nil, validation("1 validation error detected: Value null at 'requestItems.%s.member.deleteRequest.key' failed to satisfy constraint: Member must not be null", name)
				}
				if o.k, err = t.keyFromKey(r.DeleteRequest.Key); err != nil {
					return nil, err
				}
			default:
				return nil, validation("Supplied AttributeValue has more than one datatypes set, must contain exactly one of the supported datatypes")
			}
			id := string(o.k.baseKey())
			if seen[id] {
				return nil, validation("Provided list of item keys contains duplicates")
			}
			seen[id] = true
			ops = append(ops, o)
		}
	}
	units := map[string]float64{}
	tables := map[string]*table{}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		for _, o := range ops {
			old, err := getItem(c.ctx, tx, o.t, o.k)
			if err != nil {
				return err
			}
			if o.put == nil && old == nil {
				continue
			}
			if err := writeItem(c.ctx, tx, o.t, o.k, old, o.put); err != nil {
				return err
			}
			units[o.t.desc.TableName] += writeUnits(o.put, old)
			tables[o.t.desc.TableName] = o.t
		}
		return tx.Change("dynamodb", "BatchWriteItem", "", map[string]int{"ops": len(ops)})
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{"UnprocessedItems": map[string]any{}}
	if in.ReturnConsumedCapacity == "TOTAL" || in.ReturnConsumedCapacity == "INDEXES" {
		var cc []map[string]any
		for name, u := range units {
			m := map[string]any{}
			h.addCapacity(m, in.ReturnConsumedCapacity, tables[name], u, nil)
			cc = append(cc, m["ConsumedCapacity"].(map[string]any))
		}
		out["ConsumedCapacity"] = cc
	}
	return out, nil
}

type keysAndAttributes struct {
	Keys                     []expr.Item       `json:"Keys"`
	ProjectionExpression     *string           `json:"ProjectionExpression"`
	ExpressionAttributeNames map[string]string `json:"ExpressionAttributeNames"`
	AttributesToGet          []string          `json:"AttributesToGet"`
	ConsistentRead           bool              `json:"ConsistentRead"`
}

type batchGetInput struct {
	RequestItems           map[string]json.RawMessage `json:"RequestItems"`
	ReturnConsumedCapacity string                     `json:"ReturnConsumedCapacity"`
}

func (h *Handler) batchGetItem(c *call) (any, error) {
	var in batchGetInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if len(in.RequestItems) == 0 {
		return nil, validation("1 validation error detected: Value null at 'requestItems' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	type tableReq struct {
		t    *table
		keys []itemKey
		proj []expr.Path
		cons bool
	}
	var reqs []tableReq
	total := 0
	for _, name := range sortedNames(in.RequestItems) {
		var ka keysAndAttributes
		ei := exprInput{}
		if err := json.Unmarshal(in.RequestItems[name], &ka); err != nil {
			return nil, asError(err)
		}
		if err := json.Unmarshal(in.RequestItems[name], &ei); err != nil {
			return nil, asError(err)
		}
		if err := ei.prepare(in.RequestItems[name]); err != nil {
			return nil, err
		}
		t, err := h.loadTable(c, name)
		if err != nil {
			return nil, err
		}
		if len(ka.Keys) == 0 {
			return nil, validation("1 validation error detected: Value '[]' at 'requestItems.%s.member.keys' failed to satisfy constraint: Member must have length greater than or equal to 1", name)
		}
		if err := mixCheck(map[string]bool{"AttributesToGet": ka.AttributesToGet != nil}, map[string]bool{"ProjectionExpression": ka.ProjectionExpression != nil}); err != nil {
			return nil, err
		}
		if err := ei.placeholdersNeedExpressions(ka.ProjectionExpression != nil, "ProjectionExpression"); err != nil {
			return nil, err
		}
		proj, err := ei.projection()
		if err != nil {
			return nil, err
		}
		if err := ei.params.CheckUnused(); err != nil {
			return nil, err
		}
		tr := tableReq{t: t, proj: proj, cons: ka.ConsistentRead}
		seen := map[string]bool{}
		for _, key := range ka.Keys {
			k, err := t.keyFromKey(key)
			if err != nil {
				return nil, err
			}
			if seen[string(k.baseKey())] {
				return nil, validation("Provided list of item keys contains duplicates")
			}
			seen[string(k.baseKey())] = true
			tr.keys = append(tr.keys, k)
		}
		total += len(tr.keys)
		reqs = append(reqs, tr)
	}
	if total > 100 {
		return nil, validation("Too many items requested for the BatchGetItem call")
	}
	responses := map[string][]expr.Item{}
	var cc []map[string]any
	for _, tr := range reqs {
		items := []expr.Item{}
		units := 0.0
		for _, k := range tr.keys {
			it, err := getItem(c.ctx, h.st.DB(), tr.t, k)
			if err != nil {
				return nil, err
			}
			units += readUnits(it, tr.cons)
			if it == nil {
				continue
			}
			if tr.proj != nil {
				it = expr.Project(it, tr.proj)
			}
			items = append(items, it)
		}
		responses[tr.t.desc.TableName] = items
		if in.ReturnConsumedCapacity == "TOTAL" || in.ReturnConsumedCapacity == "INDEXES" {
			m := map[string]any{}
			h.addCapacity(m, in.ReturnConsumedCapacity, tr.t, units, nil)
			cc = append(cc, m["ConsumedCapacity"].(map[string]any))
		}
	}
	out := map[string]any{"Responses": responses, "UnprocessedKeys": map[string]any{}}
	if cc != nil {
		out["ConsumedCapacity"] = cc
	}
	return out, nil
}
