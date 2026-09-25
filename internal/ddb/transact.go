package ddb

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"citadel/internal/ddb/expr"
	"citadel/internal/store"
)

// TransactWriteItems and TransactGetItems.
// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
// A write transaction runs inside one SQLite write transaction: every
// condition is evaluated first, and if any fails nothing is written and the
// caller gets TransactionCanceledException with one reason per action.

func init() {
	register("TransactWriteItems", (*Handler).transactWrite)
	register("TransactGetItems", (*Handler).transactGet)
}

const maxTransactItems = 100

type transactAction struct {
	TableName        string    `json:"TableName"`
	Item             expr.Item `json:"Item"`
	Key              expr.Item `json:"Key"`
	UpdateExpression *string   `json:"UpdateExpression"`
	exprInput
}

type transactWriteInput struct {
	TransactItems          []map[string]json.RawMessage `json:"TransactItems"`
	ClientRequestToken     *string                      `json:"ClientRequestToken"`
	ReturnConsumedCapacity string                       `json:"ReturnConsumedCapacity"`
}

// prepared is one validated action, ready to run in the transaction.
type prepared struct {
	kind string // Put, Delete, Update, ConditionCheck
	t    *table
	k    itemKey
	cond *expr.Cond
	put  expr.Item
	upd  *expr.Update
	key  expr.Item
	rv   string // ReturnValuesOnConditionCheckFailure
}

// idempotency remembers ClientRequestTokens for 10 minutes, as DynamoDB does.
type idempotency struct {
	mu   sync.Mutex
	seen map[string]tokenEntry
}

type tokenEntry struct {
	hash [32]byte
	at   time.Time
}

var tokens = &idempotency{seen: map[string]tokenEntry{}}

// check returns (alreadyDone, error).
func (i *idempotency) check(account, token string, body []byte) (bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	for k, e := range i.seen {
		if now.Sub(e.at) > 10*time.Minute {
			delete(i.seen, k)
		}
	}
	h := sha256.Sum256(body)
	key := account + "/" + token
	if e, ok := i.seen[key]; ok {
		if e.hash != h {
			return false, errf(400, "IdempotentParameterMismatchException", "The request uses the same client token as a previous, but non-identical request.")
		}
		return true, nil
	}
	return false, nil
}

func (i *idempotency) remember(account, token string, body []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.seen[account+"/"+token] = tokenEntry{hash: sha256.Sum256(body), at: time.Now()}
}

func (h *Handler) prepareAction(c *call, kind string, raw json.RawMessage) (*prepared, error) {
	var a transactAction
	if err := json.Unmarshal(raw, &a); err != nil {
		var ve *expr.ValidationError
		if errors.As(err, &ve) {
			return nil, validation("%s", ve.Msg)
		}
		return nil, errf(400, "SerializationException", "%v", err)
	}
	if err := a.prepare(raw); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, a.TableName)
	if err != nil {
		return nil, err
	}
	p := &prepared{kind: kind, t: t, rv: a.ReturnValuesOnConditionCheckFailure}
	if a.ConditionExpression != nil {
		if p.cond, err = expr.ParseCondition(*a.ConditionExpression, "ConditionExpression", a.params); err != nil {
			return nil, err
		}
	}
	switch kind {
	case "Put":
		if a.Item == nil {
			return nil, validation("1 validation error detected: Value null at 'transactItems.member.put.item' failed to satisfy constraint: Member must not be null")
		}
		if p.k, err = t.keyFromItem(a.Item); err != nil {
			return nil, err
		}
		if err := validateItem(a.Item); err != nil {
			return nil, err
		}
		if err := t.validateIndexKeys(a.Item); err != nil {
			return nil, err
		}
		p.put = a.Item
	case "Delete", "ConditionCheck", "Update":
		if a.Key == nil {
			return nil, validation("1 validation error detected: Value null at 'transactItems.member.%s.key' failed to satisfy constraint: Member must not be null", strings.ToLower(kind))
		}
		if p.k, err = t.keyFromKey(a.Key); err != nil {
			return nil, err
		}
		p.key = a.Key
		if kind == "ConditionCheck" && p.cond == nil {
			return nil, validation("1 validation error detected: Value null at 'transactItems.member.conditionCheck.conditionExpression' failed to satisfy constraint: Member must not be null")
		}
		if kind == "Update" {
			if a.UpdateExpression == nil {
				return nil, validation("1 validation error detected: Value null at 'transactItems.member.update.updateExpression' failed to satisfy constraint: Member must not be null")
			}
			if p.upd, err = expr.ParseUpdate(*a.UpdateExpression, a.params); err != nil {
				return nil, err
			}
			for _, act := range p.upd.Actions {
				if n := act.Path[0].Name; n == t.hashKey() || n == t.rangeKey() {
					return nil, validation("One or more parameter values were invalid: Cannot update attribute %s. This attribute is part of the key", n)
				}
			}
		}
	}
	if a.ProjectionExpression != nil {
		return nil, validation("ProjectionExpression is not supported in TransactWriteItems")
	}
	if err := a.params.CheckUnused(); err != nil {
		return nil, err
	}
	return p, nil
}

func (h *Handler) transactWrite(c *call) (any, error) {
	var in transactWriteInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if len(in.TransactItems) == 0 {
		return nil, validation("1 validation error detected: Value '[]' at 'transactItems' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	if len(in.TransactItems) > maxTransactItems {
		return nil, validation("1 validation error detected: Value at 'transactItems' failed to satisfy constraint: Member must have length less than or equal to %d", maxTransactItems)
	}
	if tok := in.ClientRequestToken; tok != nil {
		if len(*tok) < 1 || len(*tok) > 36 {
			return nil, validation("1 validation error detected: Value '%s' at 'clientRequestToken' failed to satisfy constraint: Member must have length less than or equal to 36", *tok)
		}
		done, err := tokens.check(c.account, *tok, c.body)
		if err != nil {
			return nil, err
		}
		if done {
			return map[string]any{}, nil
		}
	}
	var acts []*prepared
	seen := map[string]bool{}
	total := 0
	for _, entry := range in.TransactItems {
		if len(entry) != 1 {
			return nil, validation("TransactItems can only contain one of Check, Put, Update or Delete")
		}
		for kind, raw := range entry {
			switch kind {
			case "Put", "Delete", "Update", "ConditionCheck":
			default:
				return nil, validation("TransactItems can only contain one of Check, Put, Update or Delete")
			}
			p, err := h.prepareAction(c, kind, raw)
			if err != nil {
				return nil, err
			}
			id := fmt.Sprintf("%d/%x", p.t.id, p.k.baseKey())
			if seen[id] {
				return nil, validation("Transaction request cannot include multiple operations on one item")
			}
			seen[id] = true
			if p.put != nil {
				total += p.put.Size()
			}
			acts = append(acts, p)
		}
	}
	if total > 4<<20 {
		return nil, validation("Transaction size exceeded the maximum allowed size of 4 MB")
	}

	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		olds := make([]expr.Item, len(acts))
		reasons := make([]map[string]any, len(acts))
		failed := false
		for i, p := range acts {
			old, err := getItem(c.ctx, tx, p.t, p.k)
			if err != nil {
				return err
			}
			olds[i] = old
			reasons[i] = map[string]any{"Code": "None"}
			if p.cond != nil {
				ok, err := p.cond.Eval(old, "ConditionExpression")
				if err != nil {
					return err
				}
				if !ok {
					failed = true
					reasons[i] = map[string]any{"Code": "ConditionalCheckFailed", "Message": "The conditional request failed"}
					if p.rv == "ALL_OLD" && old != nil {
						reasons[i]["Item"] = old
					}
				}
			}
		}
		// Compute updates, reporting item-level validation errors per action.
		news := make([]expr.Item, len(acts))
		for i, p := range acts {
			if failed {
				break
			}
			switch p.kind {
			case "Put":
				news[i] = p.put
			case "Update":
				base := olds[i]
				if base == nil {
					base = p.key.Clone()
				}
				n, err := p.upd.Apply(base)
				if err == nil {
					err = validateItem(n)
				}
				if err == nil {
					err = p.t.validateIndexKeys(n)
				}
				if err != nil {
					failed = true
					reasons[i] = map[string]any{"Code": "ValidationError", "Message": asError(err).Message}
					continue
				}
				news[i] = n
			}
		}
		if failed {
			codes := make([]string, len(reasons))
			for i, r := range reasons {
				codes[i] = r["Code"].(string)
			}
			return &Error{Status: 400, Code: "TransactionCanceledException",
				Message: "Transaction cancelled, please refer cancellation reasons for specific reasons [" + strings.Join(codes, ", ") + "]",
				Extra:   map[string]any{"CancellationReasons": reasons}}
		}
		for i, p := range acts {
			switch p.kind {
			case "Put", "Update":
				if err := writeItem(c.ctx, tx, p.t, p.k, olds[i], news[i]); err != nil {
					return err
				}
			case "Delete":
				if olds[i] != nil {
					if err := writeItem(c.ctx, tx, p.t, p.k, olds[i], nil); err != nil {
						return err
					}
				}
			}
		}
		return tx.Change("dynamodb", "TransactWriteItems", "", map[string]int{"actions": len(acts)})
	})
	if err != nil {
		return nil, err
	}
	if tok := in.ClientRequestToken; tok != nil {
		tokens.remember(c.account, *tok, c.body)
	}
	return map[string]any{}, nil
}

type transactGetInput struct {
	TransactItems []struct {
		Get json.RawMessage `json:"Get"`
	} `json:"TransactItems"`
	ReturnConsumedCapacity string `json:"ReturnConsumedCapacity"`
}

func (h *Handler) transactGet(c *call) (any, error) {
	var in transactGetInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if len(in.TransactItems) == 0 {
		return nil, validation("1 validation error detected: Value '[]' at 'transactItems' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	if len(in.TransactItems) > maxTransactItems {
		return nil, validation("1 validation error detected: Value at 'transactItems' failed to satisfy constraint: Member must have length less than or equal to %d", maxTransactItems)
	}
	type getReq struct {
		t    *table
		k    itemKey
		proj []expr.Path
	}
	var reqs []getReq
	for _, ti := range in.TransactItems {
		if ti.Get == nil {
			return nil, validation("1 validation error detected: Value null at 'transactItems.member.get' failed to satisfy constraint: Member must not be null")
		}
		var g struct {
			TableName string    `json:"TableName"`
			Key       expr.Item `json:"Key"`
			exprInput
		}
		if err := json.Unmarshal(ti.Get, &g); err != nil {
			return nil, asError(err)
		}
		if err := g.prepare(ti.Get); err != nil {
			return nil, err
		}
		t, err := h.loadTable(c, g.TableName)
		if err != nil {
			return nil, err
		}
		k, err := t.keyFromKey(g.Key)
		if err != nil {
			return nil, err
		}
		if err := g.placeholdersNeedExpressions(g.ProjectionExpression != nil, "ProjectionExpression"); err != nil {
			return nil, err
		}
		proj, err := g.projection()
		if err != nil {
			return nil, err
		}
		if err := g.params.CheckUnused(); err != nil {
			return nil, err
		}
		reqs = append(reqs, getReq{t, k, proj})
	}
	responses := make([]map[string]any, 0, len(reqs))
	for _, r := range reqs {
		it, err := getItem(c.ctx, h.st.DB(), r.t, r.k)
		if err != nil {
			return nil, err
		}
		resp := map[string]any{}
		if it != nil {
			if r.proj != nil {
				it = expr.Project(it, r.proj)
			}
			resp["Item"] = it
		}
		responses = append(responses, resp)
	}
	return map[string]any{"Responses": responses}, nil
}
