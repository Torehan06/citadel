package ddb

import (
	"math"
	"sort"

	"citadel/internal/ddb/expr"
)

// Legacy (pre-expression) parameters: Expected, QueryFilter/ScanFilter and
// KeyConditions are translated into the expression AST and evaluated by the
// same code; AttributeUpdates is applied directly.
// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.html

type expectedAttr struct {
	Value              *expr.Value   `json:"Value"`
	Exists             *bool         `json:"Exists"`
	ComparisonOperator string        `json:"ComparisonOperator"`
	AttributeValueList []*expr.Value `json:"AttributeValueList"`
}

func scalarKind(k expr.Kind) bool { return k == expr.S || k == expr.N || k == expr.B }

// comparisonCond builds the condition for one legacy comparison.
func comparisonCond(name, op string, args []*expr.Value) (*expr.Cond, error) {
	path := &expr.Operand{Path: expr.Path{{Name: name}}}
	lit := func(v *expr.Value) *expr.Operand { return &expr.Operand{Value: v} }
	nargs := map[string]int{"EQ": 1, "NE": 1, "LE": 1, "LT": 1, "GE": 1, "GT": 1, "CONTAINS": 1, "NOT_CONTAINS": 1,
		"BEGINS_WITH": 1, "NULL": 0, "NOT_NULL": 0, "BETWEEN": 2, "IN": -1}
	want, ok := nargs[op]
	if !ok {
		return nil, validation("1 validation error detected: Value '%s' at 'comparisonOperator' failed to satisfy constraint: Member must satisfy enum value set: [IN, NULL, BETWEEN, LT, NOT_CONTAINS, EQ, GT, NOT_NULL, NE, LE, BEGINS_WITH, GE, CONTAINS]", op)
	}
	if want >= 0 && len(args) != want || want < 0 && len(args) == 0 {
		return nil, validation("One or more parameter values were invalid: Invalid number of argument(s) for the %s ComparisonOperator", op)
	}
	for _, a := range args {
		if a == nil {
			return nil, validation("One or more parameter values were invalid: Invalid number of argument(s) for the %s ComparisonOperator", op)
		}
		switch op {
		case "LE", "LT", "GE", "GT", "BETWEEN", "IN", "CONTAINS", "NOT_CONTAINS":
			if !scalarKind(a.Kind) {
				return nil, validation("One or more parameter values were invalid: ComparisonOperator %s is not valid for %s AttributeValue type", op, a.Kind)
			}
		case "BEGINS_WITH":
			if a.Kind != expr.S && a.Kind != expr.B {
				return nil, validation("One or more parameter values were invalid: ComparisonOperator %s is not valid for %s AttributeValue type", op, a.Kind)
			}
		}
	}
	cmp := map[string]string{"EQ": "=", "NE": "<>", "LE": "<=", "LT": "<", "GE": ">=", "GT": ">"}
	switch op {
	case "EQ", "NE", "LE", "LT", "GE", "GT":
		return &expr.Cond{Op: cmp[op], Args: []*expr.Operand{path, lit(args[0])}}, nil
	case "NULL":
		return &expr.Cond{Op: "attribute_not_exists", Args: []*expr.Operand{path}}, nil
	case "NOT_NULL":
		return &expr.Cond{Op: "attribute_exists", Args: []*expr.Operand{path}}, nil
	case "CONTAINS":
		return &expr.Cond{Op: "contains", Args: []*expr.Operand{path, lit(args[0])}}, nil
	case "NOT_CONTAINS":
		return &expr.Cond{Op: "AND",
			Left:  &expr.Cond{Op: "attribute_exists", Args: []*expr.Operand{path}},
			Right: &expr.Cond{Op: "NOT", Left: &expr.Cond{Op: "contains", Args: []*expr.Operand{path, lit(args[0])}}}}, nil
	case "BEGINS_WITH":
		return &expr.Cond{Op: "begins_with", Args: []*expr.Operand{path, lit(args[0])}}, nil
	case "BETWEEN":
		if args[0].Kind != args[1].Kind {
			return nil, validation("One or more parameter values were invalid: AttributeValues inside AttributeValueList must be of same type")
		}
		if c, ok := expr.Compare(args[0], args[1]); ok && c > 0 {
			return nil, validation("The BETWEEN condition was provided a range where the lower bound is greater than the upper bound")
		}
		return &expr.Cond{Op: "BETWEEN", Args: []*expr.Operand{path, lit(args[0]), lit(args[1])}}, nil
	case "IN":
		ops := []*expr.Operand{path}
		for _, a := range args {
			if a.Kind != args[0].Kind {
				return nil, validation("One or more parameter values were invalid: AttributeValues inside AttributeValueList must be of same type")
			}
			ops = append(ops, lit(a))
		}
		return &expr.Cond{Op: "IN", Args: ops}, nil
	}
	return nil, validation("unsupported ComparisonOperator %s", op)
}

// expectedToCond converts Expected (+ ConditionalOperator) to a condition.
func expectedToCond(exp map[string]expectedAttr, condOp *string) (*expr.Cond, error) {
	op := "AND"
	if condOp != nil {
		op = *condOp
		if op != "AND" && op != "OR" {
			return nil, validation("1 validation error detected: Value '%s' at 'conditionalOperator' failed to satisfy constraint: Member must satisfy enum value set: [OR, AND]", op)
		}
	}
	var out *expr.Cond
	for _, name := range sortedNames(exp) {
		e := exp[name]
		var c *expr.Cond
		var err error
		switch {
		case e.ComparisonOperator != "":
			if e.Exists != nil {
				return nil, validation("One or more parameter values were invalid: Exists and ComparisonOperator cannot be used together for Attribute: %s", name)
			}
			if e.Value != nil && e.AttributeValueList != nil {
				return nil, validation("One or more parameter values were invalid: Value and AttributeValueList cannot be used together for Attribute: %s", name)
			}
			args := e.AttributeValueList
			if e.Value != nil {
				args = []*expr.Value{e.Value}
			}
			c, err = comparisonCond(name, e.ComparisonOperator, args)
		case e.AttributeValueList != nil:
			return nil, validation("One or more parameter values were invalid: AttributeValueList can only be used with a ComparisonOperator for Attribute: %s", name)
		case e.Exists != nil && !*e.Exists:
			if e.Value != nil {
				return nil, validation("One or more parameter values were invalid: Value cannot be used when Exists is false for Attribute: %s", name)
			}
			c = &expr.Cond{Op: "attribute_not_exists", Args: []*expr.Operand{{Path: expr.Path{{Name: name}}}}}
		default:
			if e.Value == nil {
				return nil, validation("One or more parameter values were invalid: Value must be provided when Exists is true for Attribute: %s", name)
			}
			c, err = comparisonCond(name, "EQ", []*expr.Value{e.Value})
		}
		if err != nil {
			return nil, err
		}
		if out == nil {
			out = c
		} else {
			out = &expr.Cond{Op: op, Left: out, Right: c}
		}
	}
	return out, nil
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- AttributeUpdates ---------------------------------------------------------------

type attributeUpdate struct {
	Value  *expr.Value `json:"Value"`
	Action string      `json:"Action"`
}

func applyAttributeUpdates(base expr.Item, au map[string]attributeUpdate) (expr.Item, error) {
	out := base.Clone()
	for _, name := range sortedNames(au) {
		if err := expr.CheckAttrName(name); err != nil {
			return nil, err
		}
		u := au[name]
		action := u.Action
		if action == "" {
			action = "PUT"
		}
		cur := out[name]
		switch action {
		case "PUT":
			if u.Value == nil {
				return nil, validation("One or more parameter values were invalid: Only DELETE action is allowed when no attribute value is specified")
			}
			out[name] = u.Value
		case "DELETE":
			if u.Value == nil {
				delete(out, name)
				continue
			}
			switch u.Value.Kind {
			case expr.SS, expr.NS, expr.BS:
			default:
				return nil, validation("One or more parameter values were invalid: DELETE action with value is not supported for the type %s", u.Value.Kind)
			}
			if cur == nil {
				continue
			}
			if cur.Kind != u.Value.Kind {
				return nil, validation("Type mismatch for attribute to update")
			}
			upd, _ := expr.ParseUpdate("DELETE a :v", expr.NewParams(nil, map[string]*expr.Value{":v": u.Value}))
			tmp, err := upd.Apply(expr.Item{"a": cur})
			if err != nil {
				return nil, err
			}
			if v, ok := tmp["a"]; ok {
				out[name] = v
			} else {
				delete(out, name)
			}
		case "ADD":
			if u.Value == nil {
				return nil, validation("One or more parameter values were invalid: Only DELETE action is allowed when no attribute value is specified")
			}
			switch u.Value.Kind {
			case expr.N, expr.SS, expr.NS, expr.BS, expr.L:
			default:
				return nil, validation("One or more parameter values were invalid: ADD action is not supported for the type %s", u.Value.Kind)
			}
			if cur == nil {
				out[name] = u.Value
				continue
			}
			if cur.Kind != u.Value.Kind {
				return nil, validation("Type mismatch for attribute to update")
			}
			if cur.Kind == expr.L {
				out[name] = &expr.Value{Kind: expr.L, L: append(append([]*expr.Value{}, cur.L...), u.Value.L...)}
				continue
			}
			upd, _ := expr.ParseUpdate("ADD a :v", expr.NewParams(nil, map[string]*expr.Value{":v": u.Value}))
			tmp, err := upd.Apply(expr.Item{"a": cur})
			if err != nil {
				return nil, err
			}
			out[name] = tmp["a"]
		default:
			return nil, validation("1 validation error detected: Value '%s' at 'attributeUpdates.%s.member.action' failed to satisfy constraint: Member must satisfy enum value set: [ADD, PUT, DELETE]", action, name)
		}
	}
	return out, nil
}

// ---- consumed capacity -------------------------------------------------------------

func readUnits(it expr.Item, consistent bool) float64 {
	size := 0
	if it != nil {
		size = it.Size()
	}
	u := math.Max(1, math.Ceil(float64(size)/4096))
	if !consistent {
		u /= 2
	}
	return u
}

func writeUnits(new, old expr.Item) float64 {
	size := 0
	if new != nil {
		size = new.Size()
	}
	if old != nil && old.Size() > size {
		size = old.Size()
	}
	return math.Max(1, math.Ceil(float64(size)/1024))
}

// addCapacity adds ConsumedCapacity to a response when asked for.
func (h *Handler) addCapacity(out map[string]any, mode string, t *table, units float64, indexUnits map[string]float64) {
	switch mode {
	case "TOTAL":
		out["ConsumedCapacity"] = map[string]any{"TableName": t.desc.TableName, "CapacityUnits": units}
	case "INDEXES":
		cc := map[string]any{"TableName": t.desc.TableName, "CapacityUnits": units, "Table": map[string]any{"CapacityUnits": units}}
		if len(indexUnits) > 0 {
			g := map[string]any{}
			for name, u := range indexUnits {
				g[name] = map[string]any{"CapacityUnits": u}
			}
			cc["GlobalSecondaryIndexes"] = g
		}
		out["ConsumedCapacity"] = cc
	}
}
