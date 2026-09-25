package ddb

import (
	"bytes"
	"encoding/json"
	"hash/fnv"

	"citadel/internal/ddb/expr"
)

// Query and Scan.
// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Query.html

func init() {
	register("Query", (*Handler).query)
	register("Scan", (*Handler).scan)
}

const maxPageBytes = 1 << 20 // DynamoDB stops a page after 1 MB of data read

type condAttr struct {
	AttributeValueList []*expr.Value `json:"AttributeValueList"`
	ComparisonOperator string        `json:"ComparisonOperator"`
}

type readInput struct {
	TableName              string              `json:"TableName"`
	IndexName              *string             `json:"IndexName"`
	KeyConditionExpression *string             `json:"KeyConditionExpression"`
	KeyConditions          map[string]condAttr `json:"KeyConditions"`
	FilterExpression       *string             `json:"FilterExpression"`
	QueryFilter            map[string]condAttr `json:"QueryFilter"`
	ScanFilter             map[string]condAttr `json:"ScanFilter"`
	Select                 string              `json:"Select"`
	Limit                  *int                `json:"Limit"`
	ExclusiveStartKey      expr.Item           `json:"ExclusiveStartKey"`
	ScanIndexForward       *bool               `json:"ScanIndexForward"`
	ConsistentRead         bool                `json:"ConsistentRead"`
	Segment                *int                `json:"Segment"`
	TotalSegments          *int                `json:"TotalSegments"`
	exprInput
}

// keyRange is a Query's key condition compiled to byte bounds.
type keyRange struct {
	pk           []byte
	lo, hi       []byte // nil: unbounded
	loInc, hiInc bool
}

// target is what a read goes against: the table itself or one index.
type target struct {
	t      *table
	idx    int
	ix     *index
	hash   string
	rng    string
	global bool
}

func (h *Handler) readTarget(t *table, in *readInput) (*target, error) {
	tg := &target{t: t, hash: t.hashKey(), rng: t.rangeKey()}
	if in.IndexName == nil {
		return tg, nil
	}
	ix, ok := t.findIndex(*in.IndexName)
	if !ok {
		return nil, validation("The table does not have the specified index: %s", *in.IndexName)
	}
	tg.ix, tg.idx, tg.global = &ix, ix.def.ID, ix.global
	tg.hash = ix.def.KeySchema[0].AttributeName
	tg.rng = ""
	if len(ix.def.KeySchema) > 1 {
		tg.rng = ix.def.KeySchema[1].AttributeName
	}
	if ix.global && in.ConsistentRead {
		return nil, validation("Consistent reads are not supported on global secondary indexes")
	}
	return tg, nil
}

// successor returns the smallest byte string greater than every string
// with prefix p (nil when none).
func successor(p []byte) []byte {
	b := append([]byte(nil), p...)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return b[:i+1]
		}
	}
	return nil
}

// compileKeyCondition turns the key condition into a byte range.
func compileKeyCondition(tg *target, conds []*expr.Cond) (*keyRange, error) {
	var hashCond, rangeCond *expr.Cond
	for _, c := range conds {
		var attr string
		for _, a := range c.Args {
			if a.Path != nil {
				if len(a.Path) != 1 || a.Path[0].IsIdx || a.Size {
					return nil, validation("Invalid KeyConditionExpression: Key conditions must use simple attribute names")
				}
				if attr != "" {
					return nil, validation("Invalid KeyConditionExpression: The operator or function requires a value operand")
				}
				attr = a.Path[0].Name
			}
		}
		switch c.Op {
		case "=", "<", "<=", ">", ">=", "BETWEEN", "begins_with":
		default:
			return nil, validation("Invalid KeyConditionExpression: Invalid operator used in KeyConditionExpression: %s", c.Op)
		}
		if attr == "" {
			return nil, validation("Invalid KeyConditionExpression: The expression does not contain a key attribute")
		}
		switch attr {
		case tg.hash:
			if hashCond != nil {
				return nil, validation("KeyConditionExpressions must only contain one condition per key")
			}
			if c.Op != "=" {
				return nil, validation("Query key condition not supported")
			}
			hashCond = c
		case tg.rng:
			if rangeCond != nil {
				return nil, validation("KeyConditionExpressions must only contain one condition per key")
			}
			rangeCond = c
		default:
			return nil, validation("Query condition missed key schema element: %s", attr)
		}
	}
	if hashCond == nil {
		return nil, validation("Query condition missed key schema element: %s", tg.hash)
	}
	value := func(c *expr.Cond, attr string) ([]*expr.Value, error) {
		var out []*expr.Value
		for _, a := range c.Args {
			if a.Value != nil {
				if string(a.Value.Kind) != tg.t.attrType(attr) {
					return nil, validation("One or more parameter values were invalid: Condition parameter type does not match schema type")
				}
				out = append(out, a.Value)
			}
		}
		return out, nil
	}
	hv, err := value(hashCond, tg.hash)
	if err != nil {
		return nil, err
	}
	r := &keyRange{pk: keyBytes(hv[0])}
	if rangeCond == nil {
		return r, nil
	}
	rv, err := value(rangeCond, tg.rng)
	if err != nil {
		return nil, err
	}
	// "value op key" flips the comparison.
	op := rangeCond.Op
	if rangeCond.Args[0].Value != nil && len(rangeCond.Args) == 2 && op != "begins_with" {
		op = map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<=", "=": "="}[op]
	}
	switch op {
	case "=":
		b := keyBytes(rv[0])
		r.lo, r.hi, r.loInc, r.hiInc = b, b, true, true
	case "<":
		r.hi = keyBytes(rv[0])
	case "<=":
		r.hi, r.hiInc = keyBytes(rv[0]), true
	case ">":
		r.lo = keyBytes(rv[0])
	case ">=":
		r.lo, r.loInc = keyBytes(rv[0]), true
	case "BETWEEN":
		if c, ok := expr.Compare(rv[0], rv[1]); ok && c > 0 {
			return nil, validation("Invalid KeyConditionExpression: The BETWEEN operator requires upper bound to be greater than or equal to lower bound; lower bound operand: AttributeValue: {%s}, upper bound operand: AttributeValue: {%s}", rv[0].Kind, rv[1].Kind)
		}
		r.lo, r.hi, r.loInc, r.hiInc = keyBytes(rv[0]), keyBytes(rv[1]), true, true
	case "begins_with":
		if rangeCond.Args[0].Path == nil {
			return nil, validation("Invalid KeyConditionExpression: Incorrect operand type for operator or function; operator or function: begins_with")
		}
		if rv[0].Kind == expr.N {
			return nil, validation("Invalid KeyConditionExpression: Incorrect operand type for operator or function; operator or function: begins_with, operand type: N")
		}
		p := keyBytes(rv[0])
		r.lo, r.loInc = p, true
		r.hi = successor(p)
	}
	return r, nil
}

// flattenAnd lists the conjuncts of a key condition (OR/NOT are invalid).
func flattenAnd(c *expr.Cond, out []*expr.Cond) ([]*expr.Cond, error) {
	switch c.Op {
	case "AND":
		var err error
		if out, err = flattenAnd(c.Left, out); err != nil {
			return nil, err
		}
		return flattenAnd(c.Right, out)
	case "OR", "NOT":
		return nil, validation("Invalid KeyConditionExpression: Invalid operator used in KeyConditionExpression: %s", c.Op)
	}
	return append(out, c), nil
}

func legacyFilter(m map[string]condAttr, op *string) (*expr.Cond, error) {
	exp := map[string]expectedAttr{}
	for name, ca := range m {
		exp[name] = expectedAttr{ComparisonOperator: ca.ComparisonOperator, AttributeValueList: ca.AttributeValueList}
		if ca.ComparisonOperator == "" {
			return nil, validation("1 validation error detected: Value null at 'comparisonOperator' failed to satisfy constraint: Member must not be null")
		}
	}
	return expectedToCond(exp, op)
}

// cursor is a position in (pk, sk, bk) order.
type cursor struct{ pk, sk, bk []byte }

func (h *Handler) startCursor(tg *target, esk expr.Item) (*cursor, error) {
	if esk == nil {
		return nil, nil
	}
	bad := validation("The provided starting key is invalid: The provided key element does not match the schema")
	tk, err := tg.t.keyFromItem(esk)
	if err != nil {
		return nil, bad
	}
	want := 1
	if tg.t.rangeKey() != "" {
		want++
	}
	if tg.ix == nil {
		if len(esk) != want {
			return nil, bad
		}
		return &cursor{pk: tk.pk, sk: nonNil(tk.sk), bk: []byte{}}, nil
	}
	ik, ok, err := tg.t.indexKey(*tg.ix, esk)
	if err != nil || !ok {
		return nil, bad
	}
	return &cursor{pk: ik.pk, sk: nonNil(ik.sk), bk: tk.baseKey()}, nil
}

type row struct {
	pk, sk, bk []byte
	item       expr.Item
	size       int
}

// fetch reads rows in order, starting after cur.
func (h *Handler) fetch(c *call, tg *target, kr *keyRange, cur *cursor, forward bool, batch int) ([]row, error) {
	q := `SELECT pk, sk, bk, item, size FROM ddb_items WHERE table_id = ? AND idx = ?`
	args := []any{tg.t.id, tg.idx}
	if kr != nil {
		q += ` AND pk = ?`
		args = append(args, kr.pk)
		if kr.lo != nil {
			if kr.loInc {
				q += ` AND sk >= ?`
			} else {
				q += ` AND sk > ?`
			}
			args = append(args, kr.lo)
		}
		if kr.hi != nil {
			if kr.hiInc {
				q += ` AND sk <= ?`
			} else {
				q += ` AND sk < ?`
			}
			args = append(args, kr.hi)
		}
		if cur != nil {
			if forward {
				q += ` AND (sk > ? OR (sk = ? AND bk > ?))`
			} else {
				q += ` AND (sk < ? OR (sk = ? AND bk < ?))`
			}
			args = append(args, cur.sk, cur.sk, cur.bk)
		}
		if forward {
			q += ` ORDER BY sk, bk`
		} else {
			q += ` ORDER BY sk DESC, bk DESC`
		}
	} else {
		if cur != nil {
			q += ` AND (pk > ? OR (pk = ? AND (sk > ? OR (sk = ? AND bk > ?))))`
			args = append(args, cur.pk, cur.pk, cur.sk, cur.sk, cur.bk)
		}
		q += ` ORDER BY pk, sk, bk`
	}
	q += ` LIMIT ?`
	args = append(args, batch)
	rows, err := h.st.DB().QueryContext(c.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var r row
		var raw []byte
		if err := rows.Scan(&r.pk, &r.sk, &r.bk, &raw, &r.size); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &r.item); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (h *Handler) query(c *call) (any, error) { return h.read(c, true) }
func (h *Handler) scan(c *call) (any, error)  { return h.read(c, false) }

func (h *Handler) read(c *call, isQuery bool) (any, error) {
	var in readInput
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
	tg, err := h.readTarget(t, &in)
	if err != nil {
		return nil, err
	}
	filterLegacy := in.ScanFilter
	filterName := "ScanFilter"
	if isQuery {
		filterLegacy, filterName = in.QueryFilter, "QueryFilter"
	}
	if in.KeyConditions != nil && in.KeyConditionExpression != nil {
		return nil, validation("Can not use both expression and non-expression parameters in the same request: Non-expression parameters: {KeyConditions} Expression parameters: {KeyConditionExpression}")
	}
	if err := mixCheck(
		// KeyConditions may be combined with FilterExpression (DynamoDB accepts it).
		map[string]bool{filterName: filterLegacy != nil, "AttributesToGet": in.AttributesToGet != nil},
		map[string]bool{"KeyConditionExpression": in.KeyConditionExpression != nil, "FilterExpression": in.FilterExpression != nil, "ProjectionExpression": in.ProjectionExpression != nil}); err != nil {
		return nil, err
	}
	anyExpr := in.KeyConditionExpression != nil || in.FilterExpression != nil || in.ProjectionExpression != nil
	if in.values && in.KeyConditionExpression == nil && in.FilterExpression == nil {
		return nil, validation("ExpressionAttributeValues can only be specified when using expressions: FilterExpression and KeyConditionExpression are null")
	}
	if err := in.placeholdersNeedExpressions(anyExpr, "FilterExpression and KeyConditionExpression are null"); err != nil {
		return nil, err
	}
	if in.Limit != nil && *in.Limit < 1 {
		return nil, validation("1 validation error detected: Value '%d' at 'limit' failed to satisfy constraint: Member must have value greater than or equal to 1", *in.Limit)
	}

	var kr *keyRange
	if isQuery {
		var conds []*expr.Cond
		switch {
		case in.KeyConditionExpression != nil:
			kc, err := expr.ParseCondition(*in.KeyConditionExpression, "KeyConditionExpression", in.params)
			if err != nil {
				return nil, err
			}
			if conds, err = flattenAnd(kc, nil); err != nil {
				return nil, err
			}
		case in.KeyConditions != nil:
			for _, name := range sortedNames(in.KeyConditions) {
				kc, err := comparisonCond(name, in.KeyConditions[name].ComparisonOperator, in.KeyConditions[name].AttributeValueList)
				if err != nil {
					return nil, err
				}
				if name == tg.hash && kc.Op != "=" {
					return nil, validation("Query key condition not supported")
				}
				conds = append(conds, kc)
			}
		default:
			return nil, validation("Either the KeyConditions or KeyConditionExpression parameter must be specified in the request.")
		}
		if kr, err = compileKeyCondition(tg, conds); err != nil {
			return nil, err
		}
	} else if in.KeyConditionExpression != nil || in.KeyConditions != nil {
		return nil, validation("KeyConditionExpression is not supported for Scan")
	}

	var filter *expr.Cond
	switch {
	case in.FilterExpression != nil:
		if filter, err = expr.ParseCondition(*in.FilterExpression, "FilterExpression", in.params); err != nil {
			return nil, err
		}
		if isQuery {
			if err := filterUsesKey(filter, tg); err != nil {
				return nil, err
			}
		}
	case filterLegacy != nil:
		if filter, err = legacyFilter(filterLegacy, in.ConditionalOperator); err != nil {
			return nil, err
		}
	case in.ConditionalOperator != nil:
		return nil, validation("ConditionalOperator can only be used when Expected or QueryFilter or ScanFilter are specified")
	}
	proj, err := in.projection()
	if err != nil {
		return nil, err
	}
	if err := in.params.CheckUnused(); err != nil {
		return nil, err
	}

	// Select.
	sel := in.Select
	switch sel {
	case "":
		if proj != nil {
			sel = "SPECIFIC_ATTRIBUTES"
		} else if tg.ix != nil {
			sel = "ALL_PROJECTED_ATTRIBUTES"
		} else {
			sel = "ALL_ATTRIBUTES"
		}
	case "ALL_ATTRIBUTES", "COUNT":
		if proj != nil {
			return nil, validation("Cannot specify the AttributesToGet when choosing to get %s", sel)
		}
	case "ALL_PROJECTED_ATTRIBUTES":
		if tg.ix == nil {
			return nil, validation("ALL_PROJECTED_ATTRIBUTES can be used only when Querying using an IndexName")
		}
		if proj != nil {
			return nil, validation("Cannot specify the AttributesToGet when choosing to get ALL_PROJECTED_ATTRIBUTES")
		}
	case "SPECIFIC_ATTRIBUTES":
		if proj == nil {
			return nil, validation("Must specify the AttributesToGet or ProjectionExpression when choosing to get SPECIFIC_ATTRIBUTES")
		}
	default:
		return nil, validation("1 validation error detected: Value '%s' at 'select' failed to satisfy constraint: Member must satisfy enum value set: [SPECIFIC_ATTRIBUTES, COUNT, ALL_ATTRIBUTES, ALL_PROJECTED_ATTRIBUTES]", sel)
	}
	needBase := false
	if tg.ix != nil && tg.ix.def.Projection.ProjectionType != "ALL" {
		switch {
		case sel == "ALL_ATTRIBUTES" && tg.global:
			return nil, validation("One or more parameter values were invalid: Select type ALL_ATTRIBUTES is not supported for global secondary index %s because its projection type is not ALL", tg.ix.def.IndexName)
		case sel == "ALL_ATTRIBUTES", sel == "SPECIFIC_ATTRIBUTES" && !tg.global:
			needBase = true // LSIs fetch unprojected attributes from the table
		}
	}

	// Segments (parallel scan).
	var segment, total int
	if !isQuery && (in.Segment != nil || in.TotalSegments != nil) {
		if in.Segment == nil || in.TotalSegments == nil {
			return nil, validation("The TotalSegments parameter is required but was not present in the request when parameter Segment is present")
		}
		total, segment = *in.TotalSegments, *in.Segment
		if total < 1 || total > 1000000 {
			return nil, validation("1 validation error detected: Value '%d' at 'totalSegments' failed to satisfy constraint: Member must have value less than or equal to 1000000 and greater than or equal to 1", total)
		}
		if segment < 0 || segment >= total {
			return nil, validation("The Segment parameter is zero-based and must be less than parameter TotalSegments: Segment: %d is not less than TotalSegments: %d", segment, total)
		}
	}

	cur, err := h.startCursor(tg, in.ExclusiveStartKey)
	if err != nil {
		return nil, err
	}
	if cur != nil && kr != nil && !bytes.Equal(cur.pk, kr.pk) {
		return nil, validation("The provided starting key is invalid: The provided starting key is outside query boundaries based on provided conditions")
	}
	forward := in.ScanIndexForward == nil || *in.ScanIndexForward
	limit := -1
	if in.Limit != nil {
		limit = *in.Limit
	}

	items := []expr.Item{}
	scanned, matched, bytesRead := 0, 0, 0
	var last *row
	more := false
	const batch = 256
outer:
	for {
		rows, err := h.fetch(c, tg, kr, cur, forward, batch)
		if err != nil {
			return nil, err
		}
		for i := range rows {
			r := &rows[i]
			cur = &cursor{pk: r.pk, sk: r.sk, bk: r.bk}
			if total > 0 && segmentOf(r.pk, total) != segment {
				continue
			}
			if limit >= 0 && scanned == limit || bytesRead >= maxPageBytes {
				more = true
				break outer
			}
			scanned++
			bytesRead += r.size
			last = r
			it := r.item
			if needBase {
				if full, err := h.baseItem(c, tg.t, it); err == nil && full != nil {
					it = full
				}
			}
			if filter != nil {
				ok, err := filter.Eval(it, "FilterExpression")
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
			}
			matched++
			if sel != "COUNT" {
				if proj != nil {
					it = expr.Project(it, proj)
				}
				items = append(items, it)
			}
		}
		if len(rows) < batch {
			break
		}
	}
	if limit >= 0 && scanned == limit && last != nil {
		more = true // DynamoDB can't know the next page is empty
	}
	out := map[string]any{"Count": matched, "ScannedCount": scanned}
	if sel != "COUNT" {
		out["Items"] = items
	}
	if more && last != nil {
		out["LastEvaluatedKey"] = lastKey(tg, last.item)
	}
	units := float64(bytesRead) / 4096
	if units < 1 {
		units = 1
	}
	if !in.ConsistentRead {
		units /= 2
	}
	h.addCapacity(out, in.ReturnConsumedCapacity, t, units, nil)
	return out, nil
}

func segmentOf(pk []byte, total int) int {
	h := fnv.New32a()
	h.Write(pk)
	return int(h.Sum32() % uint32(total))
}

// lastKey is the LastEvaluatedKey for an item: the table key, plus the
// index key when reading an index.
func lastKey(tg *target, it expr.Item) expr.Item {
	k := tg.t.keyItem(it)
	if tg.ix != nil {
		for _, ke := range tg.ix.def.KeySchema {
			if v := it[ke.AttributeName]; v != nil {
				k[ke.AttributeName] = v
			}
		}
	}
	return k
}

// baseItem fetches the full item behind an index row.
func (h *Handler) baseItem(c *call, t *table, it expr.Item) (expr.Item, error) {
	k, err := t.keyFromItem(it)
	if err != nil {
		return nil, err
	}
	return getItem(c.ctx, h.st.DB(), t, k)
}

// filterUsesKey: a Query's filter may not reference the key attributes.
func filterUsesKey(c *expr.Cond, tg *target) error {
	var walk func(c *expr.Cond) error
	walk = func(c *expr.Cond) error {
		if c == nil {
			return nil
		}
		for _, a := range c.Args {
			if a.Path != nil && (a.Path[0].Name == tg.hash || tg.rng != "" && a.Path[0].Name == tg.rng) {
				return validation("Filter Expression can only contain non-primary key attributes: Primary key attribute: %s", a.Path[0].Name)
			}
		}
		if err := walk(c.Left); err != nil {
			return err
		}
		return walk(c.Right)
	}
	return walk(c)
}
