package expr

import (
	"bytes"
	"math/big"
	"sort"
	"strings"
)

// Resolve follows a document path in an item; nil when any step is missing.
func Resolve(it Item, p Path) *Value {
	if len(p) == 0 || p[0].IsIdx {
		return nil
	}
	v := it[p[0].Name]
	for _, e := range p[1:] {
		if v == nil {
			return nil
		}
		if e.IsIdx {
			if v.Kind != L || e.Index >= len(v.L) {
				return nil
			}
			v = v.L[e.Index]
		} else {
			if v.Kind != M {
				return nil
			}
			v = v.M[e.Name]
		}
	}
	return v
}

// ---- conditions -----------------------------------------------------------------

// Eval evaluates a condition against an item (nil item = no item).
func (c *Cond) Eval(it Item, kind string) (bool, error) {
	switch c.Op {
	case "AND":
		l, err := c.Left.Eval(it, kind)
		if err != nil || !l {
			return false, err
		}
		return c.Right.Eval(it, kind)
	case "OR":
		l, err := c.Left.Eval(it, kind)
		if err != nil || l {
			return l, err
		}
		return c.Right.Eval(it, kind)
	case "NOT":
		l, err := c.Left.Eval(it, kind)
		return !l, err
	case "attribute_exists":
		return Resolve(it, c.Args[0].Path) != nil, nil
	case "attribute_not_exists":
		return Resolve(it, c.Args[0].Path) == nil, nil
	case "attribute_type":
		v := Resolve(it, c.Args[0].Path)
		return v != nil && string(v.Kind) == c.Args[1].Value.S, nil
	case "begins_with":
		a, b := c.Args[0].eval(it), c.Args[1].eval(it)
		if c.Args[1].Value != nil && b.Kind != S && b.Kind != B {
			return false, invalid("Invalid %s: Incorrect operand type for operator or function; operator or function: begins_with, operand type: %s", kind, b.Kind)
		}
		if a == nil || b == nil || a.Kind != b.Kind {
			return false, nil
		}
		switch a.Kind {
		case S:
			return strings.HasPrefix(a.S, b.S), nil
		case B:
			return bytes.HasPrefix(a.B, b.B), nil
		}
		return false, nil
	case "contains":
		return contains(c.Args[0].eval(it), c.Args[1].eval(it)), nil
	case "=", "<>":
		a, b := c.Args[0].eval(it), c.Args[1].eval(it)
		eq := a != nil && b != nil && Equal(a, b)
		if c.Op == "=" {
			return eq, nil
		}
		return !eq, nil
	case "<", "<=", ">", ">=":
		for _, o := range c.Args {
			if o.Value != nil && !scalar(o.Value.Kind) {
				return false, invalid("Invalid %s: Incorrect operand type for operator or function; operator or function: %s, operand type: %s", kind, c.Op, o.Value.Kind)
			}
		}
		cmp, ok := Compare(c.Args[0].eval(it), c.Args[1].eval(it))
		if !ok {
			return false, nil
		}
		switch c.Op {
		case "<":
			return cmp < 0, nil
		case "<=":
			return cmp <= 0, nil
		case ">":
			return cmp > 0, nil
		}
		return cmp >= 0, nil
	case "BETWEEN":
		lo, hi := c.Args[1].eval(it), c.Args[2].eval(it)
		if c.Args[1].Value != nil && c.Args[2].Value != nil {
			if lo.Kind != hi.Kind && scalar(lo.Kind) && scalar(hi.Kind) {
				return false, invalid("Invalid %s: The BETWEEN operator requires same data type for lower and upper bounds; lower bound operand: AttributeValue: {%s}, upper bound operand: AttributeValue: {%s}", kind, lo.Kind, hi.Kind)
			}
			if cmp, ok := Compare(lo, hi); ok && cmp > 0 {
				return false, invalid("Invalid %s: The BETWEEN operator requires upper bound to be greater than or equal to lower bound; lower bound operand: AttributeValue: {%s}, upper bound operand: AttributeValue: {%s}", kind, lo.Kind, hi.Kind)
			}
		}
		v := c.Args[0].eval(it)
		c1, ok1 := Compare(v, lo)
		c2, ok2 := Compare(v, hi)
		return ok1 && ok2 && c1 >= 0 && c2 <= 0, nil
	case "IN":
		v := c.Args[0].eval(it)
		if v == nil {
			return false, nil
		}
		for _, o := range c.Args[1:] {
			if w := o.eval(it); w != nil && Equal(v, w) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, invalid("Invalid %s: unsupported operator %s", kind, c.Op)
}

func scalar(k Kind) bool { return k == S || k == N || k == B }

func contains(a, b *Value) bool {
	if a == nil || b == nil {
		return false
	}
	switch a.Kind {
	case S:
		return b.Kind == S && strings.Contains(a.S, b.S)
	case B:
		return b.Kind == B && bytes.Contains(a.B, b.B)
	case SS:
		if b.Kind == S {
			for _, s := range a.SS {
				if s == b.S {
					return true
				}
			}
		}
	case NS:
		if b.Kind == N {
			for _, n := range a.NS {
				if n.Cmp(b.N) == 0 {
					return true
				}
			}
		}
	case BS:
		if b.Kind == B {
			for _, x := range a.BS {
				if bytes.Equal(x, b.B) {
					return true
				}
			}
		}
	case L:
		for _, e := range a.L {
			if Equal(e, b) {
				return true
			}
		}
	}
	return false
}

// eval gives a condition operand's value (nil when missing).
func (o *Operand) eval(it Item) *Value {
	switch {
	case o.Value != nil:
		return o.Value
	case o.Size:
		v := Resolve(it, o.Path)
		if v == nil {
			return nil
		}
		var n int
		switch v.Kind {
		case S:
			n = len(v.S)
		case B:
			n = len(v.B)
		case SS:
			n = len(v.SS)
		case NS:
			n = len(v.NS)
		case BS:
			n = len(v.BS)
		case M:
			n = len(v.M)
		case L:
			n = len(v.L)
		default:
			return nil
		}
		return &Value{Kind: N, N: Number{Coef: big.NewInt(int64(n))}}
	}
	return Resolve(it, o.Path)
}

// ---- projection --------------------------------------------------------------------

type projNode struct {
	all     bool // the whole value at this point is projected
	names   map[string]*projNode
	indexes map[int]*projNode
}

func newProjNode() *projNode {
	return &projNode{names: map[string]*projNode{}, indexes: map[int]*projNode{}}
}

// Project returns the parts of it selected by paths, keeping nesting; list
// elements come back in index order, compacted.
func Project(it Item, paths []Path) Item {
	root := newProjNode()
	for _, p := range paths {
		n := root
		for i, e := range p {
			var next *projNode
			if e.IsIdx {
				if next = n.indexes[e.Index]; next == nil {
					next = newProjNode()
					n.indexes[e.Index] = next
				}
			} else {
				if next = n.names[e.Name]; next == nil {
					next = newProjNode()
					n.names[e.Name] = next
				}
			}
			n = next
			if i == len(p)-1 {
				n.all = true
			}
		}
	}
	out := Item{}
	for name, child := range root.names {
		if v := it[name]; v != nil {
			if pv := child.apply(v); pv != nil {
				out[name] = pv
			}
		}
	}
	return out
}

func (n *projNode) apply(v *Value) *Value {
	if n.all {
		return v.Clone()
	}
	switch {
	case v.Kind == M && len(n.names) > 0:
		m := map[string]*Value{}
		for name, child := range n.names {
			if e := v.M[name]; e != nil {
				if pe := child.apply(e); pe != nil {
					m[name] = pe
				}
			}
		}
		if len(m) == 0 {
			return nil
		}
		return &Value{Kind: M, M: m}
	case v.Kind == L && len(n.indexes) > 0:
		idx := make([]int, 0, len(n.indexes))
		for i := range n.indexes {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		var l []*Value
		for _, i := range idx {
			if i < len(v.L) {
				if pe := n.indexes[i].apply(v.L[i]); pe != nil {
					l = append(l, pe)
				}
			}
		}
		if len(l) == 0 {
			return nil
		}
		return &Value{Kind: L, L: l}
	}
	return nil
}

// ---- updates -----------------------------------------------------------------------

func errBadPath() error {
	return invalid("The document path provided in the update expression is invalid for update")
}

func errMissingAttr() error {
	return invalid("The provided expression refers to an attribute that does not exist in the item")
}

func errOperandType(op string, k Kind) error {
	return invalid("Invalid UpdateExpression: Incorrect operand type for operator or function; operator: %s, operand type: %s", op, typeName(k))
}

func typeName(k Kind) string {
	switch k {
	case S:
		return "STRING"
	case N:
		return "NUMBER"
	case B:
		return "BINARY"
	case BOOL:
		return "BOOLEAN"
	case NULL:
		return "NULL"
	case M:
		return "MAP"
	case L:
		return "LIST"
	case SS:
		return "STRING SET"
	case NS:
		return "NUMBER SET"
	case BS:
		return "BINARY SET"
	}
	return string(k)
}

// value computes a SET right-hand side against the original item.
func (o *Operand) value(orig Item) (*Value, error) {
	switch o.Func {
	case "":
		if o.Value != nil {
			return o.Value, nil
		}
		v := Resolve(orig, o.Path)
		if v == nil {
			return nil, errMissingAttr()
		}
		return v, nil
	case "if_not_exists":
		if v := Resolve(orig, o.Args[0].Path); v != nil {
			return v, nil
		}
		return o.Args[1].value(orig)
	case "list_append":
		a, err := o.Args[0].value(orig)
		if err != nil {
			return nil, err
		}
		b, err := o.Args[1].value(orig)
		if err != nil {
			return nil, err
		}
		if a.Kind != L || b.Kind != L {
			return nil, invalid("An operand in the update expression has an incorrect data type")
		}
		l := make([]*Value, 0, len(a.L)+len(b.L))
		l = append(append(l, a.L...), b.L...)
		return &Value{Kind: L, L: l}, nil
	case "+", "-":
		a, err := o.Args[0].value(orig)
		if err != nil {
			return nil, err
		}
		b, err := o.Args[1].value(orig)
		if err != nil {
			return nil, err
		}
		if a.Kind != N || b.Kind != N {
			return nil, invalid("An operand in the update expression has an incorrect data type")
		}
		bn := b.N
		if o.Func == "-" {
			bn = bn.Neg()
		}
		sum, err := a.N.Add(bn)
		if err != nil {
			return nil, invalid("%s", err.Error())
		}
		return &Value{Kind: N, N: sum}, nil
	}
	return nil, invalid("unsupported update function %s", o.Func)
}

// Apply runs an update against a copy of it and returns the new item.
// Right-hand sides see the original item, as in DynamoDB.
func (u *Update) Apply(it Item) (Item, error) {
	orig := it
	out := it.Clone()
	if out == nil {
		out = Item{}
	}
	type pending struct {
		a UpdateAction
		v *Value
	}
	var sets []pending
	for _, a := range u.Actions {
		if a.Kind == "SET" {
			v, err := a.Value.value(orig)
			if err != nil {
				return nil, err
			}
			sets = append(sets, pending{a, v.Clone()})
		}
	}
	for _, s := range sets {
		if err := setPath(out, s.a.Path, s.v); err != nil {
			return nil, err
		}
	}
	// REMOVE list elements from the highest index down so indexes refer to
	// the original list.
	var removes []Path
	for _, a := range u.Actions {
		if a.Kind == "REMOVE" {
			removes = append(removes, a.Path)
		}
	}
	sort.SliceStable(removes, func(i, j int) bool {
		a, b := removes[i], removes[j]
		if len(a) == len(b) && a[len(a)-1].IsIdx && b[len(b)-1].IsIdx {
			return a[len(a)-1].Index > b[len(b)-1].Index
		}
		return false
	})
	for _, p := range removes {
		if err := removePath(out, p); err != nil {
			return nil, err
		}
	}
	for _, a := range u.Actions {
		switch a.Kind {
		case "ADD":
			if err := addPath(out, a.Path, a.Value.Value); err != nil {
				return nil, err
			}
		case "DELETE":
			if err := deletePath(out, a.Path, a.Value.Value); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// parentOf finds the container of p's last element, or an error when a
// step on the way is missing or of the wrong type.
func parentOf(it Item, p Path) (*Value, error) {
	if len(p) == 1 {
		return nil, nil
	}
	parent := Resolve(it, p[:len(p)-1])
	if parent == nil {
		return nil, errBadPath()
	}
	last := p[len(p)-1]
	if last.IsIdx && parent.Kind != L || !last.IsIdx && parent.Kind != M {
		return nil, errBadPath()
	}
	return parent, nil
}

func setPath(it Item, p Path, v *Value) error {
	if len(p) == 1 {
		it[p[0].Name] = v
		return nil
	}
	parent, err := parentOf(it, p)
	if err != nil {
		return err
	}
	last := p[len(p)-1]
	if last.IsIdx {
		if last.Index >= len(parent.L) {
			parent.L = append(parent.L, v)
		} else {
			parent.L[last.Index] = v
		}
		return nil
	}
	parent.M[last.Name] = v
	return nil
}

func removePath(it Item, p Path) error {
	if len(p) == 1 {
		delete(it, p[0].Name)
		return nil
	}
	parent := Resolve(it, p[:len(p)-1])
	if parent == nil {
		return nil
	}
	last := p[len(p)-1]
	switch {
	case last.IsIdx && parent.Kind == L:
		if last.Index < len(parent.L) {
			parent.L = append(parent.L[:last.Index], parent.L[last.Index+1:]...)
		}
	case !last.IsIdx && parent.Kind == M:
		delete(parent.M, last.Name)
	default:
		return errBadPath()
	}
	return nil
}

func addPath(it Item, p Path, v *Value) error {
	switch v.Kind {
	case N, SS, NS, BS:
	default:
		return errOperandType("ADD", v.Kind)
	}
	cur := Resolve(it, p)
	if cur == nil {
		return setPath(it, p, v.Clone())
	}
	if cur.Kind != v.Kind {
		return invalid("An operand in the update expression has an incorrect data type")
	}
	switch v.Kind {
	case N:
		sum, err := cur.N.Add(v.N)
		if err != nil {
			return invalid("%s", err.Error())
		}
		cur.N = sum
	case SS:
		have := map[string]bool{}
		for _, s := range cur.SS {
			have[s] = true
		}
		for _, s := range v.SS {
			if !have[s] {
				cur.SS = append(cur.SS, s)
				have[s] = true
			}
		}
	case NS:
		for _, n := range v.NS {
			found := false
			for _, m := range cur.NS {
				if m.Cmp(n) == 0 {
					found = true
					break
				}
			}
			if !found {
				cur.NS = append(cur.NS, n)
			}
		}
	case BS:
		for _, b := range v.BS {
			found := false
			for _, x := range cur.BS {
				if bytes.Equal(x, b) {
					found = true
					break
				}
			}
			if !found {
				cur.BS = append(cur.BS, b)
			}
		}
	}
	return nil
}

func deletePath(it Item, p Path, v *Value) error {
	switch v.Kind {
	case SS, NS, BS:
	default:
		return errOperandType("DELETE", v.Kind)
	}
	cur := Resolve(it, p)
	if cur == nil {
		return nil
	}
	if cur.Kind != v.Kind {
		return invalid("An operand in the update expression has an incorrect data type")
	}
	switch v.Kind {
	case SS:
		drop := map[string]bool{}
		for _, s := range v.SS {
			drop[s] = true
		}
		keep := cur.SS[:0:0]
		for _, s := range cur.SS {
			if !drop[s] {
				keep = append(keep, s)
			}
		}
		cur.SS = keep
		if len(keep) == 0 {
			return removePath(it, p)
		}
	case NS:
		var keep []Number
		for _, n := range cur.NS {
			found := false
			for _, d := range v.NS {
				if d.Cmp(n) == 0 {
					found = true
					break
				}
			}
			if !found {
				keep = append(keep, n)
			}
		}
		cur.NS = keep
		if len(keep) == 0 {
			return removePath(it, p)
		}
	case BS:
		var keep [][]byte
		for _, b := range cur.BS {
			found := false
			for _, d := range v.BS {
				if bytes.Equal(d, b) {
					found = true
					break
				}
			}
			if !found {
				keep = append(keep, b)
			}
		}
		cur.BS = keep
		if len(keep) == 0 {
			return removePath(it, p)
		}
	}
	return nil
}

// Paths returns the paths an update touches (for UPDATED_OLD/UPDATED_NEW).
func (u *Update) Paths() []Path {
	out := make([]Path, 0, len(u.Actions))
	for _, a := range u.Actions {
		out = append(out, a.Path)
	}
	return out
}
