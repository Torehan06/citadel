// Package expr is DynamoDB's value model and expression language:
// attribute values, exact numbers, and the condition, update, projection
// and key-condition expressions evaluated against them.
package expr

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// Kind is an attribute value's type descriptor.
type Kind string

const (
	S    Kind = "S"
	N    Kind = "N"
	B    Kind = "B"
	BOOL Kind = "BOOL"
	NULL Kind = "NULL"
	M    Kind = "M"
	L    Kind = "L"
	SS   Kind = "SS"
	NS   Kind = "NS"
	BS   Kind = "BS"
)

// Value is one DynamoDB attribute value.
type Value struct {
	Kind Kind
	S    string            // S
	N    Number            // N
	B    []byte            // B
	Bool bool              // BOOL
	M    map[string]*Value // M
	L    []*Value          // L
	SS   []string          // SS (unique)
	NS   []Number          // NS (unique)
	BS   [][]byte          // BS (unique)
}

// Item is a map of attribute names to values.
type Item map[string]*Value

// ValidationError is a client error in a value or expression.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// UnmarshalJSON decodes the wire form {"S": "x"} etc., validating as
// DynamoDB does.
func (v *Value) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return invalid("Supplied AttributeValue is not a valid JSON object")
	}
	if len(raw) != 1 {
		if len(raw) == 0 {
			return invalid("Supplied AttributeValue is empty, must contain exactly one of the supported datatypes")
		}
		return invalid("Supplied AttributeValue has more than one datatypes set, must contain exactly one of the supported datatypes")
	}
	for k, r := range raw {
		v.Kind = Kind(k)
		switch v.Kind {
		case S:
			return decodeInto(r, &v.S)
		case N:
			var s string
			if err := decodeInto(r, &s); err != nil {
				return err
			}
			n, err := ParseNumber(s)
			if err != nil {
				return numberError(s, err)
			}
			v.N = n
		case B:
			var s string
			if err := decodeInto(r, &s); err != nil {
				return err
			}
			d, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return invalid("Invalid BASE64 encoding")
			}
			v.B = d
		case BOOL:
			return decodeInto(r, &v.Bool)
		case NULL:
			var t bool
			if err := decodeInto(r, &t); err != nil {
				return err
			}
			if !t {
				return invalid("One or more parameter values were invalid: Null attribute value types must have the value of true")
			}
		case M:
			m := map[string]*Value{}
			if err := json.Unmarshal(r, &m); err != nil {
				return asValidation(err)
			}
			for _, e := range m {
				if e == nil {
					return invalid("Supplied AttributeValue is empty, must contain exactly one of the supported datatypes")
				}
			}
			v.M = m
		case L:
			var l []*Value
			if err := json.Unmarshal(r, &l); err != nil {
				return asValidation(err)
			}
			for _, e := range l {
				if e == nil {
					return invalid("Supplied AttributeValue is empty, must contain exactly one of the supported datatypes")
				}
			}
			if l == nil {
				l = []*Value{}
			}
			v.L = l
		case SS:
			var ss []string
			if err := decodeInto(r, &ss); err != nil {
				return err
			}
			if len(ss) == 0 {
				return invalid("One or more parameter values were invalid: An string set  may not be empty")
			}
			if hasDupStrings(ss) {
				return invalid("One or more parameter values were invalid: Input collection %s contains duplicates.", fmtStrings(ss))
			}
			v.SS = ss
		case NS:
			var ss []string
			if err := decodeInto(r, &ss); err != nil {
				return err
			}
			if len(ss) == 0 {
				return invalid("One or more parameter values were invalid: An number set  may not be empty")
			}
			seen := map[string]bool{}
			for _, s := range ss {
				n, err := ParseNumber(s)
				if err != nil {
					return numberError(s, err)
				}
				c := n.String()
				if seen[c] {
					return invalid("One or more parameter values were invalid: Input collection %s contains duplicates.", fmtStrings(ss))
				}
				seen[c] = true
				v.NS = append(v.NS, n)
			}
		case BS:
			var ss []string
			if err := decodeInto(r, &ss); err != nil {
				return err
			}
			if len(ss) == 0 {
				return invalid("One or more parameter values were invalid: Binary sets should not be empty")
			}
			seen := map[string]bool{}
			for _, s := range ss {
				d, err := base64.StdEncoding.DecodeString(s)
				if err != nil {
					return invalid("Invalid BASE64 encoding")
				}
				if seen[string(d)] {
					return invalid("One or more parameter values were invalid: Input collection contains duplicates.")
				}
				seen[string(d)] = true
				v.BS = append(v.BS, d)
			}
		default:
			return invalid("Supplied AttributeValue has unsupported datatype %s", k)
		}
	}
	return nil
}

func fmtStrings(ss []string) string {
	b, _ := json.Marshal(ss)
	return string(b)
}

func hasDupStrings(ss []string) bool {
	seen := map[string]bool{}
	for _, s := range ss {
		if seen[s] {
			return true
		}
		seen[s] = true
	}
	return false
}

func numberError(s string, err error) error {
	if err == ErrNumberSyntax {
		return invalid("A value provided cannot be converted into a number")
	}
	return invalid("%s", err.Error())
}

func decodeInto(r json.RawMessage, dst any) error {
	if err := json.Unmarshal(r, dst); err != nil {
		return invalid("Supplied AttributeValue is not valid: %v", err)
	}
	return nil
}

// asValidation keeps a nested ValidationError's message.
func asValidation(err error) error {
	for e := err; e != nil; {
		if ve, ok := e.(*ValidationError); ok {
			return ve
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return invalid("%v", err)
}

// MarshalJSON encodes the wire form. Sets are emitted as stored.
func (v *Value) MarshalJSON() ([]byte, error) {
	var inner any
	switch v.Kind {
	case S:
		inner = v.S
	case N:
		inner = v.N.String()
	case B:
		inner = base64.StdEncoding.EncodeToString(v.B)
	case BOOL:
		inner = v.Bool
	case NULL:
		inner = true
	case M:
		if v.M == nil {
			inner = map[string]*Value{}
		} else {
			inner = v.M
		}
	case L:
		if v.L == nil {
			inner = []*Value{}
		} else {
			inner = v.L
		}
	case SS:
		inner = v.SS
	case NS:
		s := make([]string, len(v.NS))
		for i, n := range v.NS {
			s[i] = n.String()
		}
		inner = s
	case BS:
		s := make([]string, len(v.BS))
		for i, b := range v.BS {
			s[i] = base64.StdEncoding.EncodeToString(b)
		}
		inner = s
	default:
		return nil, fmt.Errorf("expr: value with no kind")
	}
	return json.Marshal(map[string]any{string(v.Kind): inner})
}

// Equal compares values as DynamoDB does (sets compare as sets).
func Equal(a, b *Value) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case S:
		return a.S == b.S
	case N:
		return a.N.Cmp(b.N) == 0
	case B:
		return bytes.Equal(a.B, b.B)
	case BOOL:
		return a.Bool == b.Bool
	case NULL:
		return true
	case M:
		if len(a.M) != len(b.M) {
			return false
		}
		for k, av := range a.M {
			if !Equal(av, b.M[k]) {
				return false
			}
		}
		return true
	case L:
		if len(a.L) != len(b.L) {
			return false
		}
		for i := range a.L {
			if !Equal(a.L[i], b.L[i]) {
				return false
			}
		}
		return true
	case SS:
		return sameSet(len(a.SS), len(b.SS), func(i int) string { return a.SS[i] }, func(i int) string { return b.SS[i] })
	case NS:
		return sameSet(len(a.NS), len(b.NS), func(i int) string { return a.NS[i].String() }, func(i int) string { return b.NS[i].String() })
	case BS:
		return sameSet(len(a.BS), len(b.BS), func(i int) string { return string(a.BS[i]) }, func(i int) string { return string(b.BS[i]) })
	}
	return false
}

func sameSet(na, nb int, a, b func(int) string) bool {
	if na != nb {
		return false
	}
	seen := map[string]bool{}
	for i := 0; i < na; i++ {
		seen[a(i)] = true
	}
	for i := 0; i < nb; i++ {
		if !seen[b(i)] {
			return false
		}
	}
	return true
}

// Compare orders two scalar values of the same kind (S, N, B); ok is false
// when they aren't comparable.
func Compare(a, b *Value) (c int, ok bool) {
	if a == nil || b == nil || a.Kind != b.Kind {
		return 0, false
	}
	switch a.Kind {
	case S:
		return compareStrings(a.S, b.S), true
	case N:
		return a.N.Cmp(b.N), true
	case B:
		return bytes.Compare(a.B, b.B), true
	}
	return 0, false
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Clone deep-copies a value.
func (v *Value) Clone() *Value {
	if v == nil {
		return nil
	}
	c := *v
	if v.M != nil {
		c.M = make(map[string]*Value, len(v.M))
		for k, e := range v.M {
			c.M[k] = e.Clone()
		}
	}
	if v.L != nil {
		c.L = make([]*Value, len(v.L))
		for i, e := range v.L {
			c.L[i] = e.Clone()
		}
	}
	c.SS = append([]string(nil), v.SS...)
	c.NS = append([]Number(nil), v.NS...)
	c.BS = append([][]byte(nil), v.BS...)
	return &c
}

// Clone deep-copies an item.
func (it Item) Clone() Item {
	if it == nil {
		return nil
	}
	c := make(Item, len(it))
	for k, v := range it {
		c[k] = v.Clone()
	}
	return c
}

// Size is DynamoDB's size of a value in bytes (for the 400 KB limit and
// capacity accounting).
func (v *Value) Size() int {
	switch v.Kind {
	case S:
		return len(v.S)
	case N:
		return numberSize(v.N)
	case B:
		return len(v.B)
	case BOOL, NULL:
		return 1
	case M:
		n := 3
		for k, e := range v.M {
			n += len(k) + e.Size() + 1
		}
		return n
	case L:
		n := 3
		for _, e := range v.L {
			n += e.Size() + 1
		}
		return n
	case SS:
		n := 0
		for _, s := range v.SS {
			n += len(s)
		}
		return n
	case NS:
		n := 0
		for _, x := range v.NS {
			n += numberSize(x)
		}
		return n
	case BS:
		n := 0
		for _, b := range v.BS {
			n += len(b)
		}
		return n
	}
	return 0
}

// numberSize: roughly one byte per two significant digits, plus one.
func numberSize(n Number) int {
	digits := len(n.Coef.String())
	if n.Coef.Sign() < 0 {
		digits--
	}
	return (digits+1)/2 + 1
}

// Size of an item: attribute names plus values.
func (it Item) Size() int {
	n := 0
	for k, v := range it {
		n += len(k) + v.Size()
	}
	return n
}

// SortedKeys returns the item's attribute names in order (for stable output).
func (it Item) SortedKeys() []string {
	ks := make([]string, 0, len(it))
	for k := range it {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
