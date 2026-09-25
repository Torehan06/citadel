package expr

import (
	"fmt"
	"strconv"
	"strings"
)

// Expression grammar (https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html):
//
//	condition  := or
//	or         := and { OR and }
//	and        := not { AND not }
//	not        := NOT not | primary
//	primary    := '(' condition ')' | function | operand cmp operand
//	            | operand BETWEEN operand AND operand | operand IN '(' operand {',' operand} ')'
//	operand    := path | :value | size '(' path ')'
//	path       := name { '.' name | '[' int ']' }       name := identifier | #placeholder
//	update     := { SET action {',' action} | REMOVE path {',' path}
//	              | ADD path :value {','...} | DELETE path :value {','...} }
//	action     := path '=' setval
//	setval     := term [ ('+'|'-') term ]
//	term       := operand | if_not_exists '(' path ',' setval ')' | list_append '(' setval ',' setval ')'
//	projection := path { ',' path }

// PathElem is one step of a document path: a map key or a list index.
type PathElem struct {
	Name  string
	Index int
	IsIdx bool
}

// Path is a document path such as a.b[2].c.
type Path []PathElem

func (p Path) String() string {
	var b strings.Builder
	for i, e := range p {
		if e.IsIdx {
			fmt.Fprintf(&b, "[%d]", e.Index)
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(e.Name)
	}
	return b.String()
}

// Operand is a value source in an expression.
type Operand struct {
	Path  Path   // attribute path
	Value *Value // literal from ExpressionAttributeValues
	Size  bool   // size(Path)
	// Update-expression functions and arithmetic:
	Func string     // "if_not_exists", "list_append", "+", "-"
	Args []*Operand // function arguments / arithmetic operands
}

// Cond is a condition-expression AST node.
type Cond struct {
	Op    string // AND OR NOT = <> < <= > >= BETWEEN IN or a function name
	Left  *Cond
	Right *Cond
	Args  []*Operand
}

// UpdateAction is one action of an update expression.
type UpdateAction struct {
	Kind  string // SET REMOVE ADD DELETE
	Path  Path
	Value *Operand // SET: the value; ADD/DELETE: the literal
}

// Update is a parsed update expression.
type Update struct{ Actions []UpdateAction }

// Params are ExpressionAttributeNames/Values; Parse marks which are used.
type Params struct {
	Names      map[string]string
	Values     map[string]*Value
	usedNames  map[string]bool
	usedValues map[string]bool
}

// NewParams wraps a request's placeholder maps.
func NewParams(names map[string]string, values map[string]*Value) *Params {
	return &Params{Names: names, Values: values, usedNames: map[string]bool{}, usedValues: map[string]bool{}}
}

// CheckUnused reports placeholders that no expression used, as DynamoDB does.
func (p *Params) CheckUnused() error {
	var names, values []string
	for k := range p.Names {
		if !p.usedNames[k] {
			names = append(names, k)
		}
	}
	for k := range p.Values {
		if !p.usedValues[k] {
			values = append(values, k)
		}
	}
	if len(names) > 0 {
		return invalid("Value provided in ExpressionAttributeNames unused in expressions: keys: {%s}", strings.Join(names, ", "))
	}
	if len(values) > 0 {
		return invalid("Value provided in ExpressionAttributeValues unused in expressions: keys: {%s}", strings.Join(values, ", "))
	}
	return nil
}

// ---- lexer --------------------------------------------------------------------

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tName  // #placeholder
	tValue // :placeholder
	tNum   // list index
	tPunct // ( ) [ ] , . = <> < <= > >= + -
)

type token struct {
	kind tokKind
	s    string
	pos  int
}

func lex(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case isIdentStart(c) || c == '#' || c == ':':
			j := i + 1
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			k := tIdent
			if c == '#' {
				k = tName
			} else if c == ':' {
				k = tValue
			}
			if (k == tName || k == tValue) && j == i+1 {
				return nil, syntaxErr(src, src[i:i+1])
			}
			out = append(out, token{k, src[i:j], i})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			out = append(out, token{tNum, src[i:j], i})
			i = j
		case c == '<' && i+1 < len(src) && (src[i+1] == '>' || src[i+1] == '='):
			out = append(out, token{tPunct, src[i : i+2], i})
			i += 2
		case c == '>' && i+1 < len(src) && src[i+1] == '=':
			out = append(out, token{tPunct, ">=", i})
			i += 2
		case strings.IndexByte("()[],.=<>+-", c) >= 0:
			out = append(out, token{tPunct, string(c), i})
			i++
		default:
			return nil, syntaxErr(src, string(c))
		}
	}
	return append(out, token{tEOF, "", len(src)}), nil
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdentChar(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

func syntaxErr(src, near string) error {
	return invalid("Invalid expression: Syntax error; token: \"%s\", near: \"%s\"", near, src)
}

// ---- parser ---------------------------------------------------------------------

type parser struct {
	ops    int // operators and functions seen (DynamoDB allows 300)
	src    string
	kind   string // "ConditionExpression", "UpdateExpression", ...
	toks   []token
	i      int
	params *Params
}

// CheckAttrName applies DynamoDB's attribute-name limits.
func CheckAttrName(name string) error {
	if name == "" {
		return invalid("One or more parameter values were invalid: Empty attribute name")
	}
	if len(name) > maxAttrName {
		return invalid("One or more parameter values were invalid: Attribute name size exceeds the limit of 65535 bytes")
	}
	return nil
}

const (
	maxAttrName  = 65535
	maxExprBytes = 4096
	maxOperators = 300
)

func newParser(src, kind string, p *Params) (*parser, error) {
	if strings.TrimSpace(src) == "" {
		return nil, invalid("Invalid %s: The expression can not be empty;", kind)
	}
	if len(src) > maxExprBytes {
		return nil, invalid("Invalid %s: Expression size has exceeded the maximum allowed size; expression size: %d", kind, len(src))
	}
	toks, err := lex(src)
	if err != nil {
		return nil, invalid("Invalid %s: %s", kind, strings.TrimPrefix(err.Error(), "Invalid expression: "))
	}
	return &parser{src: src, kind: kind, toks: toks, params: p}, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) errNear(t token) error {
	s := t.s
	if t.kind == tEOF {
		s = "<EOF>"
	}
	return invalid("Invalid %s: Syntax error; token: \"%s\", near: \"%s\"", p.kind, s, p.src)
}

func (p *parser) keyword(t token, kw string) bool {
	return t.kind == tIdent && strings.EqualFold(t.s, kw)
}

func (p *parser) expect(s string) error {
	t := p.next()
	if t.kind != tPunct || t.s != s {
		return p.errNear(t)
	}
	return nil
}

func (p *parser) name(t token) (string, error) {
	switch t.kind {
	case tIdent:
		if reserved[strings.ToUpper(t.s)] {
			return "", invalid("Invalid %s: Attribute name is a reserved keyword; reserved keyword: %s", p.kind, t.s)
		}
		return t.s, nil
	case tName:
		v, ok := p.params.Names[t.s]
		if !ok {
			return "", invalid("Invalid %s: An expression attribute name used in the document path is not defined; attribute name: %s", p.kind, t.s)
		}
		p.params.usedNames[t.s] = true
		if err := CheckAttrName(v); err != nil {
			return "", err
		}
		return v, nil
	}
	return "", p.errNear(t)
}

func (p *parser) value(t token) (*Value, error) {
	v, ok := p.params.Values[t.s]
	if !ok {
		return nil, invalid("Invalid %s: An expression attribute value used in expression is not defined; attribute value: %s", p.kind, t.s)
	}
	p.params.usedValues[t.s] = true
	return v, nil
}

func (p *parser) path() (Path, error) {
	t := p.next()
	n, err := p.name(t)
	if err != nil {
		return nil, err
	}
	path := Path{{Name: n}}
	for {
		switch nt := p.peek(); {
		case nt.kind == tPunct && nt.s == ".":
			p.next()
			n, err := p.name(p.next())
			if err != nil {
				return nil, err
			}
			path = append(path, PathElem{Name: n})
		case nt.kind == tPunct && nt.s == "[":
			p.next()
			it := p.next()
			if it.kind != tNum {
				return nil, invalid("Invalid %s: Syntax error; token: \"%s\", near: \"%s\"", p.kind, it.s, p.src)
			}
			idx, err := strconv.Atoi(it.s)
			if err != nil {
				return nil, invalid("Invalid %s: List index is out of range", p.kind)
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			path = append(path, PathElem{Index: idx, IsIdx: true})
		default:
			if len(path) > 32 {
				return nil, invalid("Invalid %s: The document path has too many nesting levels; nesting levels: %d", p.kind, len(path))
			}
			return path, nil
		}
	}
}

// operand parses path | :value | size(path) (conditions).
func (p *parser) operand() (*Operand, error) {
	t := p.peek()
	switch {
	case t.kind == tValue:
		p.next()
		v, err := p.value(t)
		if err != nil {
			return nil, err
		}
		return &Operand{Value: v}, nil
	case t.kind == tIdent && p.toks[p.i+1].kind == tPunct && p.toks[p.i+1].s == "(":
		if t.s != "size" {
			if isFunction(t.s) {
				return nil, invalid("Invalid %s: The function is not allowed to be used this way in an expression; function: %s", p.kind, t.s)
			}
			return nil, invalid("Invalid %s: Invalid function name; function: %s", p.kind, t.s)
		}
		p.next()
		p.next()
		path, err := p.path()
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		return &Operand{Path: path, Size: true}, nil
	case t.kind == tIdent || t.kind == tName:
		path, err := p.path()
		if err != nil {
			return nil, err
		}
		return &Operand{Path: path}, nil
	}
	return nil, p.errNear(p.next())
}

func isFunction(s string) bool {
	switch s {
	case "attribute_exists", "attribute_not_exists", "attribute_type", "begins_with", "contains", "size",
		"if_not_exists", "list_append":
		return true
	}
	return false
}

// ParseCondition parses a condition (or filter / key condition) expression.
func ParseCondition(src, kind string, params *Params) (*Cond, error) {
	p, err := newParser(src, kind, params)
	if err != nil {
		return nil, err
	}
	c, err := p.or()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, p.errNear(t)
	}
	return c, nil
}

// op counts one operator or function against DynamoDB's limit.
func (p *parser) op() error {
	p.ops++
	if p.ops > maxOperators {
		return invalid("Invalid %s: The expression contains too many operators; operator count: %d", p.kind, p.ops)
	}
	return nil
}

func (p *parser) or() (*Cond, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.keyword(p.peek(), "OR") {
		p.next()
		if err := p.op(); err != nil {
			return nil, err
		}
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = &Cond{Op: "OR", Left: l, Right: r}
	}
	return l, nil
}

func (p *parser) and() (*Cond, error) {
	l, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.keyword(p.peek(), "AND") {
		p.next()
		if err := p.op(); err != nil {
			return nil, err
		}
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		l = &Cond{Op: "AND", Left: l, Right: r}
	}
	return l, nil
}

func (p *parser) not() (*Cond, error) {
	if p.keyword(p.peek(), "NOT") {
		p.next()
		if err := p.op(); err != nil {
			return nil, err
		}
		c, err := p.not()
		if err != nil {
			return nil, err
		}
		return &Cond{Op: "NOT", Left: c}, nil
	}
	return p.primary()
}

func (p *parser) primary() (*Cond, error) {
	t := p.peek()
	if t.kind == tPunct && t.s == "(" {
		p.next()
		c, err := p.or()
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		return c, nil
	}
	// Boolean functions.
	if t.kind == tIdent && p.toks[p.i+1].kind == tPunct && p.toks[p.i+1].s == "(" && t.s != "size" {
		return p.function()
	}
	l, err := p.operand()
	if err != nil {
		return nil, err
	}
	if err := p.op(); err != nil {
		return nil, err
	}
	op := p.next()
	switch {
	case op.kind == tPunct && (op.s == "=" || op.s == "<>" || op.s == "<" || op.s == "<=" || op.s == ">" || op.s == ">="):
		r, err := p.operand()
		if err != nil {
			return nil, err
		}
		return &Cond{Op: op.s, Args: []*Operand{l, r}}, nil
	case p.keyword(op, "BETWEEN"):
		lo, err := p.operand()
		if err != nil {
			return nil, err
		}
		if !p.keyword(p.next(), "AND") {
			return nil, p.errNear(p.toks[p.i-1])
		}
		hi, err := p.operand()
		if err != nil {
			return nil, err
		}
		return &Cond{Op: "BETWEEN", Args: []*Operand{l, lo, hi}}, nil
	case p.keyword(op, "IN"):
		if err := p.expect("("); err != nil {
			return nil, err
		}
		args := []*Operand{l}
		for {
			o, err := p.operand()
			if err != nil {
				return nil, err
			}
			args = append(args, o)
			t := p.next()
			if t.kind == tPunct && t.s == ")" {
				break
			}
			if t.kind != tPunct || t.s != "," {
				return nil, p.errNear(t)
			}
		}
		if len(args)-1 > 100 {
			return nil, invalid("Invalid %s: The IN operator is provided with too many operands; number of operands: %d", p.kind, len(args)-1)
		}
		return &Cond{Op: "IN", Args: args}, nil
	}
	return nil, p.errNear(op)
}

func (p *parser) function() (*Cond, error) {
	if err := p.op(); err != nil {
		return nil, err
	}
	fn := p.next().s
	p.next() // (
	var args []*Operand
	for {
		if t := p.peek(); t.kind == tPunct && t.s == ")" && len(args) == 0 {
			break
		}
		o, err := p.operand()
		if err != nil {
			return nil, err
		}
		args = append(args, o)
		t := p.peek()
		if t.kind == tPunct && t.s == "," {
			p.next()
			continue
		}
		break
	}
	if err := p.expect(")"); err != nil {
		return nil, err
	}
	want := map[string]int{"attribute_exists": 1, "attribute_not_exists": 1, "attribute_type": 2, "begins_with": 2, "contains": 2}
	n, ok := want[fn]
	if !ok {
		if fn == "if_not_exists" || fn == "list_append" {
			return nil, invalid("Invalid %s: The function is not allowed in a condition expression; function: %s", p.kind, fn)
		}
		return nil, invalid("Invalid %s: Invalid function name; function: %s", p.kind, fn)
	}
	if len(args) != n {
		return nil, invalid("Invalid %s: Incorrect number of operands for operator or function; operator or function: %s, number of operands: %d", p.kind, fn, len(args))
	}
	switch fn {
	case "attribute_exists", "attribute_not_exists":
		if args[0].Path == nil || args[0].Size {
			return nil, invalid("Invalid %s: Operator or function requires a document path; operator or function: %s", p.kind, fn)
		}
	case "attribute_type":
		if args[0].Path == nil || args[0].Size {
			return nil, invalid("Invalid %s: Operator or function requires a document path; operator or function: %s", p.kind, fn)
		}
		if args[1].Value == nil {
			return nil, invalid("Invalid %s: Incorrect operand type for operator or function; operator or function: %s, operand type: PATH", p.kind, fn)
		}
		if args[1].Value.Kind != S {
			return nil, invalid("Invalid %s: Incorrect operand type for operator or function; operator or function: %s, operand type: %s", p.kind, fn, args[1].Value.Kind)
		}
		switch Kind(args[1].Value.S) {
		case S, N, B, BOOL, NULL, M, L, SS, NS, BS:
		default:
			return nil, invalid("Invalid %s: Invalid attribute type name found; type: %s, valid types: { B,NULL,SS,BOOL,L,BS,N,NS,S,M }", p.kind, args[1].Value.S)
		}
	case "begins_with", "contains":
		if args[0].Size || args[1].Size && fn == "begins_with" {
			return nil, invalid("Invalid %s: Incorrect operand type for operator or function; operator or function: %s, operand type: NUMBER", p.kind, fn)
		}
	}
	return &Cond{Op: fn, Args: args}, nil
}

// ParseUpdate parses an update expression.
func ParseUpdate(src string, params *Params) (*Update, error) {
	p, err := newParser(src, "UpdateExpression", params)
	if err != nil {
		return nil, err
	}
	u := &Update{}
	seen := map[string]bool{}
	for p.peek().kind != tEOF {
		kw := p.next()
		clause := strings.ToUpper(kw.s)
		if kw.kind != tIdent || (clause != "SET" && clause != "REMOVE" && clause != "ADD" && clause != "DELETE") {
			return nil, p.errNear(kw)
		}
		if seen[clause] {
			return nil, invalid("Invalid UpdateExpression: The \"%s\" section can only be used once in an update expression;", clause)
		}
		seen[clause] = true
		for {
			a := UpdateAction{Kind: clause}
			if a.Path, err = p.path(); err != nil {
				return nil, err
			}
			switch clause {
			case "SET":
				if err := p.expect("="); err != nil {
					return nil, err
				}
				if a.Value, err = p.setValue(); err != nil {
					return nil, err
				}
			case "ADD", "DELETE":
				t := p.next()
				if t.kind != tValue {
					return nil, p.errNear(t)
				}
				v, err := p.value(t)
				if err != nil {
					return nil, err
				}
				a.Value = &Operand{Value: v}
			}
			u.Actions = append(u.Actions, a)
			if t := p.peek(); t.kind == tPunct && t.s == "," {
				p.next()
				continue
			}
			break
		}
	}
	return u, checkPathConflicts(u)
}

func (p *parser) setValue() (*Operand, error) {
	l, err := p.setTerm()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind == tPunct && (t.s == "+" || t.s == "-") {
		p.next()
		r, err := p.setTerm()
		if err != nil {
			return nil, err
		}
		return &Operand{Func: t.s, Args: []*Operand{l, r}}, nil
	}
	return l, nil
}

func (p *parser) setTerm() (*Operand, error) {
	t := p.peek()
	if t.kind == tIdent && p.toks[p.i+1].kind == tPunct && p.toks[p.i+1].s == "(" {
		fn := t.s
		switch fn {
		case "if_not_exists", "list_append":
		default:
			if isFunction(fn) {
				return nil, invalid("Invalid UpdateExpression: The function is not allowed in an update expression; function: %s", fn)
			}
			return nil, invalid("Invalid UpdateExpression: Invalid function name; function: %s", fn)
		}
		p.next()
		p.next()
		var args []*Operand
		for {
			a, err := p.setValue()
			if err != nil {
				return nil, err
			}
			args = append(args, a)
			nt := p.next()
			if nt.kind == tPunct && nt.s == ")" {
				break
			}
			if nt.kind != tPunct || nt.s != "," {
				return nil, p.errNear(nt)
			}
		}
		if len(args) != 2 {
			return nil, invalid("Invalid UpdateExpression: Incorrect number of operands for operator or function; operator or function: %s, number of operands: %d", fn, len(args))
		}
		if fn == "if_not_exists" && (args[0].Path == nil || args[0].Size || args[0].Func != "") {
			return nil, invalid("Invalid UpdateExpression: Operator or function requires a document path; operator or function: if_not_exists")
		}
		return &Operand{Func: fn, Args: args}, nil
	}
	if t.kind == tIdent && t.s == "size" && p.toks[p.i+1].kind == tPunct && p.toks[p.i+1].s == "(" {
		return nil, invalid("Invalid UpdateExpression: The function is not allowed in an update expression; function: size")
	}
	return p.operand()
}

// checkPathConflicts rejects two actions touching the same or overlapping paths.
func checkPathConflicts(u *Update) error {
	for i := range u.Actions {
		for j := i + 1; j < len(u.Actions); j++ {
			a, b := u.Actions[i].Path, u.Actions[j].Path
			n := min(len(a), len(b))
			same := true
			for k := 0; k < n; k++ {
				if a[k] != b[k] {
					same = false
					if a[k].IsIdx != b[k].IsIdx {
						// One path treats the value as a map, the other as a list.
						return invalid("Invalid UpdateExpression: Two document paths conflict with each other; must remove or rewrite one of these paths; path one: [%s], path two: [%s]", pathList(a), pathList(b))
					}
					break
				}
			}
			if !same {
				continue
			}
			if len(a) == len(b) {
				return invalid("Invalid UpdateExpression: Two document paths overlap with each other; must remove or rewrite one of these paths; path one: [%s], path two: [%s]", pathList(a), pathList(b))
			}
			return invalid("Invalid UpdateExpression: Two document paths overlap with each other; must remove or rewrite one of these paths; path one: [%s], path two: [%s]", pathList(a), pathList(b))
		}
	}
	return nil
}

func pathList(p Path) string {
	parts := make([]string, len(p))
	for i, e := range p {
		if e.IsIdx {
			parts[i] = "[" + strconv.Itoa(e.Index) + "]"
		} else {
			parts[i] = e.Name
		}
	}
	return strings.Join(parts, ", ")
}

// ParseProjection parses a projection expression into paths.
func ParseProjection(src string, params *Params) ([]Path, error) {
	p, err := newParser(src, "ProjectionExpression", params)
	if err != nil {
		return nil, err
	}
	var out []Path
	for {
		path, err := p.path()
		if err != nil {
			return nil, err
		}
		out = append(out, path)
		t := p.next()
		if t.kind == tEOF {
			break
		}
		if t.kind != tPunct || t.s != "," {
			return nil, p.errNear(t)
		}
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			a, b := out[i], out[j]
			n := min(len(a), len(b))
			overlap := true
			for k := 0; k < n; k++ {
				if a[k] != b[k] {
					overlap = false
					break
				}
			}
			if overlap {
				return nil, invalid("Invalid ProjectionExpression: Two document paths overlap with each other; must remove or rewrite one of these paths; path one: [%s], path two: [%s]", pathList(a), pathList(b))
			}
		}
	}
	return out, nil
}
