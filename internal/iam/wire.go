package iam

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The query protocol: requests are form-encoded (Action=CreateUser&UserName=…),
// lists are flattened as Name.member.N and structures in lists as
// Name.member.N.Field. Responses are XML: <OpResponse><OpResult>…</OpResult>
// <ResponseMetadata>…</ResponseMetadata></OpResponse>, with list items in
// <member> elements.

type form url.Values

func (f form) str(name string) string { return url.Values(f).Get(name) }

func (f form) has(name string) bool {
	_, ok := f[name]
	return ok
}

// list returns Name.member.1, Name.member.2, … in index order.
func (f form) list(name string) []string {
	prefix := name + ".member."
	type item struct {
		i int
		v string
	}
	var items []item
	for k, v := range f {
		if !strings.HasPrefix(k, prefix) || len(v) == 0 {
			continue
		}
		i, err := strconv.Atoi(k[len(prefix):])
		if err != nil {
			continue
		}
		items = append(items, item{i, v[0]})
	}
	sort.Slice(items, func(a, b int) bool { return items[a].i < items[b].i })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.v
	}
	return out
}

// structs returns Name.member.N.Field values grouped per N, in index order.
func (f form) structs(name string) []map[string]string {
	prefix := name + ".member."
	byIndex := map[int]map[string]string{}
	for k, v := range f {
		if !strings.HasPrefix(k, prefix) || len(v) == 0 {
			continue
		}
		rest := k[len(prefix):]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		i, err := strconv.Atoi(rest[:dot])
		if err != nil {
			continue
		}
		if byIndex[i] == nil {
			byIndex[i] = map[string]string{}
		}
		byIndex[i][rest[dot+1:]] = v[0]
	}
	idx := make([]int, 0, len(byIndex))
	for i := range byIndex {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	out := make([]map[string]string, len(idx))
	for j, i := range idx {
		out[j] = byIndex[i]
	}
	return out
}

func (f form) intValue(name string, def int) (int, error) {
	s := f.str(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, invalidInput("Invalid value for %s: %s", name, s)
	}
	return n, nil
}

func (f form) boolValue(name string) bool { return strings.EqualFold(f.str(name), "true") }

// obj is an ordered XML structure: element name → value. A nil value omits
// the element.
type obj []kv
type kv struct {
	K string
	V any
}

// members renders a list as <member> elements.
type members []any

// raw is a list of strings rendered as <member> elements.
func strMembers(ss []string) members {
	out := make(members, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func writeResult(w http.ResponseWriter, xmlns, op, reqID string, result obj) {
	var b strings.Builder
	b.WriteString(xml.Header)
	fmt.Fprintf(&b, `<%sResponse xmlns="%s">`, op, xmlns)
	if result != nil {
		fmt.Fprintf(&b, "<%sResult>", op)
		encode(&b, result)
		fmt.Fprintf(&b, "</%sResult>", op)
	}
	fmt.Fprintf(&b, "<ResponseMetadata><RequestId>%s</RequestId></ResponseMetadata></%sResponse>", reqID, op)
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(b.String()))
}

func encode(b *strings.Builder, v any) {
	switch t := v.(type) {
	case obj:
		for _, e := range t {
			if e.V == nil {
				continue
			}
			switch x := e.V.(type) {
			case *string:
				if x == nil {
					continue
				}
			case obj:
				if x == nil {
					continue
				}
			}
			fmt.Fprintf(b, "<%s>", e.K)
			encode(b, e.V)
			fmt.Fprintf(b, "</%s>", e.K)
		}
	case members:
		for _, m := range t {
			b.WriteString("<member>")
			encode(b, m)
			b.WriteString("</member>")
		}
	case entries:
		for _, m := range t {
			b.WriteString("<entry>")
			encode(b, m)
			b.WriteString("</entry>")
		}
	case string:
		_ = xml.EscapeText(stringWriter{b}, []byte(t))
	case *string:
		_ = xml.EscapeText(stringWriter{b}, []byte(*t))
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case time.Time:
		b.WriteString(isoTime(t))
	default:
		panic(fmt.Sprintf("iam: cannot encode %T", v))
	}
}

type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

func isoTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// encodeDocument percent-encodes a policy document the way IAM returns it
// (RFC 3986: everything but unreserved characters is escaped, spaces as %20).
// SDKs URL-decode policy documents in IAM responses.
func encodeDocument(doc string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(doc); i++ {
		c := doc[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// apiError is an IAM/STS error in the query-protocol envelope.
type apiError struct {
	Status        int
	Code, Message string
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func newErr(status int, code, format string, args ...any) *apiError {
	return &apiError{status, code, fmt.Sprintf(format, args...)}
}
func noSuchEntity(format string, args ...any) *apiError {
	return newErr(404, "NoSuchEntity", format, args...)
}
func alreadyExists(format string, args ...any) *apiError {
	return newErr(409, "EntityAlreadyExists", format, args...)
}
func deleteConflict(format string, args ...any) *apiError {
	return newErr(409, "DeleteConflict", format, args...)
}
func limitExceeded(format string, args ...any) *apiError {
	return newErr(409, "LimitExceeded", format, args...)
}
func invalidInput(format string, args ...any) *apiError {
	return newErr(400, "InvalidInput", format, args...)
}
func validationError(format string, args ...any) *apiError {
	return newErr(400, "ValidationError", format, args...)
}
func malformed(msg string) *apiError { return newErr(400, "MalformedPolicyDocument", "%s", msg) }

func writeError(w http.ResponseWriter, reqID string, e *apiError) {
	typ := "Sender"
	if e.Status >= 500 {
		typ = "Receiver"
	}
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<ErrorResponse><Error><Type>")
	b.WriteString(typ)
	b.WriteString("</Type><Code>")
	encode(&b, e.Code)
	b.WriteString("</Code><Message>")
	encode(&b, e.Message)
	b.WriteString("</Message></Error><RequestId>")
	b.WriteString(reqID)
	b.WriteString("</RequestId></ErrorResponse>")
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(e.Status)
	_, _ = w.Write([]byte(b.String()))
}
