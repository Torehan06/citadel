package expr

import (
	"encoding/json"
	"strings"
	"testing"
)

func item(t *testing.T, js string) Item {
	t.Helper()
	var it Item
	if err := json.Unmarshal([]byte(js), &it); err != nil {
		t.Fatalf("%s: %v", js, err)
	}
	return it
}

func vals(t *testing.T, js string) map[string]*Value {
	t.Helper()
	var m map[string]*Value
	if js == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatalf("%s: %v", js, err)
	}
	return m
}

func TestConditions(t *testing.T) {
	it := item(t, `{"a":{"N":"5"},"s":{"S":"hello"},"l":{"L":[{"N":"1"},{"S":"x"}]},
		"m":{"M":{"b":{"N":"2"}}},"ss":{"SS":["x","y"]},"n":{"NULL":true}}`)
	v := `{":five":{"N":"5"},":four":{"N":"4"},":six":{"N":"6"},":he":{"S":"he"},":x":{"S":"x"},
		":one":{"N":"1"},":S":{"S":"S"},":two":{"N":"2"}}`
	cases := []struct {
		expr  string
		names map[string]string
		want  bool
		err   string
	}{
		{"a = :five", nil, true, ""},
		{"a <> :five", nil, false, ""},
		{"zz <> :five", nil, true, ""}, // missing attribute is "not equal"
		{"zz = :five", nil, false, ""},
		{"a > :four AND a < :six", nil, true, ""},
		{"a BETWEEN :four AND :six", nil, true, ""},
		{"a IN (:one, :five)", nil, true, ""},
		{"NOT a = :four", nil, true, ""},
		{"a = :four OR a = :five", nil, true, ""},
		{"begins_with(s, :he)", nil, true, ""},
		{"contains(ss, :x)", nil, true, ""},
		{"contains(l, :x)", nil, true, ""},
		{"size(s) = :five", nil, true, ""},
		{"m.b = :two", nil, true, ""},
		{"l[0] = :one", nil, true, ""},
		{"attribute_exists(#m.b)", map[string]string{"#m": "m"}, true, ""},
		{"attribute_not_exists(m.c)", nil, true, ""},
		{"attribute_type(s, :S)", nil, true, ""},
		{"s < :five", nil, false, ""}, // different types: false, not an error
		{"(a = :five) AND (s = :he OR s = :x)", nil, false, ""},
		{"a BETWEEN :six AND :four", nil, false, "upper bound"},
		{"a = :nope", nil, false, "not defined"},
		{"#nope = :five", nil, false, "not defined"},
		{"name = :five", nil, false, "reserved keyword"},
		{"a = ", nil, false, "Syntax error"},
		{"bogus(a)", nil, false, "Invalid function name"},
		{"", nil, false, "can not be empty"},
	}
	for _, c := range cases {
		p := NewParams(c.names, vals(t, v))
		cond, err := ParseCondition(c.expr, "ConditionExpression", p)
		if err == nil {
			var ok bool
			ok, err = cond.Eval(it, "ConditionExpression")
			if err == nil && ok != c.want {
				t.Errorf("%q = %v, want %v", c.expr, ok, c.want)
			}
		}
		if c.err == "" && err != nil {
			t.Errorf("%q: unexpected error %v", c.expr, err)
		}
		if c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%q: error %v, want one containing %q", c.expr, err, c.err)
		}
	}
}

func TestUnusedPlaceholders(t *testing.T) {
	p := NewParams(map[string]string{"#a": "a", "#b": "b"}, vals(t, `{":v":{"N":"1"},":w":{"N":"2"}}`))
	if _, err := ParseCondition("#a = :v", "ConditionExpression", p); err != nil {
		t.Fatal(err)
	}
	err := p.CheckUnused()
	if err == nil || !strings.Contains(err.Error(), "#b") {
		t.Fatalf("got %v", err)
	}
}

func TestUpdates(t *testing.T) {
	cases := []struct {
		expr, values, before, after, err string
	}{
		{"SET a = :v", `{":v":{"N":"1"}}`, `{}`, `{"a":{"N":"1"}}`, ""},
		{"SET a = a + :v", `{":v":{"N":"2"}}`, `{"a":{"N":"3"}}`, `{"a":{"N":"5"}}`, ""},
		{"SET a = :v - a", `{":v":{"N":"2"}}`, `{"a":{"N":"3"}}`, `{"a":{"N":"-1"}}`, ""},
		{"SET a = if_not_exists(a, :v)", `{":v":{"N":"7"}}`, `{}`, `{"a":{"N":"7"}}`, ""},
		{"SET l = list_append(l, :v)", `{":v":{"L":[{"N":"2"}]}}`, `{"l":{"L":[{"N":"1"}]}}`, `{"l":{"L":[{"N":"1"},{"N":"2"}]}}`, ""},
		{"SET l[5] = :v", `{":v":{"N":"9"}}`, `{"l":{"L":[{"N":"1"}]}}`, `{"l":{"L":[{"N":"1"},{"N":"9"}]}}`, ""},
		{"SET m.x = :v", `{":v":{"S":"y"}}`, `{"m":{"M":{}}}`, `{"m":{"M":{"x":{"S":"y"}}}}`, ""},
		{"SET m.x = :v", `{":v":{"S":"y"}}`, `{}`, ``, "document path provided"},
		{"SET a = b, b = a", ``, `{"a":{"N":"1"},"b":{"N":"2"}}`, `{"a":{"N":"2"},"b":{"N":"1"}}`, ""}, // swap: RHS see the old item
		{"REMOVE a, l[0]", ``, `{"a":{"N":"1"},"l":{"L":[{"N":"1"},{"N":"2"}]}}`, `{"l":{"L":[{"N":"2"}]}}`, ""},
		{"REMOVE l[0], l[1]", ``, `{"l":{"L":[{"N":"1"},{"N":"2"},{"N":"3"}]}}`, `{"l":{"L":[{"N":"3"}]}}`, ""},
		{"ADD n :v", `{":v":{"N":"1"}}`, `{}`, `{"n":{"N":"1"}}`, ""},
		{"ADD s :v", `{":v":{"SS":["b"]}}`, `{"s":{"SS":["a"]}}`, `{"s":{"SS":["a","b"]}}`, ""},
		{"DELETE s :v", `{":v":{"SS":["a"]}}`, `{"s":{"SS":["a"]}}`, `{}`, ""},
		{"ADD s :v", `{":v":{"S":"x"}}`, `{}`, ``, "Incorrect operand type"},
		{"SET a = zz + :v", `{":v":{"N":"1"}}`, `{}`, ``, "does not exist"},
		{"SET a = :v, a = :v", `{":v":{"N":"1"}}`, `{}`, ``, "overlap"},
		{"SET a.b = :v REMOVE a", `{":v":{"N":"1"}}`, `{}`, ``, "overlap"},
		{"SET a = :v SET b = :v", `{":v":{"N":"1"}}`, `{}`, ``, "only be used once"},
	}
	for _, c := range cases {
		p := NewParams(nil, vals(t, c.values))
		u, err := ParseUpdate(c.expr, p)
		var got Item
		if err == nil {
			got, err = u.Apply(item(t, c.before))
		}
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: error %v, want %q", c.expr, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.expr, err)
			continue
		}
		want := item(t, c.after)
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		if string(gj) != string(wj) {
			t.Errorf("%q: got %s, want %s", c.expr, gj, wj)
		}
	}
}

func TestProjection(t *testing.T) {
	it := item(t, `{"a":{"N":"1"},"b":{"M":{"c":{"N":"2"},"d":{"N":"3"}}},"l":{"L":[{"N":"0"},{"N":"1"},{"N":"2"},{"N":"3"}]}}`)
	paths, err := ParseProjection("b.c, l[3], l[1], zz", NewParams(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(Project(it, paths))
	want := `{"b":{"M":{"c":{"N":"2"}}},"l":{"L":[{"N":"1"},{"N":"3"}]}}`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := ParseProjection("a, a", NewParams(nil, nil)); err == nil {
		t.Fatal("overlapping projection paths accepted")
	}
}
