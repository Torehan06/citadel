package logs

import "testing"

func TestCompileFilter(t *testing.T) {
	tests := []struct {
		pattern string
		match   map[string]bool
	}{
		{"", map[string]bool{"anything": true, "": true}},
		{"ERROR", map[string]bool{"an ERROR here": true, "an error here": false}},
		{"ERROR timeout", map[string]bool{"ERROR: timeout": true, "ERROR only": false, "timeout only": false}},
		{`"hello world"`, map[string]bool{"say hello world!": true, "hello  world": false}},
		{"ERROR -retry", map[string]bool{"ERROR final": true, "ERROR will retry": false}},
		{"?ERROR ?WARN", map[string]bool{"WARN disk": true, "ERROR disk": true, "INFO disk": false}},
		{`"object b/in/obj.txt"`, map[string]bool{"hello-go: object b/in/obj.txt": true}},
	}
	for _, tc := range tests {
		m, err := compileFilter(tc.pattern)
		if err != nil {
			t.Fatalf("compileFilter(%q): %v", tc.pattern, err)
		}
		for msg, want := range tc.match {
			if got := m(msg); got != want {
				t.Errorf("pattern %q on %q = %v, want %v", tc.pattern, msg, got, want)
			}
		}
	}
	for _, bad := range []string{`"unterminated`, `{ $.level = "x" }`, `[ip, user]`} {
		if _, err := compileFilter(bad); err == nil {
			t.Errorf("compileFilter(%q): want an error", bad)
		}
	}
}

func TestValidRetention(t *testing.T) {
	for d, want := range map[int]bool{1: true, 7: true, 3653: true, 2: false, 0: false, 10000: false} {
		if got := validRetention(d); got != want {
			t.Errorf("validRetention(%d) = %v", d, got)
		}
	}
}
