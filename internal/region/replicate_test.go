package region

import (
	"testing"
	"time"
)

func TestDigestOrderIndependentAndDiff(t *testing.T) {
	entries := [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}, {"d\x00e", "4"}}
	var fwd, rev Digest
	for _, e := range entries {
		fwd.Add(e[0], e[1])
	}
	for i := len(entries) - 1; i >= 0; i-- {
		rev.Add(entries[i][0], entries[i][1])
	}
	if d := DiffLeaves(&fwd, rev.Hex()); len(d) != 0 {
		t.Fatalf("same set in another order differs in leaves %v", d)
	}
	var changed Digest
	for _, e := range entries {
		v := e[1]
		if e[0] == "b" {
			v = "newer"
		}
		changed.Add(e[0], v)
	}
	d := DiffLeaves(&fwd, changed.Hex())
	if len(d) != 1 || d[0] != LeafOf("b") {
		t.Fatalf("one changed entry: diff %v, want [%d]", d, LeafOf("b"))
	}
	if d := DiffLeaves(&fwd, nil); len(d) != Leaves {
		t.Fatalf("missing remote digest should differ everywhere, got %d leaves", len(d))
	}
	var empty Digest
	fwd.Add("a", "1") // XOR removes it again
	fwd.Add("b", "2")
	fwd.Add("c", "3")
	fwd.Add("d\x00e", "4")
	if d := DiffLeaves(&fwd, empty.Hex()); len(d) != 0 {
		t.Fatalf("adding every entry twice should cancel out, diff %v", d)
	}
}

func TestLagWindow(t *testing.T) {
	l := newLagWindow(100)
	if s := l.summary(); s["lag_samples"] != 0 {
		t.Fatalf("empty window: %v", s)
	}
	for i := 1; i <= 250; i++ {
		l.add(time.Duration(i) * time.Millisecond)
	}
	s := l.summary()
	// The window holds the last 100 samples: 151..250 ms.
	if s["lag_samples"] != 100 || s["lag_p50_ms"] != int64(201) || s["lag_p99_ms"] != int64(250) ||
		s["lag_window_max_ms"] != int64(250) || s["lag_max_ms"] != int64(250) {
		t.Fatalf("summary %v", s)
	}
	l.add(-time.Second) // clock skew never reports negative lag
	if s := l.summary(); s["lag_samples"] != 100 {
		t.Fatalf("summary after skewed sample %v", s)
	}
}
