package s3

import "testing"

func TestEventMatches(t *testing.T) {
	tests := []struct {
		configured, name string
		want             bool
	}{
		{"s3:ObjectCreated:*", "ObjectCreated:Put", true},
		{"s3:ObjectCreated:*", "ObjectCreated:CompleteMultipartUpload", true},
		{"s3:ObjectCreated:Put", "ObjectCreated:Put", true},
		{"s3:ObjectCreated:Put", "ObjectCreated:Copy", false},
		{"s3:ObjectCreated:*", "ObjectRemoved:Delete", false},
		{"s3:ObjectRemoved:*", "ObjectRemoved:DeleteMarkerCreated", true},
	}
	for _, tt := range tests {
		if got := eventMatches(tt.configured, tt.name); got != tt.want {
			t.Errorf("eventMatches(%q, %q) = %v", tt.configured, tt.name, got)
		}
	}
}

func target(events []string, prefix, suffix string) *notifyTarget {
	t := &notifyTarget{Events: events, Filter: &notifyFilter{}}
	if prefix != "" {
		t.Filter.Rules = append(t.Filter.Rules, filterRule{Name: "prefix", Value: prefix})
	}
	if suffix != "" {
		t.Filter.Rules = append(t.Filter.Rules, filterRule{Name: "Suffix", Value: suffix})
	}
	return t
}

func TestTargetsOverlap(t *testing.T) {
	created, put, removed := []string{"s3:ObjectCreated:*"}, []string{"s3:ObjectCreated:Put"}, []string{"s3:ObjectRemoved:*"}
	tests := []struct {
		a, b *notifyTarget
		want bool
	}{
		{target(created, "", ""), target(put, "", ""), true},
		{target(created, "", ""), target(removed, "", ""), false},
		{target(created, "in/", ""), target(created, "out/", ""), false},
		{target(created, "in/", ""), target(created, "in/x/", ""), true},
		{target(created, "in/", ""), target(created, "", ".txt"), true}, // in/a.txt matches both
		{target(created, "", ".jpg"), target(created, "", ".txt"), false},
		{target(created, "out/", ".txt"), target(put, "in/", ""), false},
	}
	for i, tt := range tests {
		if got := targetsOverlap(tt.a, tt.b); got != tt.want {
			t.Errorf("case %d: overlap = %v", i, got)
		}
	}
}

func TestTargetMatches(t *testing.T) {
	tg := target([]string{"s3:ObjectCreated:*"}, "out/", ".txt")
	for key, want := range map[string]bool{"out/a.txt": true, "out/a.bin": false, "in/a.txt": false, "out/.txt": true} {
		if got := targetMatches(tg, "ObjectCreated:Put", key); got != want {
			t.Errorf("targetMatches(%q) = %v", key, got)
		}
	}
	if targetMatches(tg, "ObjectRemoved:Delete", "out/a.txt") {
		t.Error("removed event matched a created-only target")
	}
}

func TestEventKey(t *testing.T) {
	for in, want := range map[string]string{"a/b c.txt": "a/b+c.txt", "x+y": "x%2By", "é/ü": "%C3%A9/%C3%BC", "plain": "plain"} {
		if got := eventKey(in); got != want {
			t.Errorf("eventKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChangeEvent(t *testing.T) {
	tests := map[string]string{
		"PutObject": "ObjectCreated:Copy", "DeleteObject": "ObjectRemoved:Delete",
		"PutDeleteMarker": "ObjectRemoved:DeleteMarkerCreated", "PutBucketAcl": "",
	}
	for kind, want := range tests {
		if got := changeEvent(kind, map[string]any{"event": "Copy"}); got != want {
			t.Errorf("changeEvent(%s) = %q", kind, got)
		}
	}
	if got := changeEvent("PutObject", nil); got != "ObjectCreated:Put" {
		t.Errorf("PutObject without event = %q", got)
	}
}
