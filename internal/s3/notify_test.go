package s3

import (
	"strings"
	"testing"

	"citadel/internal/store"
)

func TestNotificationMatches(t *testing.T) {
	cfg := targetConfig{Events: []string{"s3:ObjectCreated:*"}, Filter: &notificationFilter{Rules: []filterRule{
		{Name: "Prefix", Value: "in/"}, {Name: "Suffix", Value: ".jpg"}}}}
	tests := []struct {
		event, key string
		want       bool
	}{
		{"ObjectCreated:Put", "in/a.jpg", true},
		{"ObjectCreated:CompleteMultipartUpload", "in/deep/b.jpg", true},
		{"ObjectCreated:Put", "out/a.jpg", false},
		{"ObjectCreated:Put", "in/a.png", false},
		{"ObjectRemoved:Delete", "in/a.jpg", false},
	}
	for _, tc := range tests {
		if got := cfg.matches(tc.event, tc.key); got != tc.want {
			t.Errorf("matches(%s, %s) = %v, want %v", tc.event, tc.key, got, tc.want)
		}
	}
	exact := targetConfig{Events: []string{"s3:ObjectRemoved:DeleteMarkerCreated"}}
	if !exact.matches("ObjectRemoved:DeleteMarkerCreated", "k") || exact.matches("ObjectRemoved:Delete", "k") {
		t.Error("exact event names must match exactly")
	}
}

func TestEventName(t *testing.T) {
	tests := []struct {
		kind    string
		payload map[string]any
		want    string
	}{
		{"PutObject", map[string]any{"event": "Copy"}, "ObjectCreated:Copy"},
		{"PutObject", map[string]any{}, "ObjectCreated:Put"},
		{"DeleteObject", nil, "ObjectRemoved:Delete"},
		{"DeleteObjectVersion", nil, "ObjectRemoved:Delete"},
		{"PutDeleteMarker", nil, "ObjectRemoved:DeleteMarkerCreated"},
	}
	for _, tc := range tests {
		if got := eventName(tc.kind, tc.payload); got != tc.want {
			t.Errorf("eventName(%s) = %s, want %s", tc.kind, got, tc.want)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	bad := []targetConfig{
		{Events: nil},
		{Events: []string{"s3:ObjectCreated:Nope"}},
		{Events: []string{"s3:ObjectCreated:*"}, Filter: &notificationFilter{Rules: []filterRule{{Name: "middle", Value: "x"}}}},
		{Events: []string{"s3:ObjectCreated:*"}, Filter: &notificationFilter{Rules: []filterRule{{Name: "prefix"}, {Name: "Prefix"}}}},
	}
	for i, c := range bad {
		if err := validateTarget(&c); err == nil {
			t.Errorf("case %d: want an error", i)
		}
	}
	ok := targetConfig{Events: []string{"s3:ObjectCreated:*"}, Filter: &notificationFilter{Rules: []filterRule{{Name: "PREFIX", Value: "a"}}}}
	if err := validateTarget(&ok); err != nil || ok.ID == "" || ok.Filter.Rules[0].Name != "Prefix" {
		t.Errorf("valid target: err=%v id=%q rule=%q", err, ok.ID, ok.Filter.Rules[0].Name)
	}
}

func TestEventRecordKeyEncoding(t *testing.T) {
	rec := eventRecord(store.Change{HLC: store.MakeHLC(1_700_000_000_000, 7)}, map[string]any{"size": 5.0, "etag": `"abc"`, "version": "null"},
		"ObjectCreated:Put", "b", "dir/a b+c.txt", "owner", "tuchanka-1", "cfg")
	obj := rec["s3"].(map[string]any)["object"].(map[string]any)
	if obj["key"] != "dir/a+b%2Bc.txt" {
		t.Errorf("key = %v", obj["key"])
	}
	if obj["eTag"] != "abc" || obj["size"] != int64(5) {
		t.Errorf("object = %v", obj)
	}
	if _, ok := obj["versionId"]; ok {
		t.Error("unversioned objects carry no versionId")
	}
	if s, _ := obj["sequencer"].(string); len(s) != 16 || strings.ToUpper(s) != s {
		t.Errorf("sequencer = %v", obj["sequencer"])
	}
}
