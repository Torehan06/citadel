package s3

import (
	"errors"
	"testing"
)

func TestParseReplication(t *testing.T) {
	const ns = `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`
	cases := []struct {
		name string
		body string
		code string // expected error code, "" for success
	}{
		{"v1", `<ReplicationConfiguration ` + ns + `><Role>r</Role><Rule><Prefix>a/</Prefix><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule></ReplicationConfiguration>`, ""},
		{"v2", `<ReplicationConfiguration><Role>r</Role><Rule><ID>x</ID><Priority>1</Priority><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule></ReplicationConfiguration>`, ""},
		{"bare bucket name", `<ReplicationConfiguration><Role>r</Role><Rule><Status>Enabled</Status><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>`, ""},
		{"no role", `<ReplicationConfiguration><Rule><Status>Enabled</Status><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>`, "MalformedXML"},
		{"no rules", `<ReplicationConfiguration><Role>r</Role></ReplicationConfiguration>`, "MalformedXML"},
		{"bad status", `<ReplicationConfiguration><Role>r</Role><Rule><Status>On</Status><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>`, "MalformedXML"},
		{"no destination", `<ReplicationConfiguration><Role>r</Role><Rule><Status>Enabled</Status></Rule></ReplicationConfiguration>`, "MalformedXML"},
		{"prefix and filter", `<ReplicationConfiguration><Role>r</Role><Rule><Prefix/><Filter><Prefix/></Filter><Status>Enabled</Status><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>`, "MalformedXML"},
		{"v2 without delete marker replication", `<ReplicationConfiguration><Role>r</Role><Rule><Filter><Prefix/></Filter><Status>Enabled</Status><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>`, "InvalidRequest"},
		{"tag filter replicating delete markers", `<ReplicationConfiguration><Role>r</Role><Rule><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>`, "InvalidRequest"},
		{"duplicate ids", `<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID><Status>Enabled</Status><Destination><Bucket>d1</Bucket></Destination></Rule><Rule><ID>a</ID><Status>Enabled</Status><Destination><Bucket>d2</Bucket></Destination></Rule></ReplicationConfiguration>`, "InvalidArgument"},
		{"bad arn", `<ReplicationConfiguration><Role>r</Role><Rule><Status>Enabled</Status><Destination><Bucket>arn:aws:sqs:::q</Bucket></Destination></Rule></ReplicationConfiguration>`, "InvalidArgument"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := parseReplication([]byte(c.body))
			if c.code == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				for _, r := range cfg.Rules {
					if r.ID == "" {
						t.Errorf("rule without an assigned ID")
					}
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) || e.Code != c.code {
				t.Fatalf("got %v, want %s", err, c.code)
			}
		})
	}
}

func TestReplicationDestinations(t *testing.T) {
	p := func(s string) *string { return &s }
	n := func(i int) *int { return &i }
	cfg := &replicationConfiguration{Rules: []replRule{
		{ID: "v1", Prefix: p("logs/"), Status: "Enabled", Destination: replDestination{Bucket: "arn:aws:s3:::a"}},
		{ID: "tagged", Priority: n(1), Filter: &replFilter{Tag: &tag{"env", "prod"}}, Status: "Enabled",
			DeleteMarkerReplication: &replStatus{"Disabled"}, Destination: replDestination{Bucket: "arn:aws:s3:::b"}},
		{ID: "all-to-b", Priority: n(2), Filter: &replFilter{Prefix: p("")}, Status: "Enabled",
			DeleteMarkerReplication: &replStatus{"Enabled"}, Destination: replDestination{Bucket: "arn:aws:s3:::b"}},
		{ID: "off", Status: "Disabled", Destination: replDestination{Bucket: "arn:aws:s3:::c"}},
	}}
	cases := []struct {
		key    string
		tags   []tag
		marker bool
		want   map[string]string // destination -> rule ID
	}{
		{"logs/1", nil, false, map[string]string{"a": "v1", "b": "all-to-b"}},
		{"data/1", []tag{{"env", "prod"}}, false, map[string]string{"b": "all-to-b"}},
		{"logs/1", nil, true, map[string]string{"a": "v1", "b": "all-to-b"}},
		{"data/1", nil, true, map[string]string{"b": "all-to-b"}},
	}
	for _, c := range cases {
		got := cfg.destinations(c.key, c.tags, c.marker)
		if len(got) != len(c.want) {
			t.Errorf("%s marker=%v: got %d destinations, want %v", c.key, c.marker, len(got), c.want)
			continue
		}
		for d, r := range got {
			if c.want[d] != r.ID {
				t.Errorf("%s marker=%v: destination %s via %s, want %s", c.key, c.marker, d, r.ID, c.want[d])
			}
		}
	}
	// A V2 tag rule alone never ships delete markers.
	only := &replicationConfiguration{Rules: cfg.Rules[1:2]}
	if d := only.destinations("x", nil, true); len(d) != 0 {
		t.Errorf("tag rule shipped a delete marker: %v", d)
	}
	if d := only.destinations("x", []tag{{"env", "prod"}}, false); len(d) != 1 {
		t.Errorf("tag rule did not select a tagged object")
	}
}
