package s3

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
)

func TestLifecycleMinSize(t *testing.T) {
	cases := []struct {
		header, want string
		err          bool
	}{
		{"", "all_storage_classes_128K", false},
		{"all_storage_classes_128K", "all_storage_classes_128K", false},
		{"varies_by_storage_class", "varies_by_storage_class", false},
		{"128K", "", true},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(http.MethodPut, "/b?lifecycle", nil)
		if c.header != "" {
			r.Header.Set(hdrLifecycleMinSize, c.header)
		}
		got, err := lifecycleMinSize(r)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("lifecycleMinSize(%q) = %q, %v; want %q, err=%v", c.header, got, err, c.want, c.err)
		}
	}
}

func TestCreateBucketConfigurationTags(t *testing.T) {
	body := `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<LocationConstraint>tuchanka-1</LocationConstraint>
		<Tags><Tag><Key>Stack</Key><Value>single-region</Value></Tag><Tag><Key>Team</Key><Value></Value></Tag></Tags>
	</CreateBucketConfiguration>`
	var cfg createBucketConfiguration
	if err := xml.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.LocationConstraint != "tuchanka-1" || len(cfg.Tags) != 2 || cfg.Tags[0] != (tag{"Stack", "single-region"}) || cfg.Tags[1] != (tag{"Team", ""}) {
		t.Fatalf("parsed %+v", cfg)
	}
}

// Clients compare the rules they PUT with the rules they GET field by field,
// so an empty filter and unset optional elements must survive storage.
func TestLifecycleRoundTripKeepsEmptyFilter(t *testing.T) {
	in := `<LifecycleConfiguration><Rule><ID>abort</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>` +
		`<AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>` +
		`<Rule><ID>tmp</ID><Filter><Prefix>tmp/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>7</Days></Expiration>` +
		`<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`
	rules, err := parseLifecycle([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rules)
	var stored []lcRule
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	out, _ := xml.Marshal(lifecycleConfiguration{Rules: stored})
	for _, want := range []string{
		"<Filter><Prefix></Prefix></Filter>",
		"<Filter><Prefix>tmp/</Prefix></Filter>",
		"<Expiration><Days>7</Days></Expiration>",
		"<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("GET body lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "ExpiredObjectDeleteMarker") {
		t.Errorf("unset ExpiredObjectDeleteMarker came back:\n%s", out)
	}
}
