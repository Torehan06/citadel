package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoBootstrapFileIsValid(t *testing.T) {
	f, err := Load(filepath.Join("..", "..", "harness", "bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.KeyCount() < 5 {
		t.Fatalf("expected the conformance-suite keys to be present, got %d keys", f.KeyCount())
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		"short account id": `{"accounts":[{"id":"123","canonical_id":"c","users":[]}]}`,
		"duplicate key": `{"accounts":[
			{"id":"111111111111","canonical_id":"a","users":[{"name":"x","access_key":"K","secret_key":"s"}]},
			{"id":"222222222222","canonical_id":"b","users":[{"name":"y","access_key":"K","secret_key":"s"}]}]}`,
		"missing canonical id": `{"accounts":[{"id":"111111111111","users":[]}]}`,
		"missing secret":       `{"accounts":[{"id":"111111111111","canonical_id":"a","users":[{"name":"x","access_key":"K"}]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "b.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
