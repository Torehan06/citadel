// Package bootstrap loads the static identities a region starts with.
//
// Every conformance suite signs requests with fixed test keys (s3-tests, moto,
// alternator). The bootstrap file seeds those keys so a fresh data directory
// can serve the suites immediately. Real multi-region identity lives in the
// control plane (see ARCHITECTURE.md, "Identity"); this file only seeds it.
package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type File struct {
	Accounts []Account `json:"accounts"`
}

type Account struct {
	ID          string `json:"id"`           // 12-digit AWS-style account ID
	Name        string `json:"name"`         // human label only
	CanonicalID string `json:"canonical_id"` // S3 canonical user ID reported as Owner.ID
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Users       []User `json:"users"`
}

type User struct {
	Name      string `json:"name"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

var accountID = regexp.MustCompile(`^[0-9]{12}$`)

// Load reads and validates a bootstrap file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap: %w", err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse bootstrap %s: %w", path, err)
	}
	return &f, f.Validate()
}

// Validate enforces the invariants the rest of the system relies on.
func (f *File) Validate() error {
	seenAcct := map[string]bool{}
	seenKey := map[string]bool{}
	for _, a := range f.Accounts {
		if !accountID.MatchString(a.ID) {
			return fmt.Errorf("account %q: id must be 12 digits", a.ID)
		}
		if seenAcct[a.ID] {
			return fmt.Errorf("account %s: duplicate id", a.ID)
		}
		seenAcct[a.ID] = true
		if a.CanonicalID == "" {
			return fmt.Errorf("account %s: canonical_id is required", a.ID)
		}
		for _, u := range a.Users {
			if u.AccessKey == "" || u.SecretKey == "" {
				return fmt.Errorf("account %s user %q: access_key and secret_key are required", a.ID, u.Name)
			}
			if seenKey[u.AccessKey] {
				return fmt.Errorf("access key %s appears twice", u.AccessKey)
			}
			seenKey[u.AccessKey] = true
		}
	}
	return nil
}

// KeyCount returns the number of access keys defined across all accounts.
func (f *File) KeyCount() int {
	n := 0
	for _, a := range f.Accounts {
		n += len(a.Users)
	}
	return n
}
