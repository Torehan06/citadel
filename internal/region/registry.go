// Package region connects a Citadel region to the others: the region registry,
// the control-plane change feed the home region serves, the follower that
// replays it, and the forwarding of global (IAM) calls to the home region
// (ARCHITECTURE.md §7).
package region

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Region is one entry of the registry.
type Region struct {
	Name string `json:"name"`
	// Endpoint is the base URL other regions (and clients) reach it at.
	Endpoint string `json:"endpoint"`
}

// Registry lists the regions of one Citadel cloud and names the home region,
// the single writer of global state. Regions authenticate to each other with
// an HMAC over a shared key that never appears in the registry file itself:
// it comes from CITADEL_REGION_KEY or from key_file.
type Registry struct {
	Home    string   `json:"home"`
	Regions []Region `json:"regions"`
	KeyFile string   `json:"key_file,omitempty"` // relative to the registry file

	key []byte
}

// KeyEnv names the environment variable holding the shared region key.
const KeyEnv = "CITADEL_REGION_KEY"

// Load reads and validates a registry file.
func Load(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("region registry: %w", err)
	}
	var r Registry
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("region registry %s: %w", path, err)
	}
	key := os.Getenv(KeyEnv)
	if key == "" && r.KeyFile != "" {
		kf := r.KeyFile
		if !filepath.IsAbs(kf) {
			kf = filepath.Join(filepath.Dir(path), kf)
		}
		kb, err := os.ReadFile(kf)
		if err != nil {
			return nil, fmt.Errorf("region key: %w", err)
		}
		key = strings.TrimSpace(string(kb))
	}
	r.key = []byte(key)
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("region registry %s: %w", path, err)
	}
	return &r, nil
}

func (r *Registry) validate() error {
	if len(r.Regions) == 0 {
		return errors.New("no regions")
	}
	seen := map[string]bool{}
	for _, g := range r.Regions {
		if g.Name == "" {
			return errors.New("a region has no name")
		}
		if seen[g.Name] {
			return fmt.Errorf("region %s is listed twice", g.Name)
		}
		seen[g.Name] = true
		u, err := url.Parse(g.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("region %s: endpoint %q is not an http(s) URL", g.Name, g.Endpoint)
		}
	}
	if !seen[r.Home] {
		return fmt.Errorf("home region %q is not in the registry", r.Home)
	}
	if len(r.Regions) > 1 && len(r.key) < 16 {
		return fmt.Errorf("regions need a shared key of at least 16 bytes in $%s or key_file", KeyEnv)
	}
	return nil
}

// Get returns the named region.
func (r *Registry) Get(name string) (Region, bool) {
	for _, g := range r.Regions {
		if g.Name == name {
			return g, true
		}
	}
	return Region{}, false
}

// HomeRegion returns the home region's entry.
func (r *Registry) HomeRegion() Region {
	g, _ := r.Get(r.Home)
	return g
}
