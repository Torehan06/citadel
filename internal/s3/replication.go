package s3

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"

	"citadel/internal/store"
)

// Replication configuration: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html
// The configuration is stored as written; replicate.go ships the versions it
// selects to the destination buckets (ARCHITECTURE.md §8).
//
// A rule without a Filter is the V1 schema: it matches on Prefix and always
// replicates delete markers. A rule with a Filter is V2: it must say whether
// delete markers replicate (DeleteMarkerReplication), and rules are ranked by
// Priority when several send the same object to one destination.

type replStatus struct {
	Status string `xml:"Status" json:"status"`
}

type replAnd struct {
	Prefix *string `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Tags   []tag   `xml:"Tag" json:"tags,omitempty"`
}

type replFilter struct {
	Prefix *string  `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Tag    *tag     `xml:"Tag,omitempty" json:"tag,omitempty"`
	And    *replAnd `xml:"And,omitempty" json:"and,omitempty"`
}

type replTime struct {
	Status string `xml:"Status" json:"status"`
	Time   *struct {
		Minutes int `xml:"Minutes" json:"minutes"`
	} `xml:"Time,omitempty" json:"time,omitempty"`
}

type replMetrics struct {
	Status         string `xml:"Status" json:"status"`
	EventThreshold *struct {
		Minutes int `xml:"Minutes" json:"minutes"`
	} `xml:"EventThreshold,omitempty" json:"event_threshold,omitempty"`
}

type replDestination struct {
	Bucket                   string `xml:"Bucket" json:"bucket"`
	Account                  string `xml:"Account,omitempty" json:"account,omitempty"`
	StorageClass             string `xml:"StorageClass,omitempty" json:"storage_class,omitempty"`
	AccessControlTranslation *struct {
		Owner string `xml:"Owner" json:"owner"`
	} `xml:"AccessControlTranslation,omitempty" json:"act,omitempty"`
	EncryptionConfiguration *struct {
		ReplicaKmsKeyID string `xml:"ReplicaKmsKeyID,omitempty" json:"kms,omitempty"`
	} `xml:"EncryptionConfiguration,omitempty" json:"encryption,omitempty"`
	ReplicationTime *replTime    `xml:"ReplicationTime,omitempty" json:"rtc,omitempty"`
	Metrics         *replMetrics `xml:"Metrics,omitempty" json:"metrics,omitempty"`
}

type replSelection struct {
	SseKmsEncryptedObjects *replStatus `xml:"SseKmsEncryptedObjects,omitempty" json:"sse_kms,omitempty"`
	ReplicaModifications   *replStatus `xml:"ReplicaModifications,omitempty" json:"replica_mods,omitempty"`
}

type replRule struct {
	ID                        string          `xml:"ID,omitempty" json:"id"`
	Priority                  *int            `xml:"Priority,omitempty" json:"priority,omitempty"`
	Prefix                    *string         `xml:"Prefix,omitempty" json:"prefix,omitempty"` // V1 schema
	Filter                    *replFilter     `xml:"Filter,omitempty" json:"filter,omitempty"`
	Status                    string          `xml:"Status" json:"status"`
	SourceSelectionCriteria   *replSelection  `xml:"SourceSelectionCriteria,omitempty" json:"selection,omitempty"`
	ExistingObjectReplication *replStatus     `xml:"ExistingObjectReplication,omitempty" json:"existing,omitempty"`
	Destination               replDestination `xml:"Destination" json:"destination"`
	DeleteMarkerReplication   *replStatus     `xml:"DeleteMarkerReplication,omitempty" json:"delete_markers,omitempty"`
}

type replicationConfiguration struct {
	XMLName xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ReplicationConfiguration"`
	Role    string     `xml:"Role" json:"role"`
	Rules   []replRule `xml:"Rule" json:"rules"`
}

type replicationIn struct {
	Role  string     `xml:"Role"`
	Rules []replRule `xml:"Rule"`
}

func validStatus(s *replStatus) bool {
	return s == nil || s.Status == "Enabled" || s.Status == "Disabled"
}

func parseReplication(body []byte) (*replicationConfiguration, error) {
	var in replicationIn
	if err := xml.Unmarshal(body, &in); err != nil || in.Role == "" || len(in.Rules) == 0 || len(in.Rules) > 1000 {
		return nil, errMalformedXML()
	}
	seen := map[string]bool{}
	priorities := map[int]bool{}
	for i := range in.Rules {
		r := &in.Rules[i]
		if r.Status != "Enabled" && r.Status != "Disabled" || r.Destination.Bucket == "" {
			return nil, errMalformedXML()
		}
		if r.Prefix != nil && r.Filter != nil {
			return nil, errMalformedXML()
		}
		if !validStatus(r.DeleteMarkerReplication) || !validStatus(r.ExistingObjectReplication) {
			return nil, errMalformedXML()
		}
		if f := r.Filter; f != nil {
			n := 0
			for _, set := range []bool{f.Prefix != nil, f.Tag != nil, f.And != nil} {
				if set {
					n++
				}
			}
			if n > 1 {
				return nil, errMalformedXML()
			}
		}
		if len(r.ID) > 255 {
			return nil, errInvalidArgument("ID length should not exceed allowed limit of 255")
		}
		if r.ID == "" {
			r.ID = newVersionID() // S3 assigns an ID when none is given
		}
		if seen[r.ID] {
			return nil, errInvalidArgument("Rule Id must be unique")
		}
		seen[r.ID] = true
		if r.Filter != nil {
			if r.DeleteMarkerReplication == nil {
				return nil, errf(400, "InvalidRequest", "DeleteMarkerReplication must be specified for this version of Cross Region Replication configuration schema.")
			}
			if r.DeleteMarkerReplication.Status == "Enabled" && r.hasTagFilter() {
				return nil, errf(400, "InvalidRequest", "Delete marker replication is not supported if any Tag filter is specified.")
			}
			if r.Priority != nil {
				if priorities[*r.Priority] {
					return nil, errf(400, "InvalidRequest", "Found overlapping priority %d in replication configuration", *r.Priority)
				}
				priorities[*r.Priority] = true
			}
		}
		if destBucketName(r.Destination.Bucket) == "" {
			return nil, errInvalidArgument("Invalid bucket ARN: %s", r.Destination.Bucket)
		}
	}
	return &replicationConfiguration{Role: in.Role, Rules: in.Rules}, nil
}

func (r *replRule) hasTagFilter() bool {
	f := r.Filter
	return f != nil && (f.Tag != nil || f.And != nil && len(f.And.Tags) > 0)
}

// destBucketName extracts the bucket name from a destination ARN
// (arn:aws:s3:::name). A bare name is accepted as the name itself.
func destBucketName(arn string) string {
	name, ok := strings.CutPrefix(arn, "arn:aws:s3:::")
	if !ok && strings.HasPrefix(arn, "arn:") {
		return ""
	}
	if strings.ContainsAny(name, "/:") {
		return ""
	}
	return name
}

// matches reports whether the rule selects an object version with this key
// and tag set. Disabled rules select nothing.
func (r *replRule) matches(key string, tags []tag) bool {
	if r.Status != "Enabled" {
		return false
	}
	hasTag := func(want tag) bool {
		for _, t := range tags {
			if t == want {
				return true
			}
		}
		return false
	}
	switch f := r.Filter; {
	case f == nil:
		return r.Prefix == nil || strings.HasPrefix(key, *r.Prefix)
	case f.Prefix != nil:
		return strings.HasPrefix(key, *f.Prefix)
	case f.Tag != nil:
		return hasTag(*f.Tag)
	case f.And != nil:
		if f.And.Prefix != nil && !strings.HasPrefix(key, *f.And.Prefix) {
			return false
		}
		for _, t := range f.And.Tags {
			if !hasTag(t) {
				return false
			}
		}
	}
	return true
}

// replicatesDeleteMarkers: V1 rules always do; V2 rules when enabled.
func (r *replRule) replicatesDeleteMarkers() bool {
	if r.Filter == nil {
		return true
	}
	return r.DeleteMarkerReplication != nil && r.DeleteMarkerReplication.Status == "Enabled"
}

func (r *replRule) priority() int {
	if r.Priority == nil {
		return 0
	}
	return *r.Priority
}

// destinations returns, per destination bucket, the highest-priority enabled
// rule that selects the version. Delete markers only go where the rule
// replicates them.
func (c *replicationConfiguration) destinations(key string, tags []tag, deleteMarker bool) map[string]*replRule {
	out := map[string]*replRule{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if deleteMarker && (!r.replicatesDeleteMarkers() || r.hasTagFilter()) {
			continue
		}
		if !deleteMarker && !r.matches(key, tags) || deleteMarker && !r.matches(key, nil) {
			continue
		}
		d := destBucketName(r.Destination.Bucket)
		if prev, ok := out[d]; !ok || r.priority() > prev.priority() {
			out[d] = r
		}
	}
	return out
}

func loadReplication(raw string) *replicationConfiguration {
	if raw == "" {
		return nil
	}
	var c replicationConfiguration
	if json.Unmarshal([]byte(raw), &c) != nil || len(c.Rules) == 0 {
		return nil
	}
	return &c
}

func (h *Handler) putBucketReplication(req *request) error {
	b, err := h.bucketAccess(req, "s3:PutReplicationConfiguration", "")
	if err != nil {
		return err
	}
	body, err := readSmallBody(req, 2<<20, false)
	if err != nil {
		return err
	}
	cfg, err := parseReplication(body)
	if err != nil {
		return err
	}
	if b.Versioning != versioningEnabled {
		return &Error{Status: 400, Code: "InvalidRequest", Bucket: req.bucket,
			Message: "Versioning must be 'Enabled' on the bucket to apply a replication configuration"}
	}
	raw, _ := json.Marshal(cfg)
	if err := h.setBucketColumn(req, "replication", string(raw), "PutBucketReplication"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) getBucketReplication(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetReplicationConfiguration", "")
	if err != nil {
		return err
	}
	cfg := loadReplication(b.Replication)
	if cfg == nil {
		return &Error{Status: 404, Code: "ReplicationConfigurationNotFoundError", Message: "The replication configuration was not found", Bucket: req.bucket}
	}
	writeXML(req.w, http.StatusOK, cfg)
	return nil
}

func (h *Handler) deleteBucketReplication(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutReplicationConfiguration", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "replication", "", "DeleteBucketReplication"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}

// replicationPendingTx decides a new version's replication status inside the
// write: PENDING when an enabled rule will ship it, else none. Delete markers
// get one too (S3 doesn't report it, but anti-entropy uses it to know which
// versions a rule is responsible for).
func replicationPendingTx(req *request, tx *store.Tx, key string, tags []tag, deleteMarker bool) (string, error) {
	var raw string
	if err := tx.QueryRowContext(req.ctx, `SELECT replication FROM s3_buckets WHERE name = ?`, req.bucket).Scan(&raw); err != nil {
		return "", err
	}
	if cfg := loadReplication(raw); cfg != nil && len(cfg.destinations(key, tags, deleteMarker)) > 0 {
		return replPending, nil
	}
	return "", nil
}

// x-amz-replication-status values.
const (
	replPending   = "PENDING"
	replCompleted = "COMPLETED"
	replFailed    = "FAILED"
	replReplica   = "REPLICA"
)
