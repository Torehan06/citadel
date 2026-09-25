package s3

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"time"
)

// Lifecycle configuration: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html
// M2 stores and validates the configuration; nothing expires yet. Optional
// elements are pointers so a configuration reads back exactly as written.

type lcAnd struct {
	Prefix                *string `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Tags                  []tag   `xml:"Tag" json:"tags,omitempty"`
	ObjectSizeGreaterThan *int64  `xml:"ObjectSizeGreaterThan,omitempty" json:"size_gt,omitempty"`
	ObjectSizeLessThan    *int64  `xml:"ObjectSizeLessThan,omitempty" json:"size_lt,omitempty"`
}

type lcFilter struct {
	Prefix                *string `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Tag                   *tag    `xml:"Tag,omitempty" json:"tag,omitempty"`
	And                   *lcAnd  `xml:"And,omitempty" json:"and,omitempty"`
	ObjectSizeGreaterThan *int64  `xml:"ObjectSizeGreaterThan,omitempty" json:"size_gt,omitempty"`
	ObjectSizeLessThan    *int64  `xml:"ObjectSizeLessThan,omitempty" json:"size_lt,omitempty"`
}

type lcExpiration struct {
	Days                      *int    `xml:"Days,omitempty" json:"days,omitempty"`
	Date                      *string `xml:"Date,omitempty" json:"date,omitempty"`
	ExpiredObjectDeleteMarker *bool   `xml:"ExpiredObjectDeleteMarker,omitempty" json:"expired_dm,omitempty"`
}

type lcTransition struct {
	Days         *int    `xml:"Days,omitempty" json:"days,omitempty"`
	Date         *string `xml:"Date,omitempty" json:"date,omitempty"`
	StorageClass string  `xml:"StorageClass" json:"storage_class"`
}

type lcNoncurrent struct {
	NoncurrentDays          *int   `xml:"NoncurrentDays,omitempty" json:"days,omitempty"`
	NewerNoncurrentVersions *int   `xml:"NewerNoncurrentVersions,omitempty" json:"newer,omitempty"`
	StorageClass            string `xml:"StorageClass,omitempty" json:"storage_class,omitempty"`
}

type lcAbortMPU struct {
	DaysAfterInitiation int `xml:"DaysAfterInitiation" json:"days"`
}

type lcRule struct {
	ID                             string         `xml:"ID,omitempty" json:"id"`
	Prefix                         *string        `xml:"Prefix,omitempty" json:"prefix,omitempty"` // legacy form
	Filter                         *lcFilter      `xml:"Filter,omitempty" json:"filter,omitempty"`
	Status                         string         `xml:"Status" json:"status"`
	Expiration                     *lcExpiration  `xml:"Expiration,omitempty" json:"expiration,omitempty"`
	Transitions                    []lcTransition `xml:"Transition" json:"transitions,omitempty"`
	NoncurrentVersionTransitions   []lcNoncurrent `xml:"NoncurrentVersionTransition" json:"nc_transitions,omitempty"`
	NoncurrentVersionExpiration    *lcNoncurrent  `xml:"NoncurrentVersionExpiration,omitempty" json:"nc_expiration,omitempty"`
	AbortIncompleteMultipartUpload *lcAbortMPU    `xml:"AbortIncompleteMultipartUpload,omitempty" json:"abort_mpu,omitempty"`
}

type lifecycleConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LifecycleConfiguration"`
	Rules   []lcRule `xml:"Rule"`
}

type lifecycleIn struct {
	Rules []lcRule `xml:"Rule"`
}

// lifecycleDate accepts the ISO 8601 forms S3 does; the time must be midnight UTC.
func validLifecycleDate(s string) bool {
	for _, layout := range []string{"2006-01-02", "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
		}
	}
	return false
}

func parseLifecycle(body []byte) ([]lcRule, error) {
	var in lifecycleIn
	if err := xml.Unmarshal(body, &in); err != nil || len(in.Rules) == 0 || len(in.Rules) > 1000 {
		return nil, errMalformedXML()
	}
	seen := map[string]bool{}
	for i := range in.Rules {
		r := &in.Rules[i]
		if r.Status != "Enabled" && r.Status != "Disabled" {
			return nil, errMalformedXML()
		}
		if len(r.ID) > 255 {
			return nil, errInvalidArgument("ID length should not exceed allowed limit of 255")
		}
		if r.ID == "" {
			r.ID = newVersionID() // S3 assigns an ID when none is given
		}
		if seen[r.ID] {
			return nil, errInvalidArgument("Rule ID must be unique. Found same ID for more than one rule")
		}
		seen[r.ID] = true
		if r.Prefix != nil && r.Filter != nil {
			return nil, errMalformedXML()
		}
		if e := r.Expiration; e != nil {
			if e.Days != nil && e.Date != nil {
				return nil, errMalformedXML()
			}
			if e.Days != nil && *e.Days <= 0 {
				return nil, errInvalidArgument("'Days' for Expiration action must be a positive integer")
			}
			if e.Date != nil && !validLifecycleDate(*e.Date) {
				return nil, errInvalidArgument("'Date' must be at midnight GMT")
			}
		}
		for _, t := range r.Transitions {
			if t.Date != nil && !validLifecycleDate(*t.Date) {
				return nil, errInvalidArgument("'Date' must be at midnight GMT")
			}
			if t.Days != nil && *t.Days < 0 {
				return nil, errInvalidArgument("'Days' for Transition action must be a positive integer")
			}
		}
		if nc := r.NoncurrentVersionExpiration; nc != nil && nc.NoncurrentDays != nil && *nc.NoncurrentDays <= 0 {
			return nil, errInvalidArgument("'NoncurrentDays' for NoncurrentVersionExpiration action must be a positive integer")
		}
		if a := r.AbortIncompleteMultipartUpload; a != nil && a.DaysAfterInitiation <= 0 {
			return nil, errInvalidArgument("'DaysAfterInitiation' for AbortIncompleteMultipartUpload action must be a positive integer")
		}
	}
	return in.Rules, nil
}

func (h *Handler) getBucketLifecycle(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetLifecycleConfiguration", "")
	if err != nil {
		return err
	}
	var rules []lcRule
	if b.Lifecycle != "" {
		_ = json.Unmarshal([]byte(b.Lifecycle), &rules)
	}
	if len(rules) == 0 {
		return &Error{Status: 404, Code: "NoSuchLifecycleConfiguration", Message: "The lifecycle configuration does not exist", Bucket: req.bucket}
	}
	writeXML(req.w, http.StatusOK, lifecycleConfiguration{Rules: rules})
	return nil
}

func (h *Handler) putBucketLifecycle(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutLifecycleConfiguration", ""); err != nil {
		return err
	}
	body, err := readSmallBody(req, 256<<10, false)
	if err != nil {
		return err
	}
	rules, err := parseLifecycle(body)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(rules)
	if err := h.setBucketColumn(req, "lifecycle", string(raw), "PutBucketLifecycleConfiguration"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) deleteBucketLifecycle(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutLifecycleConfiguration", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "lifecycle", "", "DeleteBucketLifecycle"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}
