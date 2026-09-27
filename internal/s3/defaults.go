package s3

import (
	"encoding/xml"
	"net/http"
)

// Bucket configurations Citadel can't set yet still have an AWS answer for a
// bucket that never had them: a default document or a "not found" error.
// Clients such as the Terraform provider read every one of them on refresh.

type accelerateConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccelerateConfiguration"`
}

type requestPaymentConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ RequestPaymentConfiguration"`
	Payer   string   `xml:"Payer"`
}

type bucketLoggingStatus struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ BucketLoggingStatus"`
}

// Since January 2023 every bucket has SSE-S3 default encryption.
type sseConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ServerSideEncryptionConfiguration"`
	Rule    struct {
		Default struct {
			SSEAlgorithm string `xml:"SSEAlgorithm"`
		} `xml:"ApplyServerSideEncryptionByDefault"`
		BucketKeyEnabled bool `xml:"BucketKeyEnabled"`
	} `xml:"Rule"`
}

// defaultBucketConfig answers GET (and DELETE) for a bucket subresource whose
// PUT is not implemented. ok is false when sub is not one of them.
func (h *Handler) defaultBucketConfig(req *request, sub string) (ok bool, err error) {
	type entry struct {
		get, del string // IAM actions
		body     func() any
		missing  *Error
	}
	var e entry
	switch sub {
	case "website":
		e = entry{get: "s3:GetBucketWebsite", del: "s3:DeleteBucketWebsite",
			missing: &Error{Status: 404, Code: "NoSuchWebsiteConfiguration", Message: "The specified bucket does not have a website configuration"}}
	case "object-lock":
		e = entry{get: "s3:GetBucketObjectLockConfiguration",
			missing: &Error{Status: 404, Code: "ObjectLockConfigurationNotFoundError", Message: "Object Lock configuration does not exist for this bucket"}}
	case "accelerate":
		e = entry{get: "s3:GetAccelerateConfiguration", body: func() any { return accelerateConfiguration{} }}
	case "requestPayment":
		e = entry{get: "s3:GetBucketRequestPayment", body: func() any { return requestPaymentConfiguration{Payer: "BucketOwner"} }}
	case "logging":
		e = entry{get: "s3:GetBucketLogging", body: func() any { return bucketLoggingStatus{} }}
	case "encryption":
		e = entry{get: "s3:GetEncryptionConfiguration", del: "s3:PutEncryptionConfiguration", body: func() any {
			var c sseConfiguration
			c.Rule.Default.SSEAlgorithm = "AES256"
			return c
		}}
	default:
		return false, nil
	}
	switch req.r.Method {
	case http.MethodGet:
		if _, err := h.bucketAccess(req, e.get, ""); err != nil {
			return true, err
		}
		if e.missing != nil {
			m := *e.missing
			m.Bucket = req.bucket
			return true, &m
		}
		writeXML(req.w, http.StatusOK, e.body())
		return true, nil
	case http.MethodDelete:
		if e.del == "" {
			return false, nil
		}
		// Nothing was ever set, so deleting leaves the bucket as it is.
		if _, err := h.bucketAccess(req, e.del, ""); err != nil {
			return true, err
		}
		req.w.WriteHeader(http.StatusNoContent)
		return true, nil
	}
	return false, nil
}
