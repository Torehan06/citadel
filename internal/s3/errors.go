package s3

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	"citadel/internal/sigv4"
)

// Error is an S3 error response. Codes and statuses follow
// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
type Error struct {
	Status  int
	Code    string
	Message string
	Bucket  string
	Key     string
	// Header holds extra response headers (e.g. Content-Range on 416).
	Header http.Header
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

func errNoSuchBucket(b string) *Error {
	return &Error{Status: 404, Code: "NoSuchBucket", Message: "The specified bucket does not exist", Bucket: b}
}

func errNoSuchKey(b, k string) *Error {
	return &Error{Status: 404, Code: "NoSuchKey", Message: "The specified key does not exist.", Bucket: b, Key: k}
}

func errAccessDenied() *Error { return errf(403, "AccessDenied", "Access Denied") }

func errNotImplemented(what string) *Error {
	return errf(501, "NotImplemented", "citadel: %s is not implemented yet", what)
}

func errMalformedXML() *Error {
	return errf(400, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema")
}

func errInvalidArgument(format string, args ...any) *Error {
	return errf(400, "InvalidArgument", format, args...)
}

type errorBody struct {
	XMLName    xml.Name `xml:"Error"`
	Code       string   `xml:"Code"`
	Message    string   `xml:"Message"`
	BucketName string   `xml:"BucketName,omitempty"`
	Key        string   `xml:"Key,omitempty"`
	Resource   string   `xml:"Resource,omitempty"`
	RequestID  string   `xml:"RequestId"`
	HostID     string   `xml:"HostId"`
}

// writeError renders err in S3's error envelope and returns the status sent.
// Anything that isn't an *Error or *sigv4.Error is an internal failure.
func writeError(w http.ResponseWriter, r *http.Request, err error) int {
	var e *Error
	var se *sigv4.Error
	switch {
	case errors.As(err, &e):
	case errors.As(err, &se):
		e = &Error{Status: se.Status, Code: se.Code, Message: se.Message}
		switch se.Code { // S3's own wording for temporary-credential problems
		case "InvalidClientTokenId":
			e = errf(400, "InvalidToken", "The provided token is malformed or otherwise invalid.")
		case "ExpiredToken":
			e = errf(400, "ExpiredToken", "The provided token has expired.")
		}
	default:
		e = errf(500, "InternalError", "We encountered an internal error. Please try again.")
	}
	for k, vs := range e.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	reqID := w.Header().Get("x-amz-request-id")
	if r.Method == http.MethodHead {
		// HEAD responses carry no body; SDKs map the bare status code.
		w.WriteHeader(e.Status)
		return e.Status
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(e.Status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(errorBody{
		Code: e.Code, Message: e.Message, BucketName: e.Bucket, Key: e.Key,
		Resource: r.URL.Path, RequestID: reqID, HostID: reqID,
	})
	return e.Status
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}
