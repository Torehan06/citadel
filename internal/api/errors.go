package api

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
)

// Each AWS protocol family has its own error shape. SDKs parse these shapes to
// raise typed exceptions, so getting them wrong makes every conformance test fail
// in confusing ways. Unimplemented operations answer 501 NotImplemented
// immediately: SDKs do not retry 501, while a 500 would trigger retries with
// backoff and make conformance runs crawl.

type s3Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId"`
}

type queryError struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

// WriteError writes an error in the wire format of the given service.
func WriteError(w http.ResponseWriter, r *http.Request, svc string, status int, code, msg string) {
	reqID := w.Header().Get("x-amz-request-id")
	switch svc {
	case SvcDynamoDB, SvcSQS:
		// AWS JSON 1.0: the error type travels in __type.
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.Header().Set("x-amzn-ErrorType", code)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"__type":  "com.amazonaws.citadel#" + code,
			"message": msg,
		})
	case SvcLambda:
		// REST-JSON: type in a header and in the body.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-amzn-ErrorType", code)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"Type": "User", "message": msg})
	case SvcIAM, SvcSTS, SvcRoute53:
		// Query and REST-XML protocols share this envelope.
		var e queryError
		e.Error.Type = "Sender"
		e.Error.Code = code
		e.Error.Message = msg
		e.RequestID = reqID
		writeXML(w, status, e)
	default:
		writeXML(w, status, s3Error{Code: code, Message: msg, Resource: r.URL.Path, RequestID: reqID})
	}
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}

// NotImplemented is the default answer for every operation nobody has built yet.
func NotImplemented(w http.ResponseWriter, r *http.Request, svc string) {
	WriteError(w, r, svc, http.StatusNotImplemented, "NotImplemented",
		"citadel: this operation is not implemented yet (service "+svc+")")
}
