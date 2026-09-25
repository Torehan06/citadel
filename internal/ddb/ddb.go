// Package ddb implements the DynamoDB JSON 1.0 API on top of the region store.
package ddb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"citadel/internal/ddb/expr"
	"citadel/internal/sigv4"
	"citadel/internal/store"
)

// Handler serves DynamoDB for one region.
type Handler struct {
	st     *store.Store
	auth   *sigv4.Verifier
	region string
	log    *slog.Logger
}

func New(st *store.Store, v *sigv4.Verifier, region string, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{st: st, auth: v, region: region, log: log}
}

// Error is a DynamoDB error: __type and message in a JSON body.
type Error struct {
	Status  int
	Code    string
	Message string
	// Extra fields for the body (e.g. CancellationReasons).
	Extra map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

func validation(format string, args ...any) *Error {
	return errf(400, "ValidationException", format, args...)
}

func notFound(format string, args ...any) *Error {
	return errf(400, "ResourceNotFoundException", format, args...)
}

func conditionFailed() *Error {
	return errf(400, "ConditionalCheckFailedException", "The conditional request failed")
}

// asError maps any error to a DynamoDB error.
func asError(err error) *Error {
	var e *Error
	var ve *expr.ValidationError
	var se *sigv4.Error
	switch {
	case errors.As(err, &e):
		return e
	case errors.As(err, &ve):
		return validation("%s", ve.Msg)
	case errors.As(err, &se):
		switch se.Code {
		case "InvalidAccessKeyId":
			return errf(400, "UnrecognizedClientException", "The security token included in the request is invalid.")
		case "RequestTimeTooSkewed":
			return errf(400, "InvalidSignatureException", "Signature expired: the request time is too far from the server time.")
		case "SignatureDoesNotMatch":
			return errf(400, "InvalidSignatureException", "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method.")
		}
		return errf(400, "IncompleteSignatureException", "%s", se.Message)
	}
	return errf(500, "InternalServerError", "Internal server error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *Error) {
	body := map[string]any{"__type": "com.amazonaws.dynamodb.v20120810#" + e.Code, "message": e.Message}
	for k, v := range e.Extra {
		body[k] = v
	}
	writeJSON(w, e.Status, body)
}

// call is one authenticated request.
type call struct {
	ctx     context.Context
	who     store.Principal
	account string
	body    []byte
}

type opFunc func(h *Handler, c *call) (any, error)

var ops = map[string]opFunc{}

func register(name string, f opFunc) { ops[name] = f }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	out, err := h.serve(r)
	if err != nil {
		e := asError(err)
		if e.Status >= 500 {
			h.log.Error("ddb internal error", "target", r.Header.Get("X-Amz-Target"), "err", err)
		}
		writeError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) serve(r *http.Request) (any, error) {
	if r.Method != http.MethodPost {
		return nil, errf(400, "UnknownOperationException", "")
	}
	target := r.Header.Get("X-Amz-Target")
	name, ok := strings.CutPrefix(target, "DynamoDB_20120810.")
	if !ok {
		return nil, errf(400, "UnknownOperationException", "")
	}
	auth, err := h.auth.Verify(r)
	if err != nil {
		return nil, err
	}
	if auth.Anonymous {
		return nil, errf(400, "MissingAuthenticationTokenException", "Request must contain either a valid (registered) AWS access key ID or X.509 certificate.")
	}
	_, p, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return nil, errf(400, "UnrecognizedClientException", "The security token included in the request is invalid.")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20+1))
	if err != nil {
		var se *sigv4.Error
		if errors.As(err, &se) {
			return nil, err
		}
		return nil, validation("Could not read request body")
	}
	if len(body) > 16<<20 {
		return nil, errf(413, "RequestEntityTooLarge", "Request must be smaller than 16777216 bytes for the %s operation", name)
	}
	op, ok := ops[name]
	if !ok {
		if !knownOperations[name] {
			return nil, errf(400, "UnknownOperationException", "")
		}
		return nil, errf(501, "NotImplemented", "citadel: DynamoDB %s is not implemented yet", name)
	}
	return op(h, &call{ctx: r.Context(), who: p, account: p.Account.ID, body: body})
}

// decode unmarshals the request body into dst, turning JSON problems into
// the errors DynamoDB gives.
func decode(c *call, dst any) error {
	if len(strings.TrimSpace(string(c.body))) == 0 {
		return errf(400, "SerializationException", "Start of structure or map found where not expected")
	}
	if err := json.Unmarshal(c.body, dst); err != nil {
		var ve *expr.ValidationError
		if errors.As(err, &ve) {
			return validation("%s", ve.Msg)
		}
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return errf(400, "SerializationException", "Unexpected value type in payload: %s", te.Field)
		}
		return errf(400, "SerializationException", "%v", err)
	}
	return nil
}

// knownOperations are DynamoDB's API operations. A real operation Citadel
// hasn't built answers 501; a name DynamoDB doesn't have is
// UnknownOperationException, as in DynamoDB.
var knownOperations = map[string]bool{}

func init() {
	for _, op := range strings.Fields(`BatchExecuteStatement BatchGetItem BatchWriteItem CreateBackup
		CreateGlobalTable CreateTable DeleteBackup DeleteItem DeleteResourcePolicy DeleteTable
		DescribeBackup DescribeContinuousBackups DescribeContributorInsights DescribeEndpoints
		DescribeExport DescribeGlobalTable DescribeGlobalTableSettings DescribeImport
		DescribeKinesisStreamingDestination DescribeLimits DescribeTable DescribeTableReplicaAutoScaling
		DescribeTimeToLive DisableKinesisStreamingDestination EnableKinesisStreamingDestination
		ExecuteStatement ExecuteTransaction ExportTableToPointInTime GetItem GetResourcePolicy
		ImportTable ListBackups ListContributorInsights ListExports ListGlobalTables ListImports
		ListTables ListTagsOfResource PutItem PutResourcePolicy Query RestoreTableFromBackup
		RestoreTableToPointInTime Scan TagResource TransactGetItems TransactWriteItems UntagResource
		UpdateContinuousBackups UpdateContributorInsights UpdateGlobalTable UpdateGlobalTableSettings
		UpdateItem UpdateKinesisStreamingDestination UpdateTable UpdateTableReplicaAutoScaling
		UpdateTimeToLive`) {
		knownOperations[op] = true
	}
}
