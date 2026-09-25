package sigv4

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Error is an authentication failure with the AWS error code and HTTP status
// the service should answer with.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errorf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// ErrUnknownKey is what a KeyLookup returns for an access key it doesn't know.
var ErrUnknownKey = errors.New("sigv4: unknown access key")

// KeyLookup returns the secret for an access key, or ErrUnknownKey.
type KeyLookup func(ctx context.Context, accessKey string) (secret string, err error)

// MaxSkew is how far a request's timestamp may be from the server clock.
const MaxSkew = 15 * time.Minute

// Verifier checks request signatures.
type Verifier struct {
	Lookup KeyLookup
	Now    func() time.Time // time.Now when nil
	// MaxBufferedBody bounds how much of a body is read into memory to hash
	// it when the client didn't send X-Amz-Content-Sha256 (non-S3 services).
	MaxBufferedBody int64
}

// Auth describes a request whose signature checked out.
type Auth struct {
	Anonymous bool
	AccessKey string
	Date      time.Time
	Region    string // region from the credential scope
	Service   string // service from the credential scope
	Presigned bool
	// PayloadHash is the declared X-Amz-Content-Sha256 (or UNSIGNED-PAYLOAD).
	PayloadHash string
	// Streaming is set for aws-chunked bodies; r.Body then yields the decoded
	// payload and r.Trailer is filled in once the body has been read to EOF.
	Streaming bool
	// DecodedLength is X-Amz-Decoded-Content-Length for streaming bodies, else -1.
	DecodedLength int64
}

// IsSigned reports whether the request carries any SigV4 signature.
func IsSigned(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.URL.Query().Get("X-Amz-Credential") != "" ||
		r.URL.Query().Get("X-Amz-Signature") != ""
}

type parsedAuth struct {
	accessKey, date, region, service string
	signedHeaders                    []string
	signature                        string
}

func parseCredential(cred string) (ak, date, region, service string, err *Error) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" || parts[0] == "" {
		return "", "", "", "", errorf(400, "AuthorizationHeaderMalformed",
			"The authorization header is malformed; the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".")
	}
	if _, perr := time.Parse("20060102", parts[1]); perr != nil {
		return "", "", "", "", errorf(400, "AuthorizationHeaderMalformed",
			"The authorization header is malformed; incorrect date format %q. This date in the credential must be in the format \"yyyyMMdd\".", parts[1])
	}
	return parts[0], parts[1], parts[2], parts[3], nil
}

func parseAuthorization(h string) (*parsedAuth, *Error) {
	if strings.HasPrefix(h, "AWS ") {
		return nil, errorf(400, "InvalidRequest",
			"The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.")
	}
	rest, ok := strings.CutPrefix(h, Algorithm+" ")
	if !ok {
		return nil, errorf(400, "InvalidArgument", "Unsupported Authorization Type")
	}
	var p parsedAuth
	var cred, signed string
	for _, field := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(field), "=")
		switch k {
		case "Credential":
			cred = v
		case "SignedHeaders":
			signed = v
		case "Signature":
			p.signature = v
		}
	}
	if cred == "" || signed == "" || p.signature == "" {
		return nil, errorf(400, "AuthorizationHeaderMalformed",
			"The authorization header is malformed; it must contain Credential, SignedHeaders and Signature.")
	}
	var err *Error
	if p.accessKey, p.date, p.region, p.service, err = parseCredential(cred); err != nil {
		return nil, err
	}
	p.signedHeaders = strings.Split(signed, ";")
	return &p, nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks the request's signature. Unsigned requests come back as
// Anonymous; deciding whether anonymous access is allowed is the caller's job.
// For signed payloads Verify wraps r.Body so that reading it to EOF checks the
// payload hash (or each chunk's signature for aws-chunked bodies). Those
// failures surface as *Error from r.Body.Read.
func (v *Verifier) Verify(r *http.Request) (*Auth, error) {
	q := r.URL.Query()
	switch {
	case r.Header.Get("Authorization") != "":
		return v.verifyHeader(r)
	case q.Get("X-Amz-Credential") != "" || q.Get("X-Amz-Signature") != "" || q.Get("X-Amz-Algorithm") != "":
		return v.verifyPresigned(r)
	case q.Get("AWSAccessKeyId") != "" && q.Get("Signature") != "":
		return nil, errorf(400, "InvalidRequest",
			"The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.")
	}
	return &Auth{Anonymous: true, DecodedLength: -1}, nil
}

func (v *Verifier) secret(ctx context.Context, accessKey string) (string, error) {
	secret, err := v.Lookup(ctx, accessKey)
	if errors.Is(err, ErrUnknownKey) {
		return "", errorf(403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
	}
	return secret, err
}

// requestTime reads X-Amz-Date, falling back to Date.
func requestTime(r *http.Request) (time.Time, string, *Error) {
	if s := r.Header.Get("X-Amz-Date"); s != "" {
		t, err := time.Parse(amzDateFormat, s)
		if err != nil {
			return time.Time{}, "", errorf(403, "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header")
		}
		return t, s, nil
	}
	if s := r.Header.Get("Date"); s != "" {
		t, err := parseHTTPDate(s)
		if err != nil {
			return time.Time{}, "", errorf(403, "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header")
		}
		return t.UTC(), t.UTC().Format(amzDateFormat), nil
	}
	return time.Time{}, "", errorf(403, "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header")
}

func (v *Verifier) verifyHeader(r *http.Request) (*Auth, error) {
	p, aerr := parseAuthorization(r.Header.Get("Authorization"))
	if aerr != nil {
		return nil, aerr
	}
	t, amzDate, terr := requestTime(r)
	if terr != nil {
		return nil, terr
	}
	if d := v.now().Sub(t); d > MaxSkew || d < -MaxSkew {
		return nil, errorf(403, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.")
	}
	if amzDate[:8] != p.date {
		return nil, errorf(400, "AuthorizationHeaderMalformed",
			"The authorization header is malformed; Invalid credential date. Date is not the same as X-Amz-Date.")
	}
	if !containsHost(p.signedHeaders) {
		return nil, errorf(400, "AuthorizationHeaderMalformed", "The authorization header is malformed; host must be signed.")
	}

	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		if p.service == "s3" {
			return nil, errorf(400, "InvalidRequest", "Missing required header for this request: x-amz-content-sha256")
		}
		// Other services don't send the header; hash the (small) body ourselves.
		body, err := v.bufferBody(r)
		if err != nil {
			return nil, err
		}
		payload = hexSHA256(body)
	} else if !validPayloadHash(payload) {
		return nil, errorf(400, "InvalidArgument", "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER or a valid sha256 value.")
	}

	secret, err := v.secret(r.Context(), p.accessKey)
	if err != nil {
		return nil, err
	}
	scope := p.date + "/" + p.region + "/" + p.service + "/aws4_request"
	creq := CanonicalRequest(r, p.service, p.signedHeaders, r.URL.RawQuery, "", payload)
	key := SigningKey(secret, p.date, p.region, p.service)
	want := hex.EncodeToString(hmacSHA256(key, StringToSign(amzDate, scope, creq)))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(p.signature))) {
		return nil, errorf(403, "SignatureDoesNotMatch",
			"The request signature we calculated does not match the signature you provided. Check your key and signing method.")
	}

	auth := &Auth{
		AccessKey: p.accessKey, Date: t, Region: p.region, Service: p.service,
		PayloadHash: payload, DecodedLength: -1,
	}
	switch payload {
	case UnsignedPayload:
	case StreamingSigned, StreamingSignedTrailer, StreamingUnsigned:
		n, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
		if err != nil || n < 0 {
			return nil, errorf(411, "MissingContentLength", "You must provide the Content-Length HTTP header.")
		}
		auth.Streaming, auth.DecodedLength = true, n
		dec := &chunkedReader{
			r: newLineReader(r.Body), body: r.Body, remainingDecoded: n,
			signed:  payload != StreamingUnsigned,
			trailer: payload != StreamingSigned,
			key:     key, amzDate: amzDate, scope: scope, prevSig: strings.ToLower(p.signature),
		}
		if r.Trailer == nil {
			r.Trailer = http.Header{}
		}
		dec.trailers = r.Trailer
		r.Body = dec
	default:
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &hashCheckReader{r: r.Body, h: sha256.New(), want: payload}
		} else if payload != emptySHA256 {
			return nil, errorf(400, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.")
		}
	}
	return auth, nil
}

func (v *Verifier) verifyPresigned(r *http.Request) (*Auth, error) {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != Algorithm {
		return nil, errorf(400, "AuthorizationQueryParametersError", "X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\"")
	}
	for _, k := range []string{"X-Amz-Credential", "X-Amz-Signature", "X-Amz-SignedHeaders", "X-Amz-Date", "X-Amz-Expires"} {
		if q.Get(k) == "" {
			return nil, errorf(400, "AuthorizationQueryParametersError",
				"Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.")
		}
	}
	ak, date, region, service, cerr := parseCredential(q.Get("X-Amz-Credential"))
	if cerr != nil {
		cerr.Code = "AuthorizationQueryParametersError"
		return nil, cerr
	}
	amzDate := q.Get("X-Amz-Date")
	t, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		return nil, errorf(400, "AuthorizationQueryParametersError", "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"")
	}
	expires, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || expires < 0 {
		return nil, errorf(400, "AuthorizationQueryParametersError", "X-Amz-Expires should be a number")
	}
	if expires > 604800 {
		return nil, errorf(400, "AuthorizationQueryParametersError", "X-Amz-Expires must be less than a week (in seconds) that is 604800")
	}
	now := v.now()
	if t.Sub(now) > MaxSkew {
		return nil, errorf(403, "AccessDenied", "Request is not valid yet")
	}
	if now.After(t.Add(time.Duration(expires) * time.Second)) {
		return nil, errorf(403, "AccessDenied", "Request has expired")
	}
	signed := strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	if !containsHost(signed) {
		return nil, errorf(400, "AuthorizationQueryParametersError", "Query-string authentication requires the host header to be signed.")
	}
	payload := emptySHA256
	if service == "s3" {
		payload = UnsignedPayload
		if h := r.Header.Get("X-Amz-Content-Sha256"); h != "" && contains(signed, "x-amz-content-sha256") {
			payload = h
		}
	}
	secret, serr := v.secret(r.Context(), ak)
	if serr != nil {
		return nil, serr
	}
	scope := date + "/" + region + "/" + service + "/aws4_request"
	creq := CanonicalRequest(r, service, signed, r.URL.RawQuery, "X-Amz-Signature", payload)
	key := SigningKey(secret, date, region, service)
	want := hex.EncodeToString(hmacSHA256(key, StringToSign(amzDate, scope, creq)))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(q.Get("X-Amz-Signature")))) {
		return nil, errorf(403, "SignatureDoesNotMatch",
			"The request signature we calculated does not match the signature you provided. Check your key and signing method.")
	}
	return &Auth{
		AccessKey: ak, Date: t, Region: region, Service: service, Presigned: true,
		PayloadHash: payload, DecodedLength: -1,
	}, nil
}

func (v *Verifier) bufferBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	limit := v.MaxBufferedBody
	if limit <= 0 {
		limit = 16 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errorf(413, "RequestEntityTooLarge", "Request body is too large to verify without X-Amz-Content-Sha256.")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func validPayloadHash(s string) bool {
	switch s {
	case UnsignedPayload, StreamingSigned, StreamingSignedTrailer, StreamingUnsigned:
		return true
	}
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func containsHost(signed []string) bool { return contains(signed, "host") }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// hashCheckReader verifies a declared SHA-256 when the body hits EOF.
type hashCheckReader struct {
	r    io.ReadCloser
	h    hash.Hash
	want string
	done bool
}

func (h *hashCheckReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.h.Write(p[:n])
	if err == io.EOF && !h.done {
		h.done = true
		if hex.EncodeToString(h.h.Sum(nil)) != strings.ToLower(h.want) {
			return n, errorf(400, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.")
		}
	}
	return n, err
}

func (h *hashCheckReader) Close() error { return h.r.Close() }

// parseHTTPDate accepts the HTTP date formats plus RFC 1123 with a numeric
// zone ("Fri, 24 May 2013 00:00:00 -0000"), which botocore sends in Date.
func parseHTTPDate(s string) (time.Time, error) {
	if t, err := http.ParseTime(s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC1123Z, s)
}
