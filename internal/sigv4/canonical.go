// Package sigv4 verifies AWS Signature Version 4: the Authorization header,
// presigned query strings, and aws-chunked streaming bodies with their
// per-chunk signatures and trailing checksums.
//
// Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	Algorithm = "AWS4-HMAC-SHA256"

	// Payload hash values a client can put in X-Amz-Content-Sha256.
	UnsignedPayload        = "UNSIGNED-PAYLOAD"
	StreamingSigned        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	StreamingSignedTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	StreamingUnsigned      = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

	amzDateFormat = "20060102T150405Z"
	emptySHA256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// uriEncode is AWS's UriEncode: every byte except the unreserved characters
// A-Z a-z 0-9 - . _ ~ becomes %XX (uppercase hex). '/' is kept when
// keepSlash is set (paths) and encoded otherwise (query keys and values).
func uriEncode(s string, keepSlash bool) string {
	const hexdig = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexdig[c>>4])
			b.WriteByte(hexdig[c&15])
		}
	}
	return b.String()
}

// rawPath returns the request path exactly as the client sent it.
func rawPath(r *http.Request) string {
	p := r.RequestURI
	if p == "" { // client-side request (tests, signing)
		return r.URL.EscapedPath()
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		if u, err := url.Parse(p); err == nil {
			return u.EscapedPath()
		}
	}
	return p
}

// canonicalURI encodes the path the way the signer did. S3 signs the path
// encoded once; every other service encodes the (already encoded) path a
// second time.
func canonicalURI(r *http.Request, service string) string {
	p := rawPath(r)
	if p == "" {
		return "/"
	}
	if service == "s3" {
		if dec, err := url.PathUnescape(p); err == nil {
			p = dec
		}
	}
	return uriEncode(p, true)
}

// canonicalQuery sorts and re-encodes the query string, dropping skip (the
// signature itself, for presigned URLs).
func canonicalQuery(rawQuery, skip string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		if k == skip {
			continue
		}
		pairs = append(pairs, kv{uriEncode(k, false), uriEncode(v, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// headerValue returns the value a signer saw for a lowercase header name.
// Go moves Host and Transfer-Encoding out of r.Header, so fetch them back.
func headerValue(r *http.Request, name string) string {
	var vals []string
	switch name {
	case "host":
		if r.Host != "" {
			vals = []string{r.Host}
		} else {
			vals = []string{r.URL.Host}
		}
	case "transfer-encoding":
		vals = r.TransferEncoding
		if len(vals) == 0 {
			vals = r.Header.Values("Transfer-Encoding")
		}
	default:
		vals = r.Header.Values(name)
		if len(vals) == 0 && name == "content-length" && r.ContentLength >= 0 && r.Body != nil && r.Body != http.NoBody {
			vals = []string{strconv.FormatInt(r.ContentLength, 10)}
		}
	}
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(out, ",")
}

func canonicalHeaders(r *http.Request, signed []string) string {
	var b strings.Builder
	for _, h := range signed {
		b.WriteString(h)
		b.WriteByte(':')
		b.WriteString(headerValue(r, h))
		b.WriteByte('\n')
	}
	return b.String()
}

// CanonicalRequest builds the canonical request string (step 1 of SigV4).
func CanonicalRequest(r *http.Request, service string, signedHeaders []string, rawQuery, skipQuery, payloadHash string) string {
	return strings.Join([]string{
		r.Method,
		canonicalURI(r, service),
		canonicalQuery(rawQuery, skipQuery),
		canonicalHeaders(r, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
}

// StringToSign builds step 2 of SigV4.
func StringToSign(amzDate, scope, canonicalRequest string) string {
	return Algorithm + "\n" + amzDate + "\n" + scope + "\n" + hexSHA256([]byte(canonicalRequest))
}

// SigningKey derives kSigning = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request").
func SigningKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
