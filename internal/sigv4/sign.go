package sigv4

import (
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Credentials sign requests. SessionToken is set for temporary credentials.
type Credentials struct {
	AccessKey, SecretKey, SessionToken string
}

// Sign adds a SigV4 Authorization header to r, the way SDKs do: it signs
// host, x-amz-date, x-amz-content-sha256 (the hash of body), the security
// token when there is one, and content-type when set. body must be the
// exact bytes r will send. Citadel's own clients (integration tests, the
// region tooling, later the canaries) use it; the server never signs.
func Sign(r *http.Request, c Credentials, region, service string, body []byte, now time.Time) {
	amzDate := now.UTC().Format(amzDateFormat)
	date := amzDate[:8]
	payload := hexSHA256(body)
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payload)
	if c.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if c.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	if r.Header.Get("Content-Type") != "" {
		signed = append(signed, "content-type")
	}
	if r.Header.Get("X-Amz-Target") != "" {
		signed = append(signed, "x-amz-target")
	}
	sort.Strings(signed)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	creq := CanonicalRequest(r, service, signed, r.URL.RawQuery, "", payload)
	sig := hex.EncodeToString(hmacSHA256(SigningKey(c.SecretKey, date, region, service), StringToSign(amzDate, scope, creq)))
	r.Header.Set("Authorization", Algorithm+" Credential="+c.AccessKey+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}
