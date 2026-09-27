package region

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Region-to-region requests carry three headers: the calling region, a unix
// timestamp, and HMAC-SHA256(key, method \n request-URI \n time \n region).
// The timestamp bounds replays to MaxSkew; the requests themselves are reads.
const (
	hdrRegion    = "X-Citadel-Region"
	hdrTime      = "X-Citadel-Time"
	hdrSignature = "X-Citadel-Signature"

	MaxSkew = 5 * time.Minute
)

func mac(key []byte, method, uri, ts, region string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(method + "\n" + uri + "\n" + ts + "\n" + region))
	return hex.EncodeToString(m.Sum(nil))
}

// sign authenticates a request from region self.
func (r *Registry) sign(req *http.Request, self string, now time.Time) {
	ts := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set(hdrRegion, self)
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrSignature, mac(r.key, req.Method, req.URL.RequestURI(), ts, self))
}

var errUnauthenticated = errors.New("region request not authenticated")

// verify checks a region request and returns the calling region.
func (r *Registry) verify(req *http.Request, now time.Time) (string, error) {
	from := req.Header.Get(hdrRegion)
	if _, ok := r.Get(from); !ok || len(r.key) == 0 {
		return "", errUnauthenticated
	}
	ts := req.Header.Get(hdrTime)
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", errUnauthenticated
	}
	if d := now.Sub(time.Unix(sec, 0)); d > MaxSkew || d < -MaxSkew {
		return "", errUnauthenticated
	}
	want := mac(r.key, req.Method, req.URL.RequestURI(), ts, from)
	if !hmac.Equal([]byte(want), []byte(req.Header.Get(hdrSignature))) {
		return "", errUnauthenticated
	}
	return from, nil
}
