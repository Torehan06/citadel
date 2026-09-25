package s3

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
)

// CORS: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
// The bucket's CORS configuration decides two things: the answer to browser
// preflight requests (OPTIONS), and the Access-Control-* headers added to
// ordinary requests that carry an Origin header (errors included).

type corsRule struct {
	ID             string   `xml:"ID,omitempty" json:"id,omitempty"`
	AllowedHeaders []string `xml:"AllowedHeader" json:"allowed_headers,omitempty"`
	AllowedMethods []string `xml:"AllowedMethod" json:"allowed_methods"`
	AllowedOrigins []string `xml:"AllowedOrigin" json:"allowed_origins"`
	ExposeHeaders  []string `xml:"ExposeHeader" json:"expose_headers,omitempty"`
	MaxAgeSeconds  *int     `xml:"MaxAgeSeconds,omitempty" json:"max_age,omitempty"`
}

type corsConfiguration struct {
	XMLName xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CORSConfiguration"`
	Rules   []corsRule `xml:"CORSRule"`
}

type corsConfigurationIn struct {
	Rules []corsRule `xml:"CORSRule"`
}

func parseCORS(body []byte) ([]corsRule, error) {
	var in corsConfigurationIn
	if err := xml.Unmarshal(body, &in); err != nil || len(in.Rules) == 0 || len(in.Rules) > 100 {
		return nil, errMalformedXML()
	}
	for _, r := range in.Rules {
		if len(r.AllowedMethods) == 0 || len(r.AllowedOrigins) == 0 {
			return nil, errMalformedXML()
		}
		for _, m := range r.AllowedMethods {
			switch m {
			case "GET", "PUT", "HEAD", "POST", "DELETE":
			default:
				return nil, errf(400, "InvalidRequest", "Found unsupported HTTP method in CORS config. Unsupported method is %s", m)
			}
		}
		for _, o := range r.AllowedOrigins {
			if strings.Count(o, "*") > 1 {
				return nil, errf(400, "InvalidRequest", "AllowedOrigin %q can not have more than one wildcard.", o)
			}
		}
		for _, hd := range r.AllowedHeaders {
			if strings.Count(hd, "*") > 1 {
				return nil, errf(400, "InvalidRequest", "AllowedHeader %q can not have more than one wildcard.", hd)
			}
		}
	}
	return in.Rules, nil
}

func loadCORS(s string) []corsRule {
	if s == "" {
		return nil
	}
	var rules []corsRule
	_ = json.Unmarshal([]byte(s), &rules)
	return rules
}

// match finds the first rule allowing origin and method (and, for
// preflights, every requested header).
func matchCORS(rules []corsRule, origin, method string, headers []string) *corsRule {
	for i := range rules {
		r := &rules[i]
		if !anyGlob(r.AllowedOrigins, origin, false) || !containsString(r.AllowedMethods, method) {
			continue
		}
		ok := true
		for _, h := range headers {
			if !anyGlob(r.AllowedHeaders, h, true) {
				ok = false
				break
			}
		}
		if ok {
			return r
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// setCORSHeaders writes the Access-Control-* headers for a matched rule.
func setCORSHeaders(w http.ResponseWriter, r *corsRule, origin string, reqHeaders []string) {
	h := w.Header()
	if containsString(r.AllowedOrigins, "*") {
		h.Set("Access-Control-Allow-Origin", "*")
	} else {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	h.Set("Access-Control-Allow-Methods", strings.Join(r.AllowedMethods, ", "))
	if len(reqHeaders) > 0 {
		h.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
	}
	if len(r.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(r.ExposeHeaders, ", "))
	}
	if r.MaxAgeSeconds != nil {
		h.Set("Access-Control-Max-Age", strconv.Itoa(*r.MaxAgeSeconds))
	}
	h.Add("Vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method")
}

func requestedHeaders(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("Access-Control-Request-Headers") {
		for _, h := range strings.Split(v, ",") {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				out = append(out, h)
			}
		}
	}
	return out
}

// applyCORS adds CORS headers to a normal request that carries Origin.
func (h *Handler) applyCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	origin := r.Header.Get("Origin")
	if origin == "" || bucket == "" {
		return
	}
	var raw string
	if err := h.st.DB().QueryRowContext(r.Context(), `SELECT cors FROM s3_buckets WHERE name = ?`, bucket).Scan(&raw); err != nil {
		return
	}
	method := r.Method
	if m := r.Header.Get("Access-Control-Request-Method"); m != "" {
		method = m
	}
	if rule := matchCORS(loadCORS(raw), origin, method, nil); rule != nil {
		setCORSHeaders(w, rule, origin, nil)
	}
}

// preflight answers a browser's OPTIONS request. Preflights are never
// signed, so this runs before authentication.
func (h *Handler) preflight(w http.ResponseWriter, r *http.Request, bucket string) error {
	origin := r.Header.Get("Origin")
	method := r.Header.Get("Access-Control-Request-Method")
	if origin == "" {
		return errf(400, "BadRequest", "Insufficient information. Origin request header needed.")
	}
	if method == "" {
		return errf(400, "BadRequest", "Invalid Access-Control-Request-Method header.")
	}
	b, err := h.loadBucket(r.Context(), bucket)
	if err != nil {
		return err
	}
	rules := loadCORS(b.CORS)
	if len(rules) == 0 {
		return errf(403, "AccessForbidden", "CORSResponse: CORS is not enabled for this bucket.")
	}
	reqHeaders := requestedHeaders(r)
	rule := matchCORS(rules, origin, method, reqHeaders)
	if rule == nil {
		return errf(403, "AccessForbidden", "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.")
	}
	setCORSHeaders(w, rule, origin, reqHeaders)
	w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) getBucketCORS(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketCORS", "")
	if err != nil {
		return err
	}
	rules := loadCORS(b.CORS)
	if len(rules) == 0 {
		return &Error{Status: 404, Code: "NoSuchCORSConfiguration", Message: "The CORS configuration does not exist", Bucket: req.bucket}
	}
	writeXML(req.w, http.StatusOK, corsConfiguration{Rules: rules})
	return nil
}

func (h *Handler) putBucketCORS(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketCORS", ""); err != nil {
		return err
	}
	body, err := readSmallBody(req, 64<<10, false)
	if err != nil {
		return err
	}
	rules, err := parseCORS(body)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(rules)
	if err := h.setBucketColumn(req, "cors", string(raw), "PutBucketCors"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) deleteBucketCORS(req *request) error {
	if _, err := h.bucketAccess(req, "s3:PutBucketCORS", ""); err != nil {
		return err
	}
	if err := h.setBucketColumn(req, "cors", "", "DeleteBucketCors"); err != nil {
		return err
	}
	req.w.WriteHeader(http.StatusNoContent)
	return nil
}
