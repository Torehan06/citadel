package lambda

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Function URLs: /_citadel/lambda/url/<url id>/<path>. The request becomes
// an API Gateway payload format 2.0 event, and the function's answer (a
// {statusCode, headers, body} object, or any JSON) becomes the response.

func (h *Handler) serveURL(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/_citadel/lambda/url/")
	id, path, _ := strings.Cut(rest, "/")
	path = "/" + path
	forbidden := func() { writeJSON(w, 403, map[string]string{"Message": "Forbidden"}) }

	var account, region, name, qualifier, cfg string
	err := h.st.DB().QueryRowContext(r.Context(), `SELECT f.account, f.region, f.name, s.qualifier, s.config
		FROM lambda_settings s JOIN lambda_functions f ON f.id = s.function_id
		WHERE s.kind = 'url' AND json_extract(s.config, '$.URLID') = ?`, id).Scan(&account, &region, &name, &qualifier, &cfg)
	if err != nil {
		forbidden()
		return
	}
	var u urlRecord
	if err := json.Unmarshal([]byte(cfg), &u); err != nil {
		forbidden()
		return
	}
	caller := "anonymous"
	if u.AuthType == "AWS_IAM" {
		auth, err := h.auth.Verify(r)
		if err != nil || auth.Anonymous {
			forbidden()
			return
		}
		_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
		if err != nil || who.Account.ID != account {
			forbidden()
			return
		}
		c := &call{ctx: r.Context(), account: account, region: region, who: &who}
		if h.authorize(c, "InvokeFunctionUrl", functionARN(region, account, name)) != nil {
			forbidden()
			return
		}
		caller = who.Account.ID
	} else if !publicURL(h, r, account, region, name) {
		forbidden()
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxResponseSize+1))
	if err != nil || len(body) > maxResponseSize {
		writeJSON(w, 413, map[string]string{"Message": "Request must be smaller than 6291456 bytes for the InvokeFunction operation"})
		return
	}
	requestID := newRequestID()
	headers := map[string]string{}
	for k, v := range r.Header {
		if k == "Cookie" {
			continue
		}
		headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	var cookies []string
	for _, c := range r.Cookies() {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	query := map[string]string{}
	for k, v := range r.URL.Query() {
		query[k] = strings.Join(v, ",")
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := h.now()
	event := map[string]any{
		"version": "2.0", "routeKey": "$default", "rawPath": path, "rawQueryString": r.URL.RawQuery,
		"headers": headers,
		"requestContext": map[string]any{
			"accountId": caller, "apiId": id, "domainName": r.Host, "domainPrefix": id,
			"http":      map[string]any{"method": r.Method, "path": path, "protocol": r.Proto, "sourceIp": ip, "userAgent": r.UserAgent()},
			"requestId": requestID, "routeKey": "$default", "stage": "$default",
			"time": now.UTC().Format("02/Jan/2006:15:04:05 -0700"), "timeEpoch": now.UnixMilli(),
		},
		"isBase64Encoded": false,
	}
	if len(cookies) > 0 {
		event["cookies"] = cookies
	}
	if len(query) > 0 {
		event["queryStringParameters"] = query
	}
	if len(body) > 0 {
		if utf8.Valid(body) {
			event["body"] = string(body)
		} else {
			event["body"] = base64.StdEncoding.EncodeToString(body)
			event["isBase64Encoded"] = true
		}
	}
	payload, _ := json.Marshal(event)
	qualified := name
	if qualifier != "" {
		qualified += ":" + qualifier
	}
	res, err := h.Invoke(r.Context(), account, region, qualified, payload)
	var th *throttled
	switch {
	case errors.As(err, &th):
		writeJSON(w, 429, map[string]string{"Message": "Rate Exceeded."})
		return
	case err != nil || res.FunctionError != "":
		writeJSON(w, 502, map[string]string{"Message": "Internal Server Error"})
		return
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	var out struct {
		StatusCode      *int              `json:"statusCode"`
		Headers         map[string]string `json:"headers"`
		Body            *string           `json:"body"`
		IsBase64Encoded bool              `json:"isBase64Encoded"`
		Cookies         []string          `json:"cookies"`
	}
	if json.Unmarshal(res.Payload, &out) != nil || out.StatusCode == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(res.Payload)
		return
	}
	for k, v := range out.Headers {
		w.Header().Set(k, v)
	}
	for _, c := range out.Cookies {
		w.Header().Add("Set-Cookie", c)
	}
	respBody := []byte{}
	if out.Body != nil {
		respBody = []byte(*out.Body)
		if out.IsBase64Encoded {
			if b, err := base64.StdEncoding.DecodeString(*out.Body); err == nil {
				respBody = b
			}
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(*out.StatusCode)
	_, _ = w.Write(respBody)
}

// publicURL reports whether a function's resource policy lets anyone invoke
// its URL, as AuthType NONE requires.
func publicURL(h *Handler, r *http.Request, account, region, name string) bool {
	fn, err := loadFunctionByName(r.Context(), h.st.DB(), account, region, name)
	if err != nil || fn == nil {
		return false
	}
	for _, doc := range functionPolicies(fn) {
		for _, s := range doc.Statement {
			action, _ := s["Action"].(string)
			p, _ := s["Principal"].(map[string]any)
			if s["Effect"] == "Allow" && (action == "lambda:InvokeFunctionUrl" || action == "lambda:*" || action == "*") && p["AWS"] == "*" {
				return true
			}
		}
	}
	return false
}
