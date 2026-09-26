// Package iam implements IAM and STS over the query protocol, and the policy
// evaluation that authorizes requests to the other services.
package iam

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"citadel/internal/sigv4"
	"citadel/internal/store"
)

const (
	iamXMLNS = "https://iam.amazonaws.com/doc/2010-05-08/"
	stsXMLNS = "https://sts.amazonaws.com/doc/2011-06-15/"
)

// Handler serves IAM; Handler.STS serves STS. Both share one store.
type Handler struct {
	st     *store.Store
	auth   *sigv4.Verifier
	region string
	log    *slog.Logger
	now    func() time.Time
}

func New(st *store.Store, auth *sigv4.Verifier, region string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{st: st, auth: auth, region: region, log: logger, now: time.Now}
}

// call is one authenticated IAM or STS request.
type call struct {
	ctx     context.Context
	tx      *store.Tx
	h       *Handler
	f       form
	account string
	who     store.Principal
	region  string
	now     time.Time
}

type opFunc func(c *call) (obj, error)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.serve(w, r, false) }

// STS returns the handler for the STS endpoint.
func (h *Handler) STS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, true) })
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, sts bool) {
	reqID := w.Header().Get("x-amz-request-id")
	xmlns := iamXMLNS
	if sts {
		xmlns = stsXMLNS
	}
	op, out, err := h.handle(r, sts)
	if err != nil {
		var e *apiError
		if !errors.As(err, &e) {
			var se *sigv4.Error
			if errors.As(err, &se) {
				e = &apiError{se.Status, se.Code, se.Message}
			} else {
				h.log.Error("iam internal error", "op", op, "err", err)
				e = &apiError{500, "ServiceFailure", "Internal server error"}
			}
		}
		writeError(w, reqID, e)
		return
	}
	writeResult(w, xmlns, op, reqID, out)
}

func (h *Handler) handle(r *http.Request, sts bool) (string, obj, error) {
	auth, err := h.auth.Verify(r)
	if err != nil {
		return "", nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return "", nil, err
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return "", nil, newErr(400, "MalformedQueryString", "Invalid form encoding.")
	}
	for k, v := range r.URL.Query() {
		if _, ok := vals[k]; !ok {
			vals[k] = v
		}
	}
	f := form(vals)
	op := f.str("Action")
	if auth.Anonymous {
		return op, nil, newErr(403, "MissingAuthenticationToken", "Request is missing Authentication Token")
	}
	_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return op, nil, newErr(403, "InvalidClientTokenId", "The security token included in the request is invalid.")
	}
	ops := iamOps
	if sts {
		ops = stsOps
	}
	fn, ok := ops[op]
	if !ok {
		if op == "" {
			return op, nil, newErr(400, "MissingAction", "Missing Action")
		}
		svc := "IAM"
		if sts {
			svc = "STS"
		}
		return op, nil, newErr(501, "NotImplemented", "citadel: %s %s is not implemented yet", svc, op)
	}
	c := &call{ctx: r.Context(), h: h, f: f, account: who.Account.ID, who: who, region: auth.Region, now: h.now().UTC().Truncate(time.Second)}
	if c.region == "" {
		c.region = h.region
	}
	// IAM and STS calls are not yet gated by identity policies: any valid
	// credential may manage its own account (see PROGRESS.md, M5).
	var out obj
	err = h.st.Update(r.Context(), func(tx *store.Tx) error {
		c.tx = tx
		var err error
		out, err = fn(c)
		if err != nil {
			return err
		}
		return tx.Change("iam", op, c.account, nil)
	})
	return op, out, err
}

// Reset wipes every IAM entity and every non-bootstrap credential.
func (h *Handler) Reset() {
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.Exec(`DELETE FROM iam_entities`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM access_keys WHERE kind <> 'root'`); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE access_keys SET last_used=0, last_service='', last_region=''`); err != nil {
			return err
		}
		return tx.Change("iam", "Reset", "", nil)
	})
	if err != nil {
		h.log.Error("reset iam", "err", err)
	}
}

const idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomID returns prefix followed by n random uppercase letters and digits,
// the shape of IAM unique IDs (AIDA…, AROA…) and access key IDs.
func randomID(prefix string, n int) string {
	b := make([]byte, n)
	for i := range b {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(idAlphabet))))
		b[i] = idAlphabet[j.Int64()]
	}
	return prefix + string(b)
}

func randomSecret(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[j.Int64()]
	}
	return string(b)
}

func (c *call) arn(resource string) string {
	return "arn:aws:iam::" + c.account + ":" + resource
}
