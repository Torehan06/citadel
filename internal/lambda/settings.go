package lambda

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"citadel/internal/store"
)

// Per-function settings: the resource policy (AddPermission), tags, reserved
// concurrency, event invoke configs, function URL configs and code signing.

// ---- resource policy ----------------------------------------------------------------

type policyDoc struct {
	Version   string           `json:"Version"`
	Id        string           `json:"Id"`
	Statement []map[string]any `json:"Statement"`
}

// policies are stored per qualifier ("" is the unqualified function).
func functionPolicies(fn *function) map[string]*policyDoc {
	out := map[string]*policyDoc{}
	if fn.Policy != "" {
		_ = json.Unmarshal([]byte(fn.Policy), &out)
	}
	return out
}

func savePolicies(c *call, tx *store.Tx, fn *function, p map[string]*policyDoc) error {
	for q, d := range p {
		if len(d.Statement) == 0 {
			delete(p, q)
		}
	}
	s := ""
	if len(p) > 0 {
		b, _ := json.Marshal(p)
		s = string(b)
	}
	_, err := tx.ExecContext(c.ctx, `UPDATE lambda_functions SET policy=? WHERE id=?`, s, fn.ID)
	return err
}

func (h *Handler) addPermission(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "AddPermission", c.functionARN(f.name)); err != nil {
		return err
	}
	var req struct {
		StatementId, Action, Principal, SourceArn, SourceAccount, EventSourceToken string
		PrincipalOrgID, FunctionUrlAuthType, RevisionId                            string
	}
	if err := c.decode(&req, 1<<20); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9-_.]{1,100}$`).MatchString(req.StatementId) {
		return validation(req.StatementId, "statementId", `Member must satisfy regular expression pattern: ([a-zA-Z0-9-_.]+)`)
	}
	if !regexp.MustCompile(`^(lambda:[*]|lambda:[a-zA-Z]+|[*])$`).MatchString(req.Action) {
		return validation(req.Action, "action", `Member must satisfy regular expression pattern: (lambda:[*]|lambda:[a-zA-Z]+|[*])`)
	}
	if req.Principal == "" {
		return validation("null", "principal", "Member must not be null")
	}
	var statement map[string]any
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		if _, _, err := c.resolve(tx, fn, f); err != nil {
			return err
		}
		pols := functionPolicies(fn)
		doc := pols[f.qualifier]
		if doc == nil {
			doc = &policyDoc{Version: "2012-10-17", Id: "default"}
			pols[f.qualifier] = doc
		}
		for _, s := range doc.Statement {
			if s["Sid"] == req.StatementId {
				return conflict("The statement id (%s) provided already exists. Please provide a new statement id, or remove the existing statement.", req.StatementId)
			}
		}
		principal := map[string]any{"AWS": req.Principal}
		switch {
		case req.Principal == "*":
			principal = map[string]any{"AWS": "*"}
		case strings.HasSuffix(req.Principal, ".amazonaws.com") || strings.HasSuffix(req.Principal, ".amazonaws.com.cn"):
			principal = map[string]any{"Service": req.Principal}
		case isDigits(req.Principal) && len(req.Principal) == 12:
			principal = map[string]any{"AWS": "arn:aws:iam::" + req.Principal + ":root"}
		}
		statement = map[string]any{"Sid": req.StatementId, "Effect": "Allow", "Principal": principal,
			"Action": req.Action, "Resource": c.refARN(fnRef{name: fn.Name, qualifier: f.qualifier})}
		cond := map[string]any{}
		if req.SourceArn != "" {
			cond["ArnLike"] = map[string]string{"AWS:SourceArn": req.SourceArn}
		}
		eq := map[string]string{}
		if req.SourceAccount != "" {
			eq["AWS:SourceAccount"] = req.SourceAccount
		}
		if req.PrincipalOrgID != "" {
			eq["aws:PrincipalOrgID"] = req.PrincipalOrgID
		}
		if req.EventSourceToken != "" {
			eq["lambda:EventSourceToken"] = req.EventSourceToken
		}
		if req.FunctionUrlAuthType != "" {
			eq["lambda:FunctionUrlAuthType"] = req.FunctionUrlAuthType
		}
		if len(eq) > 0 {
			cond["StringEquals"] = eq
		}
		if len(cond) > 0 {
			statement["Condition"] = cond
		}
		doc.Statement = append(doc.Statement, statement)
		if err := savePolicies(c, tx, fn, pols); err != nil {
			return err
		}
		return tx.Change("lambda", "AddPermission", c.refARN(f), map[string]string{"sid": req.StatementId})
	})
	if err != nil {
		return err
	}
	b, _ := json.Marshal(statement)
	writeJSON(c.w, 201, map[string]string{"Statement": string(b)})
	return nil
}

func (h *Handler) getPolicy(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "GetPolicy", c.functionARN(f.name)); err != nil {
		return err
	}
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	if _, _, err := c.resolve(h.st.DB(), fn, f); err != nil {
		return err
	}
	doc := functionPolicies(fn)[f.qualifier]
	if doc == nil {
		return notFound("The resource you requested does not exist.")
	}
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	writeJSON(c.w, 200, map[string]string{"Policy": string(b), "RevisionId": revisionFrom(sum[:])})
	return nil
}

func revisionFrom(b []byte) string {
	h := hex.EncodeToString(b[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (h *Handler) removePermission(c *call, raw, sid string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "RemovePermission", c.functionARN(f.name)); err != nil {
		return err
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		pols := functionPolicies(fn)
		doc := pols[f.qualifier]
		if doc == nil {
			return notFound("No policy is associated with the given resource.")
		}
		kept := doc.Statement[:0]
		for _, s := range doc.Statement {
			if s["Sid"] != sid {
				kept = append(kept, s)
			}
		}
		if len(kept) == len(doc.Statement) {
			return notFound("Statement %s is not found in resource policy.", sid)
		}
		doc.Statement = kept
		if err := savePolicies(c, tx, fn, pols); err != nil {
			return err
		}
		return tx.Change("lambda", "RemovePermission", c.refARN(f), map[string]string{"sid": sid})
	})
	if err != nil {
		return err
	}
	writeJSON(c.w, 204, nil)
	return nil
}

// ---- tags ---------------------------------------------------------------------------

var mappingARNRE = regexp.MustCompile(`^arn:aws[a-zA-Z-]*:lambda:([a-z0-9-]+):(\d{12}):event-source-mapping:([0-9a-f-]+)$`)

func (h *Handler) tags(c *call, arn string) error {
	action := map[string]string{http.MethodGet: "ListTags", http.MethodPost: "TagResource", http.MethodDelete: "UntagResource"}[c.r.Method]
	if action == "" {
		return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
	}
	if err := h.authorize(c, action, arn); err != nil {
		return err
	}
	var req struct{ Tags map[string]string }
	if c.r.Method == http.MethodPost {
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
	}
	var out map[string]string
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		var table, key string
		var tags map[string]string
		if m := mappingARNRE.FindStringSubmatch(arn); m != nil {
			if m[1] != c.region || m[2] != c.account {
				return notFound("The resource you requested does not exist.")
			}
			var s string
			err := tx.QueryRowContext(c.ctx, `SELECT tags FROM lambda_mappings WHERE uuid=? AND account=? AND region=?`, m[3], c.account, c.region).Scan(&s)
			if errors.Is(err, sql.ErrNoRows) {
				return notFound("The resource you requested does not exist.")
			}
			if err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(s), &tags); err != nil {
				return err
			}
			table, key = `UPDATE lambda_mappings SET tags=? WHERE uuid=?`, m[3]
		} else {
			f, err := parseRef(arn)
			if err != nil || !strings.HasPrefix(arn, "arn:") {
				return invalidParam("The resource ARN %s is not valid.", arn)
			}
			if f.qualifier != "" {
				return invalidParam("Tags are not supported for function versions or aliases: %s", arn)
			}
			fn, err := c.loadFunction(tx, f)
			if err != nil {
				return err
			}
			tags = fn.Tags
			table, key = `UPDATE lambda_functions SET tags=? WHERE id=?`, strconv.FormatInt(fn.ID, 10)
		}
		if tags == nil {
			tags = map[string]string{}
		}
		switch c.r.Method {
		case http.MethodGet:
			out = tags
			return nil
		case http.MethodPost:
			merged := map[string]string{}
			for k, v := range tags {
				merged[k] = v
			}
			for k, v := range req.Tags {
				merged[k] = v
			}
			if err := validateTags(merged); err != nil {
				return err
			}
			tags = merged
		case http.MethodDelete:
			for _, k := range c.r.URL.Query()["tagKeys"] {
				delete(tags, k)
			}
		}
		b, _ := json.Marshal(tags)
		if _, err := tx.ExecContext(c.ctx, table, string(b), key); err != nil {
			return err
		}
		return tx.Change("lambda", action, arn, nil)
	})
	if err != nil {
		return err
	}
	if c.r.Method == http.MethodGet {
		writeJSON(c.w, 200, map[string]any{"Tags": out})
		return nil
	}
	writeJSON(c.w, 204, nil)
	return nil
}

// ---- reserved concurrency --------------------------------------------------------------

func (h *Handler) concurrency(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	f.qualifier = ""
	switch c.r.Method {
	case http.MethodGet:
		if err := h.authorize(c, "GetFunctionConcurrency", c.functionARN(f.name)); err != nil {
			return err
		}
		fn, err := c.loadFunction(h.st.DB(), f)
		if err != nil {
			return err
		}
		out := map[string]any{}
		if fn.Concurrency.Valid {
			out["ReservedConcurrentExecutions"] = fn.Concurrency.Int64
		}
		writeJSON(c.w, 200, out)
		return nil
	case http.MethodPut:
		if err := h.authorize(c, "PutFunctionConcurrency", c.functionARN(f.name)); err != nil {
			return err
		}
		var req struct{ ReservedConcurrentExecutions *int64 }
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
		if req.ReservedConcurrentExecutions == nil {
			return validation("null", "reservedConcurrentExecutions", "Member must not be null")
		}
		n := *req.ReservedConcurrentExecutions
		if n < 0 {
			return validation(strconv.FormatInt(n, 10), "reservedConcurrentExecutions", "Member must have value greater than or equal to 0")
		}
		err := h.st.Update(c.ctx, func(tx *store.Tx) error {
			fn, err := c.loadFunction(tx, f)
			if err != nil {
				return err
			}
			var others int64
			if err := tx.QueryRowContext(c.ctx, `SELECT COALESCE(SUM(concurrency), 0) FROM lambda_functions WHERE account=? AND region=? AND id<>?`,
				c.account, c.region, fn.ID).Scan(&others); err != nil {
				return err
			}
			if others+n > accountConcurrency-minUnreserved {
				return invalidParam("Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [%d].", minUnreserved)
			}
			if _, err := tx.ExecContext(c.ctx, `UPDATE lambda_functions SET concurrency=? WHERE id=?`, n, fn.ID); err != nil {
				return err
			}
			return tx.Change("lambda", "PutFunctionConcurrency", c.functionARN(fn.Name), map[string]int64{"reserved": n})
		})
		if err != nil {
			return err
		}
		writeJSON(c.w, 200, map[string]any{"ReservedConcurrentExecutions": n})
		return nil
	case http.MethodDelete:
		if err := h.authorize(c, "DeleteFunctionConcurrency", c.functionARN(f.name)); err != nil {
			return err
		}
		err := h.st.Update(c.ctx, func(tx *store.Tx) error {
			fn, err := c.loadFunction(tx, f)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(c.ctx, `UPDATE lambda_functions SET concurrency=NULL WHERE id=?`, fn.ID); err != nil {
				return err
			}
			return tx.Change("lambda", "DeleteFunctionConcurrency", c.functionARN(fn.Name), nil)
		})
		if err != nil {
			return err
		}
		writeJSON(c.w, 204, nil)
		return nil
	}
	return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
}

// ---- qualifier settings (event invoke config, function URL) ---------------------------------

func loadSetting(c *call, q querier, fid int64, qualifier, kind string, out any) (bool, error) {
	var s string
	err := q.QueryRowContext(c.ctx, `SELECT config FROM lambda_settings WHERE function_id=? AND qualifier=? AND kind=?`, fid, qualifier, kind).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(s), out)
}

func saveSetting(c *call, tx *store.Tx, fid int64, qualifier, kind string, v any) error {
	b, _ := json.Marshal(v)
	_, err := tx.ExecContext(c.ctx, `INSERT INTO lambda_settings(function_id, qualifier, kind, config) VALUES (?,?,?,?)
		ON CONFLICT(function_id, qualifier, kind) DO UPDATE SET config=excluded.config`, fid, qualifier, kind, string(b))
	return err
}

type destination struct {
	Destination string `json:"Destination,omitempty"`
}

type destinationConfig struct {
	OnSuccess destination `json:"OnSuccess"`
	OnFailure destination `json:"OnFailure"`
}

type eventInvokeConfig struct {
	LastModified             float64           `json:"LastModified"`
	FunctionArn              string            `json:"FunctionArn"`
	MaximumRetryAttempts     *int              `json:"MaximumRetryAttempts,omitempty"`
	MaximumEventAgeInSeconds *int              `json:"MaximumEventAgeInSeconds,omitempty"`
	DestinationConfig        destinationConfig `json:"DestinationConfig"`
}

var destinationRE = regexp.MustCompile(`^$|^arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)$`)

func (h *Handler) eventInvokeConfig(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	action := map[string]string{http.MethodGet: "GetFunctionEventInvokeConfig", http.MethodPut: "PutFunctionEventInvokeConfig",
		http.MethodPost: "UpdateFunctionEventInvokeConfig", http.MethodDelete: "DeleteFunctionEventInvokeConfig"}[c.r.Method]
	if action == "" {
		return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
	}
	if err := h.authorize(c, action, c.functionARN(f.name)); err != nil {
		return err
	}
	var req struct {
		MaximumRetryAttempts     *int
		MaximumEventAgeInSeconds *int
		DestinationConfig        *destinationConfig
	}
	if c.r.Method == http.MethodPut || c.r.Method == http.MethodPost {
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
		if dc := req.DestinationConfig; dc != nil {
			if !destinationRE.MatchString(dc.OnSuccess.Destination) {
				return validation(dc.OnSuccess.Destination, "destinationConfig.onSuccess.destination", `Member must satisfy regular expression pattern: ^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)`)
			}
			if !destinationRE.MatchString(dc.OnFailure.Destination) {
				return validation(dc.OnFailure.Destination, "destinationConfig.onFailure.destination", `Member must satisfy regular expression pattern: ^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)`)
			}
		}
		if n := req.MaximumRetryAttempts; n != nil && (*n < 0 || *n > 2) {
			if *n < 0 {
				return validation(strconv.Itoa(*n), "maximumRetryAttempts", "Member must have value greater than or equal to 0")
			}
			return validation(strconv.Itoa(*n), "maximumRetryAttempts", "Member must have value less than or equal to 2")
		}
		if n := req.MaximumEventAgeInSeconds; n != nil && (*n < 60 || *n > 21600) {
			if *n < 60 {
				return validation(strconv.Itoa(*n), "maximumEventAgeInSeconds", "Member must have value greater than or equal to 60")
			}
			return validation(strconv.Itoa(*n), "maximumEventAgeInSeconds", "Member must have value less than or equal to 21600")
		}
	}
	var out *eventInvokeConfig
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		if _, _, err := c.resolve(tx, fn, f); err != nil {
			return err
		}
		arn := c.refARN(fnRef{name: fn.Name, qualifier: f.qualifier})
		var cur eventInvokeConfig
		found, err := loadSetting(c, tx, fn.ID, f.qualifier, "invoke", &cur)
		if err != nil {
			return err
		}
		missing := notFound("The function %s doesn't have an EventInvokeConfig", arn)
		switch c.r.Method {
		case http.MethodGet:
			if !found {
				return missing
			}
			out = &cur
			return nil
		case http.MethodDelete:
			if !found {
				return missing
			}
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_settings WHERE function_id=? AND qualifier=? AND kind='invoke'`, fn.ID, f.qualifier); err != nil {
				return err
			}
			return tx.Change("lambda", action, arn, nil)
		case http.MethodPost:
			if !found {
				return missing
			}
		case http.MethodPut:
			cur = eventInvokeConfig{}
		}
		if req.MaximumRetryAttempts != nil {
			cur.MaximumRetryAttempts = req.MaximumRetryAttempts
		}
		if req.MaximumEventAgeInSeconds != nil {
			cur.MaximumEventAgeInSeconds = req.MaximumEventAgeInSeconds
		}
		if req.DestinationConfig != nil {
			cur.DestinationConfig = *req.DestinationConfig
		}
		cur.FunctionArn = arn
		cur.LastModified = float64(h.now().UnixMilli()) / 1000
		out = &cur
		if err := saveSetting(c, tx, fn.ID, f.qualifier, "invoke", &cur); err != nil {
			return err
		}
		return tx.Change("lambda", action, arn, nil)
	})
	if err != nil {
		return err
	}
	if c.r.Method == http.MethodDelete {
		writeJSON(c.w, 204, nil)
		return nil
	}
	writeJSON(c.w, 200, out)
	return nil
}

func (h *Handler) listEventInvokeConfigs(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "ListFunctionEventInvokeConfigs", c.functionARN(f.name)); err != nil {
		return err
	}
	f.qualifier = ""
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	rows, err := h.st.DB().QueryContext(c.ctx, `SELECT config FROM lambda_settings WHERE function_id=? AND kind='invoke' ORDER BY qualifier`, fn.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	list := []eventInvokeConfig{}
	for rows.Next() {
		var s string
		var e eventInvokeConfig
		if err := rows.Scan(&s); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(s), &e); err != nil {
			return err
		}
		list = append(list, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	writeJSON(c.w, 200, map[string]any{"FunctionEventInvokeConfigs": list})
	return nil
}

// invokeSettings is the retry and destination policy for asynchronous
// invocations of one qualifier (AWS's defaults when none is configured).
func invokeSettings(c *call, q querier, fid int64, qualifier string) (retries int, maxAge time.Duration, dest destinationConfig) {
	var e eventInvokeConfig
	retries, maxAge = 2, 6*time.Hour
	if ok, _ := loadSetting(c, q, fid, qualifier, "invoke", &e); ok {
		if e.MaximumRetryAttempts != nil {
			retries = *e.MaximumRetryAttempts
		}
		if e.MaximumEventAgeInSeconds != nil {
			maxAge = time.Duration(*e.MaximumEventAgeInSeconds) * time.Second
		}
		dest = e.DestinationConfig
	}
	return retries, maxAge, dest
}

// ---- function URLs ------------------------------------------------------------------------

type urlConfig struct {
	FunctionUrl      string         `json:"FunctionUrl"`
	FunctionArn      string         `json:"FunctionArn"`
	AuthType         string         `json:"AuthType"`
	Cors             map[string]any `json:"Cors,omitempty"`
	CreationTime     string         `json:"CreationTime"`
	LastModifiedTime string         `json:"LastModifiedTime"`
	InvokeMode       string         `json:"InvokeMode"`
}

type urlRecord struct {
	urlConfig
	URLID string
}

func (h *Handler) urlConfig(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	action := map[string]string{http.MethodGet: "GetFunctionUrlConfig", http.MethodPost: "CreateFunctionUrlConfig",
		http.MethodPut: "UpdateFunctionUrlConfig", http.MethodDelete: "DeleteFunctionUrlConfig"}[c.r.Method]
	if action == "" {
		return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
	}
	if err := h.authorize(c, action, c.functionARN(f.name)); err != nil {
		return err
	}
	var req struct {
		AuthType   string
		Cors       map[string]any
		InvokeMode string
	}
	if c.r.Method == http.MethodPost || c.r.Method == http.MethodPut {
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
		if req.AuthType != "" && req.AuthType != "NONE" && req.AuthType != "AWS_IAM" {
			return validation(req.AuthType, "authType", "Member must satisfy enum value set: [NONE, AWS_IAM]")
		}
		if req.InvokeMode != "" && req.InvokeMode != "BUFFERED" && req.InvokeMode != "RESPONSE_STREAM" {
			return validation(req.InvokeMode, "invokeMode", "Member must satisfy enum value set: [RESPONSE_STREAM, BUFFERED]")
		}
	}
	if f.qualifier != "" && (f.qualifier == latest || isDigits(f.qualifier)) {
		return invalidParam("Function URLs can only be configured on the unqualified function or an alias.")
	}
	var out *urlRecord
	status := 200
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		if _, _, err := c.resolve(tx, fn, f); err != nil {
			return err
		}
		arn := c.refARN(fnRef{name: fn.Name, qualifier: f.qualifier})
		var cur urlRecord
		found, err := loadSetting(c, tx, fn.ID, f.qualifier, "url", &cur)
		if err != nil {
			return err
		}
		now := timestamp(h.now())
		switch c.r.Method {
		case http.MethodGet:
			if !found {
				return notFound("The resource you requested does not exist.")
			}
			out = &cur
			return nil
		case http.MethodDelete:
			if !found {
				return notFound("The resource you requested does not exist.")
			}
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_settings WHERE function_id=? AND qualifier=? AND kind='url'`, fn.ID, f.qualifier); err != nil {
				return err
			}
			return tx.Change("lambda", action, arn, nil)
		case http.MethodPost:
			if found {
				return conflict("Failed to create function url config for [functionArn = %s]. Error message:  FunctionUrlConfig exists for this Lambda function", arn)
			}
			if req.AuthType == "" {
				return validation("null", "authType", "Member must not be null")
			}
			id := make([]byte, 16)
			_, _ = randRead(id)
			cur = urlRecord{URLID: hex.EncodeToString(id)}
			cur.FunctionArn, cur.CreationTime, cur.InvokeMode = arn, now, "BUFFERED"
			status = 201
		case http.MethodPut:
			if !found {
				return notFound("The resource you requested does not exist.")
			}
		}
		if req.AuthType != "" {
			cur.AuthType = req.AuthType
		}
		if req.Cors != nil {
			cur.Cors = req.Cors
		}
		if req.InvokeMode != "" {
			cur.InvokeMode = req.InvokeMode
		}
		cur.LastModifiedTime = now
		cur.FunctionUrl = c.scheme + "://" + c.host + "/_citadel/lambda/url/" + cur.URLID + "/"
		out = &cur
		if err := saveSetting(c, tx, fn.ID, f.qualifier, "url", &cur); err != nil {
			return err
		}
		return tx.Change("lambda", action, arn, map[string]string{"url": cur.URLID})
	})
	if err != nil {
		return err
	}
	if c.r.Method == http.MethodDelete {
		writeJSON(c.w, 204, nil)
		return nil
	}
	resp := map[string]any{"FunctionUrl": out.FunctionUrl, "FunctionArn": out.FunctionArn, "AuthType": out.AuthType,
		"CreationTime": out.CreationTime, "InvokeMode": out.InvokeMode}
	if out.Cors != nil {
		resp["Cors"] = out.Cors
	}
	if c.r.Method != http.MethodPost {
		resp["LastModifiedTime"] = out.LastModifiedTime
	}
	writeJSON(c.w, status, resp)
	return nil
}

func (h *Handler) listURLConfigs(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "ListFunctionUrlConfigs", c.functionARN(f.name)); err != nil {
		return err
	}
	f.qualifier = ""
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	rows, err := h.st.DB().QueryContext(c.ctx, `SELECT config FROM lambda_settings WHERE function_id=? AND kind='url' ORDER BY qualifier`, fn.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	list := []urlConfig{}
	for rows.Next() {
		var s string
		var u urlRecord
		if err := rows.Scan(&s); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(s), &u); err != nil {
			return err
		}
		list = append(list, u.urlConfig)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	writeJSON(c.w, 200, map[string]any{"FunctionUrlConfigs": list})
	return nil
}

// ---- code signing ----------------------------------------------------------------------------

func (h *Handler) codeSigning(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	f.qualifier = ""
	action := map[string]string{http.MethodGet: "GetFunctionCodeSigningConfig", http.MethodPut: "PutFunctionCodeSigningConfig",
		http.MethodDelete: "DeleteFunctionCodeSigningConfig"}[c.r.Method]
	if action == "" {
		return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
	}
	if err := h.authorize(c, action, c.functionARN(f.name)); err != nil {
		return err
	}
	var req struct{ CodeSigningConfigArn string }
	if c.r.Method == http.MethodPut {
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
		if req.CodeSigningConfigArn == "" {
			return validation("null", "codeSigningConfigArn", "Member must not be null")
		}
	}
	var name, arn string
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		name, arn = fn.Name, fn.CodeSigning
		if c.r.Method == http.MethodGet {
			return nil
		}
		arn = req.CodeSigningConfigArn
		if _, err := tx.ExecContext(c.ctx, `UPDATE lambda_functions SET code_signing=? WHERE id=?`, arn, fn.ID); err != nil {
			return err
		}
		return tx.Change("lambda", action, c.functionARN(fn.Name), nil)
	})
	if err != nil {
		return err
	}
	if c.r.Method == http.MethodDelete {
		writeJSON(c.w, 204, nil)
		return nil
	}
	writeJSON(c.w, 200, map[string]string{"CodeSigningConfigArn": arn, "FunctionName": name})
	return nil
}

// AllowsService reports whether a function exists and its resource policy
// lets a service principal (s3.amazonaws.com) invoke it on behalf of
// sourceARN in sourceAccount, as S3 checks before accepting a notification
// destination.
func (h *Handler) AllowsService(ctx context.Context, account, region, function, principal, sourceARN, sourceAccount string) bool {
	f, err := parseRef(function)
	if err != nil {
		return false
	}
	fn, err := loadFunctionByName(ctx, h.st.DB(), account, region, f.name)
	if err != nil || fn == nil {
		return false
	}
	doc := functionPolicies(fn)[f.qualifier]
	if doc == nil {
		return false
	}
	for _, s := range doc.Statement {
		action, _ := s["Action"].(string)
		p, _ := s["Principal"].(map[string]any)
		if s["Effect"] != "Allow" || (action != "lambda:InvokeFunction" && action != "lambda:*" && action != "*") {
			continue
		}
		if p["Service"] != principal && p["AWS"] != "*" {
			continue
		}
		cond, _ := s["Condition"].(map[string]any)
		ok := true
		if like, _ := cond["ArnLike"].(map[string]any); like != nil {
			if pattern, _ := like["AWS:SourceArn"].(string); pattern != "" && !arnLike(pattern, sourceARN) {
				ok = false
			}
		}
		if eq, _ := cond["StringEquals"].(map[string]any); eq != nil {
			if acct, _ := eq["AWS:SourceAccount"].(string); acct != "" && acct != sourceAccount {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// arnLike matches IAM's ArnLike wildcards: * is any run of characters, ? one.
func arnLike(pattern, s string) bool {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	ok, _ := regexp.MatchString(b.String(), s)
	return ok
}
