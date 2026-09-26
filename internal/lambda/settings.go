package lambda

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"citadel/internal/store"
)

func init() {
	handle("GET", "/2017-03-31/tags/{Resource}", "ListTags", (*Handler).listTags)
	handle("POST", "/2017-03-31/tags/{Resource}", "TagResource", (*Handler).tagResource)
	handle("DELETE", "/2017-03-31/tags/{Resource}", "UntagResource", (*Handler).untagResource)

	handle("PUT", "/2017-10-31/functions/{FunctionName}/concurrency", "PutFunctionConcurrency", (*Handler).putConcurrency)
	handle("GET", "/2019-09-30/functions/{FunctionName}/concurrency", "GetFunctionConcurrency", (*Handler).getConcurrency)
	handle("DELETE", "/2017-10-31/functions/{FunctionName}/concurrency", "DeleteFunctionConcurrency", (*Handler).deleteConcurrency)
	handle("GET", "/2016-08-19/account-settings", "GetAccountSettings", (*Handler).accountSettings)

	handle("PUT", "/2019-09-25/functions/{FunctionName}/event-invoke-config", "PutFunctionEventInvokeConfig", (*Handler).putEventInvoke)
	handle("POST", "/2019-09-25/functions/{FunctionName}/event-invoke-config", "UpdateFunctionEventInvokeConfig", (*Handler).updateEventInvoke)
	handle("GET", "/2019-09-25/functions/{FunctionName}/event-invoke-config", "GetFunctionEventInvokeConfig", (*Handler).getEventInvoke)
	handle("DELETE", "/2019-09-25/functions/{FunctionName}/event-invoke-config", "DeleteFunctionEventInvokeConfig", (*Handler).deleteEventInvoke)
	handle("GET", "/2019-09-25/functions/{FunctionName}/event-invoke-config/list", "ListFunctionEventInvokeConfigs", (*Handler).listEventInvoke)

	handle("POST", "/2021-10-31/functions/{FunctionName}/url", "CreateFunctionUrlConfig", (*Handler).createURL)
	handle("GET", "/2021-10-31/functions/{FunctionName}/url", "GetFunctionUrlConfig", (*Handler).getURL)
	handle("PUT", "/2021-10-31/functions/{FunctionName}/url", "UpdateFunctionUrlConfig", (*Handler).updateURL)
	handle("DELETE", "/2021-10-31/functions/{FunctionName}/url", "DeleteFunctionUrlConfig", (*Handler).deleteURL)
	handle("GET", "/2021-10-31/functions/{FunctionName}/urls", "ListFunctionUrlConfigs", (*Handler).listURLs)

	handle("GET", "/2020-06-30/functions/{FunctionName}/code-signing-config", "GetFunctionCodeSigningConfig", (*Handler).getCodeSigning)
	handle("PUT", "/2020-06-30/functions/{FunctionName}/code-signing-config", "PutFunctionCodeSigningConfig", (*Handler).putCodeSigning)
	handle("DELETE", "/2020-06-30/functions/{FunctionName}/code-signing-config", "DeleteFunctionCodeSigningConfig", (*Handler).deleteCodeSigning)

	handle("POST", "/2015-03-31/functions/{FunctionName}/policy", "AddPermission", (*Handler).addPermission)
	handle("GET", "/2015-03-31/functions/{FunctionName}/policy", "GetPolicy", (*Handler).getPolicy)
	handle("DELETE", "/2015-03-31/functions/{FunctionName}/policy/{StatementId}", "RemovePermission", (*Handler).removePermission)
}

// withFunction runs fn on a function's document in a write transaction and
// saves it afterwards.
func (h *Handler) withFunction(c *call, ref fnRef, kind string, fn func(f *function) error) error {
	return h.st.Update(c.ctx, func(tx *store.Tx) error {
		f, err := mustFunction(c.ctx, tx, ref)
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			return err
		}
		if err := saveFunction(c.ctx, tx, ref, f); err != nil {
			return err
		}
		return tx.Change("lambda", kind, ref.arn(), nil)
	})
}

// ---- tags ------------------------------------------------------------------

func checkTags(tags map[string]string) error {
	if len(tags) > 50 {
		return invalid("Number of tags exceeds resource tag limit.")
	}
	for k, v := range tags {
		if k == "" || len(k) > 128 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid tag key: %s", k)
		}
		if len(v) > 256 {
			return invalid("Invalid tag value for key %s", k)
		}
	}
	return nil
}

var taggableARN = regexp.MustCompile(`^arn:(aws[a-zA-Z-]*):lambda:([a-z0-9-]+):(\d{12}):(function|event-source-mapping|code-signing-config):([a-zA-Z0-9-_.]+)$`)

// taggable resolves a tag resource ARN to a function or a mapping UUID.
func (c *call) taggable() (ref fnRef, esm string, err error) {
	arn := c.params["Resource"]
	m := taggableARN.FindStringSubmatch(arn)
	if m == nil {
		return ref, "", constraint(arn, "resource", "Member must satisfy regular expression pattern: arn:(aws[a-zA-Z-]*):lambda:[a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\\d{1}:\\d{12}:(function:[a-zA-Z0-9-_]+(:(\\$LATEST|[a-zA-Z0-9-_]+))?|code-signing-config:csc-[a-z0-9]{17}|event-source-mapping:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
	}
	if m[3] != c.account {
		return ref, "", errf(403, "AccessDeniedException", "User: %s is not authorized to perform this action on resource: %s", c.account, arn)
	}
	switch m[4] {
	case "function":
		return fnRef{account: m[3], region: m[2], name: m[5]}, "", nil
	case "event-source-mapping":
		return ref, m[5], nil
	}
	return ref, "", notFound("The resource you requested does not exist.")
}

// updateTags applies fn to the tags of whichever resource the ARN names.
func (h *Handler) updateTags(c *call, action string, fn func(tags map[string]string)) error {
	ref, id, err := c.taggable()
	if err != nil {
		return err
	}
	if err := h.authorize(c, action, c.params["Resource"]); err != nil {
		return err
	}
	if id != "" {
		return h.updateMapping(c, id, func(m *mapping) error {
			if m.Tags == nil {
				m.Tags = map[string]string{}
			}
			fn(m.Tags)
			return checkTags(m.Tags)
		})
	}
	return h.withFunction(c, ref, action, func(f *function) error {
		if f.Tags == nil {
			f.Tags = map[string]string{}
		}
		fn(f.Tags)
		return checkTags(f.Tags)
	})
}

func (h *Handler) listTags(c *call) (*result, error) {
	ref, id, err := c.taggable()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "ListTags", c.params["Resource"]); err != nil {
		return nil, err
	}
	tags := map[string]string{}
	if id != "" {
		m, err := loadMapping(c.ctx, h.st.DB(), c.account, id)
		if err != nil {
			return nil, err
		}
		for k, v := range m.Tags {
			tags[k] = v
		}
	} else {
		f, err := mustFunction(c.ctx, h.st.DB(), ref)
		if err != nil {
			return nil, err
		}
		for k, v := range f.Tags {
			tags[k] = v
		}
	}
	return ok(200, map[string]any{"Tags": tags}), nil
}

func (h *Handler) tagResource(c *call) (*result, error) {
	var in struct{ Tags map[string]string }
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	err := h.updateTags(c, "TagResource", func(tags map[string]string) {
		for k, v := range in.Tags {
			tags[k] = v
		}
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

func (h *Handler) untagResource(c *call) (*result, error) {
	keys := c.query["tagKeys"]
	err := h.updateTags(c, "UntagResource", func(tags map[string]string) {
		for _, k := range keys {
			delete(tags, k)
		}
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

// ---- concurrency -------------------------------------------------------------

// Account concurrency: AWS's default quota, of which 100 must stay unreserved.
const (
	accountConcurrency = 1000
	minUnreserved      = 100
)

// reservedTotal sums the reserved concurrency of every function in the
// account and region except skip.
func (h *Handler) reservedTotal(c *call, q querier, skip string) (int, error) {
	rows, err := q.QueryContext(c.ctx, `SELECT name, doc FROM lambda_functions WHERE account_id=? AND region=?`, c.account, c.region)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var name, doc string
		if err := rows.Scan(&name, &doc); err != nil {
			return 0, err
		}
		var f function
		if err := json.Unmarshal([]byte(doc), &f); err != nil {
			return 0, err
		}
		if name != skip && f.Reserved != nil {
			total += *f.Reserved
		}
	}
	return total, rows.Err()
}

func (h *Handler) putConcurrency(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "PutFunctionConcurrency", ref.arn()); err != nil {
		return nil, err
	}
	var in struct{ ReservedConcurrentExecutions *int }
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if in.ReservedConcurrentExecutions == nil {
		return nil, validation("1 validation error detected: Value null at 'reservedConcurrentExecutions' failed to satisfy constraint: Member must not be null")
	}
	n := *in.ReservedConcurrentExecutions
	if n < 0 {
		return nil, constraint(n, "reservedConcurrentExecutions", "Member must have value greater than or equal to 0")
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		f, err := mustFunction(c.ctx, tx, ref)
		if err != nil {
			return err
		}
		others, err := h.reservedTotal(c, tx, ref.name)
		if err != nil {
			return err
		}
		if others+n > accountConcurrency-minUnreserved {
			return invalid("Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [%d].", minUnreserved)
		}
		f.Reserved = &n
		if err := saveFunction(c.ctx, tx, ref, f); err != nil {
			return err
		}
		return tx.Change("lambda", "PutFunctionConcurrency", ref.arn(), map[string]int{"reserved": n})
	})
	if err != nil {
		return nil, err
	}
	return ok(200, map[string]int{"ReservedConcurrentExecutions": n}), nil
}

func (h *Handler) getConcurrency(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetFunctionConcurrency", ref.arn()); err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	if f.Reserved != nil {
		out["ReservedConcurrentExecutions"] = *f.Reserved
	}
	return ok(200, out), nil
}

func (h *Handler) deleteConcurrency(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "DeleteFunctionConcurrency", ref.arn()); err != nil {
		return nil, err
	}
	if err := h.withFunction(c, ref, "DeleteFunctionConcurrency", func(f *function) error { f.Reserved = nil; return nil }); err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

func (h *Handler) accountSettings(c *call) (*result, error) {
	if err := h.authorize(c, "GetAccountSettings", "*"); err != nil {
		return nil, err
	}
	db := h.st.DB()
	reserved, err := h.reservedTotal(c, db, "")
	if err != nil {
		return nil, err
	}
	var count, size int64
	if err := db.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM lambda_functions WHERE account_id=? AND region=?`, c.account, c.region).Scan(&count); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(c.ctx, `SELECT COALESCE(SUM(json_extract(config, '$.CodeSize')), 0) FROM lambda_versions WHERE account_id=? AND region=?`,
		c.account, c.region).Scan(&size); err != nil {
		return nil, err
	}
	return ok(200, map[string]any{
		"AccountLimit": map[string]any{
			"TotalCodeSize": int64(80530636800), "CodeSizeUnzipped": maxUnzipped, "CodeSizeZipped": maxZipUpload,
			"ConcurrentExecutions": accountConcurrency, "UnreservedConcurrentExecutions": accountConcurrency - reserved,
		},
		"AccountUsage": map[string]any{"TotalCodeSize": size, "FunctionCount": count},
	}), nil
}

// ---- asynchronous invocation config -------------------------------------------

type eventInvokeConfig struct {
	LastModified             float64        `json:"LastModified"`
	FunctionArn              string         `json:"FunctionArn"`
	MaximumRetryAttempts     *int           `json:"MaximumRetryAttempts,omitempty"`
	MaximumEventAgeInSeconds *int           `json:"MaximumEventAgeInSeconds,omitempty"`
	DestinationConfig        map[string]any `json:"DestinationConfig,omitempty"`
}

var destinationPattern = regexp.MustCompile(`^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)`)

type eventInvokeInput struct {
	MaximumRetryAttempts     *int
	MaximumEventAgeInSeconds *int
	DestinationConfig        map[string]map[string]string
}

func (in *eventInvokeInput) validate() error {
	if n := in.MaximumRetryAttempts; n != nil && (*n < 0 || *n > 2) {
		if *n < 0 {
			return constraint(*n, "maximumRetryAttempts", "Member must have value greater than or equal to 0")
		}
		return constraint(*n, "maximumRetryAttempts", "Member must have value less than or equal to 2")
	}
	if n := in.MaximumEventAgeInSeconds; n != nil && (*n < 60 || *n > 21600) {
		if *n < 60 {
			return constraint(*n, "maximumEventAgeInSeconds", "Member must have value greater than or equal to 60")
		}
		return constraint(*n, "maximumEventAgeInSeconds", "Member must have value less than or equal to 21600")
	}
	for _, k := range []string{"OnSuccess", "OnFailure"} {
		d := in.DestinationConfig[k]["Destination"]
		if !destinationPattern.MatchString(d) || (d != "" && !strings.HasPrefix(d, "arn:")) {
			field := "destinationConfig.onSuccess.destination"
			if k == "OnFailure" {
				field = "destinationConfig.onFailure.destination"
			}
			return constraint(d, field, `Member must satisfy regular expression pattern: ^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)`)
		}
	}
	return nil
}

// qualifierKey is the qualifier a per-qualifier setting is stored under.
func (h *Handler) eventInvoke(c *call, replace bool) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	op := "UpdateFunctionEventInvokeConfig"
	if replace {
		op = "PutFunctionEventInvokeConfig"
	}
	if err := h.authorize(c, op, ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	var in eventInvokeInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	var out *eventInvokeConfig
	err = h.withFunction(c, ref, op, func(f *function) error {
		if ref.qualifier != "" {
			if _, _, err := resolve(c.ctx, h.st.DB(), ref); err != nil {
				return err
			}
		}
		cur := f.EventInvoke[ref.qualifier]
		if replace || cur == nil {
			cur = &eventInvokeConfig{}
		}
		cur.FunctionArn = ref.qualifiedARN(ref.qualifier)
		cur.LastModified = float64(h.now().UnixMilli()) / 1000
		if replace || in.MaximumRetryAttempts != nil {
			cur.MaximumRetryAttempts = in.MaximumRetryAttempts
		}
		if replace || in.MaximumEventAgeInSeconds != nil {
			cur.MaximumEventAgeInSeconds = in.MaximumEventAgeInSeconds
		}
		if replace || in.DestinationConfig != nil {
			cur.DestinationConfig = nil
			if in.DestinationConfig != nil {
				dc := map[string]any{}
				for k, v := range in.DestinationConfig {
					dc[k] = v
				}
				cur.DestinationConfig = dc
			}
		}
		if f.EventInvoke == nil {
			f.EventInvoke = map[string]*eventInvokeConfig{}
		}
		f.EventInvoke[ref.qualifier] = cur
		out = cur
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(200, out), nil
}

func (h *Handler) putEventInvoke(c *call) (*result, error)    { return h.eventInvoke(c, true) }
func (h *Handler) updateEventInvoke(c *call) (*result, error) { return h.eventInvoke(c, false) }

func (h *Handler) getEventInvoke(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetFunctionEventInvokeConfig", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	cfg := f.EventInvoke[ref.qualifier]
	if cfg == nil {
		return nil, notFound("The function %s doesn't have an EventInvokeConfig", ref.qualifiedARN(ref.qualifier))
	}
	return ok(200, cfg), nil
}

func (h *Handler) deleteEventInvoke(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "DeleteFunctionEventInvokeConfig", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	err = h.withFunction(c, ref, "DeleteFunctionEventInvokeConfig", func(f *function) error {
		if f.EventInvoke[ref.qualifier] == nil {
			return notFound("The function %s doesn't have an EventInvokeConfig", ref.qualifiedARN(ref.qualifier))
		}
		delete(f.EventInvoke, ref.qualifier)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

func (h *Handler) listEventInvoke(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "ListFunctionEventInvokeConfigs", ref.arn()); err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	list := []*eventInvokeConfig{}
	for _, q := range sortedKeys(f.EventInvoke) {
		list = append(list, f.EventInvoke[q])
	}
	return ok(200, map[string]any{"FunctionEventInvokeConfigs": list}), nil
}

// ---- function URLs --------------------------------------------------------------

type urlInput struct {
	AuthType   *string
	Cors       map[string]any
	InvokeMode *string
}

func (in *urlInput) validate(create bool) error {
	if in.AuthType == nil && create {
		return validation("1 validation error detected: Value null at 'authType' failed to satisfy constraint: Member must not be null")
	}
	if in.AuthType != nil && *in.AuthType != "NONE" && *in.AuthType != "AWS_IAM" {
		return constraint(*in.AuthType, "authType", "Member must satisfy enum value set: [NONE, AWS_IAM]")
	}
	if in.InvokeMode != nil && *in.InvokeMode != "BUFFERED" && *in.InvokeMode != "RESPONSE_STREAM" {
		return constraint(*in.InvokeMode, "invokeMode", "Member must satisfy enum value set: [BUFFERED, RESPONSE_STREAM]")
	}
	return nil
}

// urlRef parses the function name for a URL config, whose qualifier may only
// be an alias (or $LATEST).
func (h *Handler) urlRef(c *call, action string) (fnRef, error) {
	ref, err := c.fnName()
	if err != nil {
		return ref, err
	}
	if _, isVersion := versionNumber(ref.qualifier); isVersion && ref.qualifier != "$LATEST" {
		return ref, validation("1 validation error detected: Value '%s' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: (^\\$LATEST$)|((?!^[0-9]+$)([a-zA-Z0-9-_]+))", ref.qualifier)
	}
	return ref, h.authorize(c, action, ref.qualifiedARN(ref.qualifier))
}

func (h *Handler) createURL(c *call) (*result, error) {
	ref, err := h.urlRef(c, "CreateFunctionUrlConfig")
	if err != nil {
		return nil, err
	}
	var in urlInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(true); err != nil {
		return nil, err
	}
	var out map[string]any
	err = h.withFunction(c, ref, "CreateFunctionUrlConfig", func(f *function) error {
		if ref.qualifier != "" {
			if _, _, err := resolve(c.ctx, h.st.DB(), ref); err != nil {
				return err
			}
		}
		arn := ref.qualifiedARN(ref.qualifier)
		if f.URLs[ref.qualifier] != nil {
			return conflict("Failed to create function url config for [functionArn = %s]. Error message:  FunctionUrlConfig exists for this Lambda function", arn)
		}
		now := isoMillis(h.now())
		mode := "BUFFERED"
		if in.InvokeMode != nil {
			mode = *in.InvokeMode
		}
		out = map[string]any{
			"FunctionUrl":  "https://" + strings.ToLower(randomHex(32)) + ".lambda-url." + ref.region + ".on.aws/",
			"FunctionArn":  arn,
			"AuthType":     *in.AuthType,
			"CreationTime": now, "LastModifiedTime": now, "InvokeMode": mode,
		}
		if in.Cors != nil {
			out["Cors"] = in.Cors
		}
		if f.URLs == nil {
			f.URLs = map[string]map[string]any{}
		}
		f.URLs[ref.qualifier] = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	created := map[string]any{}
	for k, v := range out {
		if k != "LastModifiedTime" {
			created[k] = v
		}
	}
	return ok(201, created), nil
}

func (h *Handler) getURL(c *call) (*result, error) {
	ref, err := h.urlRef(c, "GetFunctionUrlConfig")
	if err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	u := f.URLs[ref.qualifier]
	if u == nil {
		return nil, notFound("The resource you requested does not exist.")
	}
	return ok(200, u), nil
}

func (h *Handler) updateURL(c *call) (*result, error) {
	ref, err := h.urlRef(c, "UpdateFunctionUrlConfig")
	if err != nil {
		return nil, err
	}
	var in urlInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(false); err != nil {
		return nil, err
	}
	var out map[string]any
	err = h.withFunction(c, ref, "UpdateFunctionUrlConfig", func(f *function) error {
		u := f.URLs[ref.qualifier]
		if u == nil {
			return notFound("The resource you requested does not exist.")
		}
		if in.AuthType != nil {
			u["AuthType"] = *in.AuthType
		}
		if in.InvokeMode != nil {
			u["InvokeMode"] = *in.InvokeMode
		}
		if in.Cors != nil {
			u["Cors"] = in.Cors
		}
		u["LastModifiedTime"] = isoMillis(h.now())
		out = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(200, out), nil
}

func (h *Handler) deleteURL(c *call) (*result, error) {
	ref, err := h.urlRef(c, "DeleteFunctionUrlConfig")
	if err != nil {
		return nil, err
	}
	err = h.withFunction(c, ref, "DeleteFunctionUrlConfig", func(f *function) error {
		if f.URLs[ref.qualifier] == nil {
			return notFound("The resource you requested does not exist.")
		}
		delete(f.URLs, ref.qualifier)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

func (h *Handler) listURLs(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "ListFunctionUrlConfigs", ref.arn()); err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	list := []map[string]any{}
	for _, q := range sortedKeys(f.URLs) {
		list = append(list, f.URLs[q])
	}
	return ok(200, map[string]any{"FunctionUrlConfigs": list}), nil
}

// ---- code signing -------------------------------------------------------------

func (h *Handler) getCodeSigning(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetFunctionCodeSigningConfig", ref.arn()); err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	return ok(200, map[string]string{"CodeSigningConfigArn": f.CodeSigningConfigArn, "FunctionName": ref.name}), nil
}

func (h *Handler) putCodeSigning(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "PutFunctionCodeSigningConfig", ref.arn()); err != nil {
		return nil, err
	}
	var in struct{ CodeSigningConfigArn string }
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := h.withFunction(c, ref, "PutFunctionCodeSigningConfig", func(f *function) error {
		f.CodeSigningConfigArn = in.CodeSigningConfigArn
		return nil
	}); err != nil {
		return nil, err
	}
	return ok(200, map[string]string{"CodeSigningConfigArn": in.CodeSigningConfigArn, "FunctionName": ref.name}), nil
}

func (h *Handler) deleteCodeSigning(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "DeleteFunctionCodeSigningConfig", ref.arn()); err != nil {
		return nil, err
	}
	if err := h.withFunction(c, ref, "DeleteFunctionCodeSigningConfig", func(f *function) error {
		f.CodeSigningConfigArn = ""
		return nil
	}); err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

// ---- resource-based policy ---------------------------------------------------------

type policy struct {
	Version    string           `json:"Version"`
	Id         string           `json:"Id"`
	Statement  []map[string]any `json:"Statement"`
	RevisionId string           `json:"RevisionId,omitempty"`
}

// document is the policy as GetPolicy returns it (without the revision).
func (p *policy) document() string {
	return jsonString(map[string]any{"Version": p.Version, "Id": p.Id, "Statement": p.Statement})
}

var accountPattern = regexp.MustCompile(`^\d{12}$`)

// principalOf turns AddPermission's Principal into a policy principal.
func principalOf(p string) any {
	switch {
	case p == "*":
		return "*"
	case accountPattern.MatchString(p):
		return map[string]string{"AWS": "arn:aws:iam::" + p + ":root"}
	case strings.HasSuffix(p, ".amazonaws.com") || strings.HasSuffix(p, ".amazonaws.com.cn"):
		return map[string]string{"Service": p}
	}
	return map[string]string{"AWS": p}
}

func (h *Handler) addPermission(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "AddPermission", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	var in struct {
		StatementId, Action, Principal, SourceArn, SourceAccount, EventSourceToken string
		RevisionId, PrincipalOrgID, FunctionUrlAuthType                            string
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9-_]{1,100}$`).MatchString(in.StatementId) {
		return nil, constraint(in.StatementId, "statementId", "Member must satisfy regular expression pattern: ([a-zA-Z0-9-_]+)")
	}
	if !regexp.MustCompile(`^(lambda:[*]|lambda:[a-zA-Z]+|[*])$`).MatchString(in.Action) {
		return nil, constraint(in.Action, "action", "Member must satisfy regular expression pattern: (lambda:[*]|lambda:[a-zA-Z]+|[*])")
	}
	if in.Principal == "" {
		return nil, validation("1 validation error detected: Value null at 'principal' failed to satisfy constraint: Member must not be null")
	}
	stmt := map[string]any{
		"Sid": in.StatementId, "Effect": "Allow", "Principal": principalOf(in.Principal),
		"Action": in.Action, "Resource": ref.qualifiedARN(ref.qualifier),
	}
	cond := map[string]map[string]string{}
	add := func(op, key, val string) {
		if val == "" {
			return
		}
		if cond[op] == nil {
			cond[op] = map[string]string{}
		}
		cond[op][key] = val
	}
	add("ArnLike", "AWS:SourceArn", in.SourceArn)
	add("StringEquals", "AWS:SourceAccount", in.SourceAccount)
	add("StringEquals", "aws:PrincipalOrgID", in.PrincipalOrgID)
	add("StringEquals", "lambda:EventSourceToken", in.EventSourceToken)
	add("StringEquals", "lambda:FunctionUrlAuthType", in.FunctionUrlAuthType)
	if len(cond) > 0 {
		stmt["Condition"] = cond
	}
	err = h.withFunction(c, ref, "AddPermission", func(f *function) error {
		if ref.qualifier != "" {
			if _, _, err := resolve(c.ctx, h.st.DB(), ref); err != nil {
				return err
			}
		}
		p := f.Policies[ref.qualifier]
		if p == nil {
			p = &policy{Version: "2012-10-17", Id: "default", Statement: []map[string]any{}}
		}
		if in.RevisionId != "" && p.RevisionId != "" && in.RevisionId != p.RevisionId {
			return errf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetPolicy API to retrieve the latest Revision Id")
		}
		for _, s := range p.Statement {
			if s["Sid"] == in.StatementId {
				return conflict("The statement id (%s) provided already exists. Please provide a new statement id, or remove the existing statement.", in.StatementId)
			}
		}
		p.Statement = append(p.Statement, stmt)
		p.RevisionId = newUUID()
		if f.Policies == nil {
			f.Policies = map[string]*policy{}
		}
		f.Policies[ref.qualifier] = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(201, map[string]string{"Statement": jsonString(stmt)}), nil
}

func (h *Handler) getPolicy(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetPolicy", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	p := f.Policies[ref.qualifier]
	if p == nil || len(p.Statement) == 0 {
		return nil, notFound("The resource you requested does not exist.")
	}
	return ok(200, map[string]string{"Policy": p.document(), "RevisionId": p.RevisionId}), nil
}

func (h *Handler) removePermission(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "RemovePermission", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	sid := c.params["StatementId"]
	rev := c.query.Get("RevisionId")
	err = h.withFunction(c, ref, "RemovePermission", func(f *function) error {
		p := f.Policies[ref.qualifier]
		if p == nil || len(p.Statement) == 0 {
			return notFound("No policy is associated with the given resource.")
		}
		if rev != "" && rev != p.RevisionId {
			return errf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetPolicy API to retrieve the latest Revision Id")
		}
		for i, s := range p.Statement {
			if s["Sid"] == sid {
				p.Statement = append(p.Statement[:i], p.Statement[i+1:]...)
				p.RevisionId = newUUID()
				if len(p.Statement) == 0 {
					delete(f.Policies, ref.qualifier)
				}
				return nil
			}
		}
		return notFound("Statement %s is not found in resource policy.", sid)
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}
