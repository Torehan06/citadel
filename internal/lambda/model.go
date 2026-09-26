package lambda

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Config is a function version's configuration, exactly as the API returns
// it (FunctionConfiguration). FunctionArn is filled in per response because
// the same version is reported qualified or unqualified depending on how it
// was addressed.
type Config struct {
	FunctionName        string               `json:"FunctionName"`
	FunctionArn         string               `json:"FunctionArn"`
	Runtime             string               `json:"Runtime,omitempty"`
	Role                string               `json:"Role"`
	Handler             string               `json:"Handler,omitempty"`
	CodeSize            int64                `json:"CodeSize"`
	Description         string               `json:"Description"`
	Timeout             int                  `json:"Timeout"`
	MemorySize          int                  `json:"MemorySize"`
	LastModified        string               `json:"LastModified"`
	CodeSha256          string               `json:"CodeSha256"`
	Version             string               `json:"Version"`
	VpcConfig           map[string]any       `json:"VpcConfig,omitempty"`
	DeadLetterConfig    map[string]any       `json:"DeadLetterConfig,omitempty"`
	Environment         *Environment         `json:"Environment,omitempty"`
	KMSKeyArn           string               `json:"KMSKeyArn,omitempty"`
	TracingConfig       map[string]string    `json:"TracingConfig"`
	RevisionId          string               `json:"RevisionId"`
	Layers              []map[string]any     `json:"Layers"`
	State               string               `json:"State"`
	LastUpdateStatus    string               `json:"LastUpdateStatus"`
	FileSystemConfigs   []map[string]any     `json:"FileSystemConfigs,omitempty"`
	PackageType         string               `json:"PackageType"`
	ImageConfigResponse *ImageConfigResponse `json:"ImageConfigResponse,omitempty"`
	Architectures       []string             `json:"Architectures"`
	EphemeralStorage    map[string]int       `json:"EphemeralStorage"`
	SnapStart           map[string]string    `json:"SnapStart"`
	LoggingConfig       map[string]string    `json:"LoggingConfig"`
}

type Environment struct {
	Variables map[string]string `json:"Variables"`
}

type ImageConfigResponse struct {
	ImageConfig map[string]any `json:"ImageConfig"`
}

// version is one stored version row: the public configuration plus where its
// code lives. $LATEST is version number 0.
type version struct {
	Config
	Blob             string `json:"CitadelBlob,omitempty"`     // sha256 hex of the zip
	ImageURI         string `json:"CitadelImageUri,omitempty"` // container image packages
	ResolvedImageURI string `json:"CitadelResolvedImageUri,omitempty"`
}

// function is the function-level state shared by all its versions.
type function struct {
	Tags                 map[string]string             `json:"Tags,omitempty"`
	Reserved             *int                          `json:"Reserved,omitempty"`
	Policies             map[string]*policy            `json:"Policies,omitempty"`    // qualifier ("" = function) -> policy
	URLs                 map[string]map[string]any     `json:"URLs,omitempty"`        // qualifier -> FunctionUrlConfig
	EventInvoke          map[string]*eventInvokeConfig `json:"EventInvoke,omitempty"` // qualifier -> config
	CodeSigningConfigArn string                        `json:"CodeSigningConfigArn,omitempty"`
	LastVersion          int                           `json:"LastVersion"` // highest published number
	Dirty                bool                          `json:"Dirty"`       // $LATEST changed since the last publish
	Created              int64                         `json:"Created"`
}

// querier is satisfied by *sql.DB and *store.Tx.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// fnRef names a function (and optionally a qualifier) in one account and region.
type fnRef struct {
	account, region, name, qualifier string
}

func (r fnRef) arn() string {
	return "arn:" + partition(r.region) + ":lambda:" + r.region + ":" + r.account + ":function:" + r.name
}

func (r fnRef) qualifiedARN(q string) string {
	if q == "" {
		return r.arn()
	}
	return r.arn() + ":" + q
}

// key identifies the function in in-memory maps.
func (r fnRef) key() string { return r.account + "/" + r.region + "/" + r.name }

var (
	namePattern      = regexp.MustCompile(`^[a-zA-Z0-9-_]{1,64}$`)
	qualifierPattern = regexp.MustCompile(`^(|[a-zA-Z0-9$_-]+)$`)
	// Regions: AWS's (us-west-2, us-isob-east-1) and Citadel's (tuchanka-1).
	regionPattern = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)*-\d+$`)
	accountID     = regexp.MustCompile(`^\d{12}$`)
)

// namespacedRule is the pattern Lambda quotes when a function name is malformed.
const namespacedRule = `(arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\d{1}:)?(\d{12}:)?(function:)?([a-zA-Z0-9-_\.]+)(:(\$LATEST|[a-zA-Z0-9-_]+))?`

// parseName resolves a FunctionName path parameter plus an optional
// Qualifier parameter. A function can be named four ways: "name",
// "name:qualifier", a partial ARN "account:function:name[:qualifier]" or a
// full ARN "arn:partition:lambda:region:account:function:name[:qualifier]".
// It splits on the colons structurally rather than with one regular
// expression, so a name like "my-func-1:live" can never be mistaken for a
// region followed by a name.
func (c *call) parseName(raw, qualifier string) (fnRef, error) {
	ref := fnRef{account: c.account, region: c.region}
	bad := func() (fnRef, error) {
		return ref, validation("1 validation error detected: Value '%s' at 'functionName' failed to satisfy constraint: Member must satisfy regular expression pattern: %s", raw, namespacedRule)
	}
	if raw == "" || len(raw) > 170 {
		return bad()
	}
	parts := strings.Split(raw, ":")
	var inName string
	hasQualifier := false
	switch {
	case parts[0] == "arn":
		if (len(parts) != 7 && len(parts) != 8) || parts[2] != "lambda" || parts[5] != "function" ||
			!regionPattern.MatchString(parts[3]) || !accountID.MatchString(parts[4]) {
			return bad()
		}
		ref.region, ref.account, ref.name = parts[3], parts[4], parts[6]
		if len(parts) == 8 {
			inName, hasQualifier = parts[7], true
		}
	case len(parts) >= 3 && parts[1] == "function":
		if len(parts) > 4 || !accountID.MatchString(parts[0]) {
			return bad()
		}
		ref.account, ref.name = parts[0], parts[2]
		if len(parts) == 4 {
			inName, hasQualifier = parts[3], true
		}
	case len(parts) <= 2:
		ref.name = parts[0]
		if len(parts) == 2 {
			inName, hasQualifier = parts[1], true
		}
	default:
		return bad()
	}
	if !namePattern.MatchString(ref.name) || (hasQualifier && (inName == "" || !qualifierPattern.MatchString(inName))) {
		return bad()
	}
	if !qualifierPattern.MatchString(qualifier) || len(qualifier) > 128 {
		return ref, validation("1 validation error detected: Value '%s' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: (|[a-zA-Z0-9$_-]+)", qualifier)
	}
	switch {
	case hasQualifier && qualifier != "" && inName != qualifier:
		return ref, invalid("The derived qualifier from the function name does not match the specified qualifier.")
	case hasQualifier:
		ref.qualifier = inName
	default:
		ref.qualifier = qualifier
	}
	if ref.account != c.account {
		return ref, errf(403, "AccessDeniedException", "User: %s is not authorized to perform this action on resource: %s", c.account, ref.arn())
	}
	return ref, nil
}

// fnName parses the {FunctionName} path parameter with the Qualifier query parameter.
func (c *call) fnName() (fnRef, error) {
	return c.parseName(c.params["FunctionName"], c.query.Get("Qualifier"))
}

func functionNotFound(ref fnRef, qualifier string) *apiError {
	return notFound("Function not found: %s", ref.qualifiedARN(qualifier))
}

func loadFunction(ctx context.Context, q querier, ref fnRef) (*function, error) {
	var doc string
	err := q.QueryRowContext(ctx, `SELECT doc FROM lambda_functions WHERE account_id=? AND region=? AND name=?`,
		ref.account, ref.region, ref.name).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f function
	return &f, json.Unmarshal([]byte(doc), &f)
}

// mustFunction loads a function or answers ResourceNotFoundException.
func mustFunction(ctx context.Context, q querier, ref fnRef) (*function, error) {
	f, err := loadFunction(ctx, q, ref)
	if err == nil && f == nil {
		err = functionNotFound(ref, "")
	}
	return f, err
}

func saveFunction(ctx context.Context, q querier, ref fnRef, f *function) error {
	doc, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO lambda_functions(account_id, region, name, doc) VALUES (?, ?, ?, ?)
		ON CONFLICT(account_id, region, name) DO UPDATE SET doc = excluded.doc`,
		ref.account, ref.region, ref.name, string(doc))
	return err
}

func loadVersion(ctx context.Context, q querier, ref fnRef, num int) (*version, error) {
	var doc string
	err := q.QueryRowContext(ctx, `SELECT config FROM lambda_versions WHERE account_id=? AND region=? AND name=? AND num=?`,
		ref.account, ref.region, ref.name, num).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v version
	return &v, json.Unmarshal([]byte(doc), &v)
}

func saveVersion(ctx context.Context, q querier, ref fnRef, num int, v *version) error {
	doc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO lambda_versions(account_id, region, name, num, config, blob) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(account_id, region, name, num) DO UPDATE SET config = excluded.config, blob = excluded.blob`,
		ref.account, ref.region, ref.name, num, string(doc), v.Blob)
	return err
}

func listVersions(ctx context.Context, q querier, ref fnRef) ([]*version, error) {
	rows, err := q.QueryContext(ctx, `SELECT config FROM lambda_versions WHERE account_id=? AND region=? AND name=? ORDER BY num`,
		ref.account, ref.region, ref.name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*version
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var v version
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// versionNumber parses a numeric version qualifier; $LATEST is 0.
func versionNumber(q string) (int, bool) {
	if q == "$LATEST" {
		return 0, true
	}
	n, err := strconv.Atoi(q)
	if err != nil || n < 1 || strconv.Itoa(n) != q {
		return 0, false
	}
	return n, true
}

// resolve finds the version a reference addresses: $LATEST when it has no
// qualifier, a numbered version, or the version an alias points at. It
// returns the version and the qualifier to report in its ARN ("" for an
// unqualified reference).
func resolve(ctx context.Context, q querier, ref fnRef) (*version, string, error) {
	f, err := loadFunction(ctx, q, ref)
	if err != nil {
		return nil, "", err
	}
	if f == nil {
		return nil, "", functionNotFound(ref, ref.qualifier)
	}
	num, qual := 0, ""
	if ref.qualifier != "" {
		n, isVersion := versionNumber(ref.qualifier)
		if !isVersion {
			a, err := loadAlias(ctx, q, ref, ref.qualifier)
			if err != nil {
				return nil, "", err
			}
			if a == nil {
				return nil, "", functionNotFound(ref, ref.qualifier)
			}
			n, _ = versionNumber(a.FunctionVersion)
		}
		num = n
		qual = "$LATEST"
		if n > 0 {
			qual = strconv.Itoa(n)
		}
	}
	v, err := loadVersion(ctx, q, ref, num)
	if err != nil {
		return nil, "", err
	}
	if v == nil {
		return nil, "", functionNotFound(ref, ref.qualifier)
	}
	return v, qual, nil
}

// out returns the public configuration with the given ARN.
func (v *version) out(arn string) Config {
	c := v.Config
	c.FunctionArn = arn
	return c
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// shaBase64 converts a hex SHA-256 (the blob address) to Lambda's CodeSha256.
func shaBase64(hexSHA string) string {
	raw, err := hex.DecodeString(hexSHA)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// constraint builds the "1 validation error detected" message AWS uses for
// modelled constraints.
func constraint(value any, field, rule string) *apiError {
	return validation("1 validation error detected: Value '%v' at '%s' failed to satisfy constraint: %s", value, field, rule)
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonUnmarshal(doc string, v any) error { return json.Unmarshal([]byte(doc), v) }

func itoa(n int) string { return strconv.Itoa(n) }
