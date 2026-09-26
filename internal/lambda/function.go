package lambda

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"citadel/internal/store"
)

const (
	maxZipSize         = 50 << 20 // direct upload limit for a zipped package
	maxCreateBody      = 70 << 20 // 50 MiB of zip, base64-encoded, plus the rest
	accountConcurrency = 1000
	minUnreserved      = 100
	latest             = "$LATEST"
)

// ---- names and ARNs ----------------------------------------------------------------

var (
	functionRefRE = regexp.MustCompile(`^(?:arn:(aws[a-zA-Z-]*):lambda:([a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d{1}):)?(?:(\d{12}):)?(?:function:)?([a-zA-Z0-9\-_]+)(?::(\$LATEST|[a-zA-Z0-9\-_]+))?$`)
	nameRE        = regexp.MustCompile(`^[a-zA-Z0-9\-_]{1,64}$`)
	aliasNameRE   = regexp.MustCompile(`^(?:[a-zA-Z0-9\-_]*[a-zA-Z\-_][a-zA-Z0-9\-_]*)$`)
	roleRE        = regexp.MustCompile(`^arn:(aws[a-zA-Z-]*)?:iam::(\d{12}):role/?[a-zA-Z_0-9+=,.@\-_/]+$`)
)

const rolePattern = `arn:(aws[a-zA-Z-]*)?:iam::(\d{12}):role/?[a-zA-Z_0-9+=,.@\-_/]+`

// partition maps a region to its ARN partition.
func partition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	}
	return "aws"
}

func (c *call) functionARN(name string) string {
	return functionARN(c.region, c.account, name)
}

func functionARN(region, account, name string) string {
	return "arn:" + partition(region) + ":lambda:" + region + ":" + account + ":function:" + name
}

// fnRef is a FunctionName parameter: a name, partial ARN or ARN, optionally
// with a qualifier (version or alias) after a colon.
type fnRef struct {
	name, qualifier string
	account, region string // from an ARN; empty when not given
}

func parseRef(raw string) (fnRef, error) {
	m := functionRefRE.FindStringSubmatch(raw)
	if m == nil || len(m[4]) > 64 {
		return fnRef{}, validation(raw, "functionName",
			`Member must satisfy regular expression pattern: (arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\d{1}:)?(\d{12}:)?(function:)?([a-zA-Z0-9-_\.]+)(:(\$LATEST|[a-zA-Z0-9-_]+))?`)
	}
	return fnRef{name: m[4], qualifier: m[5], account: m[3], region: m[2]}, nil
}

// ref parses a FunctionName path parameter together with the Qualifier
// query parameter.
func (c *call) ref(raw string) (fnRef, error) {
	f, err := parseRef(raw)
	if err != nil {
		return f, err
	}
	if q := c.query("Qualifier"); q != "" {
		if f.qualifier != "" && f.qualifier != q {
			return f, invalidParam("The derived qualifier from the function name does not match the specified qualifier.")
		}
		f.qualifier = q
	}
	return f, nil
}

func (c *call) refARN(f fnRef) string {
	a := c.functionARN(f.name)
	if f.qualifier != "" {
		a += ":" + f.qualifier
	}
	return a
}

// ---- stored shapes ----------------------------------------------------------------

type environment struct {
	Variables map[string]string `json:"Variables"`
}

type vpcConfig struct {
	SubnetIds               []string `json:"SubnetIds"`
	SecurityGroupIds        []string `json:"SecurityGroupIds"`
	VpcId                   string   `json:"VpcId"`
	Ipv6AllowedForDualStack bool     `json:"Ipv6AllowedForDualStack"`
}

type imageConfig struct {
	EntryPoint       []string `json:"EntryPoint,omitempty"`
	Command          []string `json:"Command,omitempty"`
	WorkingDirectory string   `json:"WorkingDirectory,omitempty"`
}

type layerRef struct {
	Arn      string `json:"Arn"`
	CodeSize int64  `json:"CodeSize"`
}

// functionConfig is a version's FunctionConfiguration, as the API returns it.
type functionConfig struct {
	FunctionName        string                      `json:"FunctionName"`
	FunctionArn         string                      `json:"FunctionArn"`
	Runtime             string                      `json:"Runtime,omitempty"`
	Role                string                      `json:"Role"`
	Handler             string                      `json:"Handler,omitempty"`
	CodeSize            int64                       `json:"CodeSize"`
	Description         string                      `json:"Description"`
	Timeout             int                         `json:"Timeout"`
	MemorySize          int                         `json:"MemorySize"`
	LastModified        string                      `json:"LastModified"`
	CodeSha256          string                      `json:"CodeSha256"`
	Version             string                      `json:"Version"`
	VpcConfig           *vpcConfig                  `json:"VpcConfig,omitempty"`
	Environment         *environment                `json:"Environment,omitempty"`
	DeadLetterConfig    *struct{ TargetArn string } `json:"DeadLetterConfig,omitempty"`
	KMSKeyArn           string                      `json:"KMSKeyArn,omitempty"`
	TracingConfig       struct{ Mode string }       `json:"TracingConfig"`
	RevisionId          string                      `json:"RevisionId"`
	Layers              []layerRef                  `json:"Layers,omitempty"`
	State               string                      `json:"State"`
	LastUpdateStatus    string                      `json:"LastUpdateStatus"`
	PackageType         string                      `json:"PackageType"`
	ImageConfigResponse *struct {
		ImageConfig imageConfig `json:"ImageConfig"`
	} `json:"ImageConfigResponse,omitempty"`
	Architectures    []string `json:"Architectures"`
	EphemeralStorage struct {
		Size int `json:"Size"`
	} `json:"EphemeralStorage"`
	SnapStart struct {
		ApplyOn            string `json:"ApplyOn"`
		OptimizationStatus string `json:"OptimizationStatus"`
	} `json:"SnapStart"`
	LoggingConfig struct {
		LogFormat string `json:"LogFormat"`
		LogGroup  string `json:"LogGroup"`
	} `json:"LoggingConfig"`
}

type function struct {
	ID                   int64
	Account, Region      string
	Name                 string
	LastVersion          int
	Published            string
	Policy               string
	Concurrency          sql.NullInt64
	Tags                 map[string]string
	CodeSigning          string
	latestRevisionCached string
}

type version struct {
	Num      int // 0 = $LATEST
	Config   functionConfig
	CodeBlob string
	ImageURI string
}

func versionName(n int) string {
	if n == 0 {
		return latest
	}
	return strconv.Itoa(n)
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (c *call) loadFunction(q querier, f fnRef) (*function, error) {
	if (f.account != "" && f.account != c.account) || (f.region != "" && f.region != c.region) {
		if f.account != "" && f.account != c.account {
			return nil, errorf(403, "AccessDeniedException", "User is not authorized to access function %s", f.name)
		}
		return nil, notFound("Function not found: %s", c.refARN(fnRef{name: f.name, qualifier: f.qualifier}))
	}
	fn, err := loadFunctionByName(c.ctx, q, c.account, c.region, f.name)
	if err != nil {
		return nil, err
	}
	if fn == nil {
		return nil, notFound("Function not found: %s", c.refARN(f))
	}
	return fn, nil
}

func loadFunctionByName(ctx context.Context, q querier, account, region, name string) (*function, error) {
	var fn function
	var tags string
	err := q.QueryRowContext(ctx, `SELECT id, account, region, name, last_version, published, policy, concurrency, tags, code_signing
		FROM lambda_functions WHERE account=? AND region=? AND name=?`, account, region, name).
		Scan(&fn.ID, &fn.Account, &fn.Region, &fn.Name, &fn.LastVersion, &fn.Published, &fn.Policy, &fn.Concurrency, &tags, &fn.CodeSigning)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(tags), &fn.Tags); err != nil {
		return nil, err
	}
	return &fn, nil
}

func loadVersion(ctx context.Context, q querier, fid int64, num int) (*version, error) {
	var v version
	var cfg string
	err := q.QueryRowContext(ctx, `SELECT version, config, code_blob, image_uri FROM lambda_versions WHERE function_id=? AND version=?`, fid, num).
		Scan(&v.Num, &cfg, &v.CodeBlob, &v.ImageURI)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, json.Unmarshal([]byte(cfg), &v.Config)
}

func saveVersion(ctx context.Context, tx *store.Tx, fid int64, v *version) error {
	cfg, err := json.Marshal(v.Config)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO lambda_versions(function_id, version, config, code_blob, image_uri) VALUES (?,?,?,?,?)
		ON CONFLICT(function_id, version) DO UPDATE SET config=excluded.config, code_blob=excluded.code_blob, image_uri=excluded.image_uri`,
		fid, v.Num, string(cfg), v.CodeBlob, v.ImageURI)
	return err
}

// resolve finds the version a qualifier names: "" and $LATEST are version 0,
// digits a published version, anything else an alias. It also returns the
// alias name when the qualifier was one.
func (c *call) resolve(q querier, fn *function, f fnRef) (*version, string, error) {
	missing := func() error { return notFound("Function not found: %s", c.refARN(f)) }
	qual := f.qualifier
	num := 0
	alias := ""
	switch {
	case qual == "" || qual == latest:
	case isDigits(qual):
		n, err := strconv.Atoi(qual)
		if err != nil || n < 1 {
			return nil, "", missing()
		}
		num = n
	default:
		a, err := loadAlias(c.ctx, q, fn.ID, qual)
		if err != nil {
			return nil, "", err
		}
		if a == nil {
			return nil, "", missing()
		}
		alias = qual
		if a.FunctionVersion != latest {
			num, _ = strconv.Atoi(a.FunctionVersion)
		}
	}
	v, err := loadVersion(c.ctx, q, fn.ID, num)
	if err != nil {
		return nil, "", err
	}
	if v == nil {
		return nil, "", missing()
	}
	return v, alias, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// view is a version's configuration as returned for a request: the ARN is
// qualified when the caller named a qualifier (or listed versions).
func (c *call) view(v *version, qualified bool) functionConfig {
	cfg := v.Config
	cfg.FunctionArn = c.functionARN(cfg.FunctionName)
	if qualified {
		cfg.FunctionArn += ":" + versionName(v.Num)
	}
	cfg.Version = versionName(v.Num)
	return cfg
}

func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000+0000") }

func newRevision() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ---- validation -----------------------------------------------------------------

var runtimes = []string{
	"nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x", "nodejs20.x", "nodejs22.x", "nodejs24.x",
	"java8", "java8.al2", "java11", "java17", "java21", "java25",
	"python2.7", "python3.6", "python3.7", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14",
	"dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6", "dotnet8", "dotnet10",
	"nodejs4.3-edge", "go1.x", "ruby2.5", "ruby2.7", "ruby3.2", "ruby3.3", "ruby3.4",
	"provided", "provided.al2", "provided.al2023",
}

func validRuntime(r string) bool {
	for _, x := range runtimes {
		if r == x {
			return true
		}
	}
	return false
}

type settings struct {
	Role             *string
	Handler          *string
	Runtime          *string
	Description      *string
	Timeout          *int
	MemorySize       *int
	Environment      *environment
	VpcConfig        *vpcConfig
	DeadLetterConfig *struct{ TargetArn string }
	KMSKeyArn        *string
	TracingConfig    *struct{ Mode string }
	Layers           []string
	EphemeralStorage *struct{ Size int }
	ImageConfig      *imageConfig
	SnapStart        *struct{ ApplyOn string }
	LoggingConfig    *struct{ LogFormat, LogGroup string }
	Architectures    []string
	RevisionId       string
}

// apply validates s and writes it onto cfg (creation defaults are already there).
func (h *Handler) apply(c *call, s *settings, cfg *functionConfig) error {
	if s.Role != nil {
		if err := h.checkRole(c, *s.Role); err != nil {
			return err
		}
		cfg.Role = *s.Role
	}
	if s.Runtime != nil {
		if !validRuntime(*s.Runtime) {
			return invalidParam("Value %s at 'runtime' failed to satisfy constraint: Member must satisfy enum value set: [%s] or be a valid ARN", *s.Runtime, strings.Join(runtimes, ", "))
		}
		cfg.Runtime = *s.Runtime
	}
	if s.Handler != nil {
		if len(*s.Handler) > 128 {
			return validation(*s.Handler, "handler", "Member must have length less than or equal to 128")
		}
		cfg.Handler = *s.Handler
	}
	if s.Description != nil {
		if len(*s.Description) > 256 {
			return validation(*s.Description, "description", "Member must have length less than or equal to 256")
		}
		cfg.Description = *s.Description
	}
	if s.Timeout != nil {
		if *s.Timeout < 1 {
			return validation(strconv.Itoa(*s.Timeout), "timeout", "Member must have value greater than or equal to 1")
		}
		if *s.Timeout > 900 {
			return validation(strconv.Itoa(*s.Timeout), "timeout", "Member must have value less than or equal to 900")
		}
		cfg.Timeout = *s.Timeout
	}
	if s.MemorySize != nil {
		if *s.MemorySize < 128 {
			return validation(strconv.Itoa(*s.MemorySize), "memorySize", "Member must have value greater than or equal to 128")
		}
		if *s.MemorySize > 10240 {
			return validation(strconv.Itoa(*s.MemorySize), "memorySize", "Member must have value less than or equal to 10240")
		}
		cfg.MemorySize = *s.MemorySize
	}
	if s.EphemeralStorage != nil {
		size := s.EphemeralStorage.Size
		if size < 512 {
			return validation(strconv.Itoa(size), "ephemeralStorage.size", "Member must have value greater than or equal to 512")
		}
		if size > 10240 {
			return validation(strconv.Itoa(size), "ephemeralStorage.size", "Member must have value less than or equal to 10240")
		}
		cfg.EphemeralStorage.Size = size
	}
	if s.Architectures != nil {
		if len(s.Architectures) != 1 || (s.Architectures[0] != "x86_64" && s.Architectures[0] != "arm64") {
			return validation("['"+strings.Join(s.Architectures, "', '")+"']", "architectures",
				"Member must satisfy constraint: [Member must satisfy enum value set: [x86_64, arm64], Member must not be null]")
		}
		cfg.Architectures = s.Architectures
	}
	if s.Environment != nil {
		size := 0
		for k, v := range s.Environment.Variables {
			if !envKeyRE.MatchString(k) {
				return validation(k, "environment.variables", "Member must satisfy regular expression pattern: [a-zA-Z]([a-zA-Z0-9_])+")
			}
			if reservedEnv[k] {
				return invalidParam("Lambda was unable to configure your environment variables because the environment variables you have provided contains reserved keys that are currently not supported for modification. Reserved keys used in this request: %s", k)
			}
			size += len(k) + len(v)
		}
		if size > 4096 {
			return invalidParam("Lambda was unable to configure your environment variables because the environment variables you have provided exceeded the 4KB limit. String measured: %d", size)
		}
		env := &environment{Variables: map[string]string{}}
		for k, v := range s.Environment.Variables {
			env.Variables[k] = v
		}
		cfg.Environment = env
	}
	if s.VpcConfig != nil {
		v := *s.VpcConfig
		if v.SubnetIds == nil {
			v.SubnetIds = []string{}
		}
		if v.SecurityGroupIds == nil {
			v.SecurityGroupIds = []string{}
		}
		if len(v.SubnetIds) == 0 && len(v.SecurityGroupIds) == 0 {
			cfg.VpcConfig = nil
		} else {
			cfg.VpcConfig = &v
		}
	}
	if s.DeadLetterConfig != nil {
		if s.DeadLetterConfig.TargetArn == "" {
			cfg.DeadLetterConfig = nil
		} else if !strings.Contains(s.DeadLetterConfig.TargetArn, ":sqs:") && !strings.Contains(s.DeadLetterConfig.TargetArn, ":sns:") {
			return invalidParam("The provided target arn is invalid: %s", s.DeadLetterConfig.TargetArn)
		} else {
			cfg.DeadLetterConfig = &struct{ TargetArn string }{s.DeadLetterConfig.TargetArn}
		}
	}
	if s.KMSKeyArn != nil {
		cfg.KMSKeyArn = *s.KMSKeyArn
	}
	if s.TracingConfig != nil {
		switch s.TracingConfig.Mode {
		case "Active", "PassThrough":
			cfg.TracingConfig.Mode = s.TracingConfig.Mode
		default:
			return validation(s.TracingConfig.Mode, "tracingConfig.mode", "Member must satisfy enum value set: [Active, PassThrough]")
		}
	}
	if s.Layers != nil {
		if len(s.Layers) > 0 {
			return errorf(501, "NotImplemented", "citadel: Lambda layers are not implemented yet")
		}
		cfg.Layers = nil
	}
	if s.ImageConfig != nil {
		if cfg.PackageType != "Image" {
			return invalidParam("Please don't provide ImageConfig for Zip-type functions.")
		}
		cfg.ImageConfigResponse = &struct {
			ImageConfig imageConfig `json:"ImageConfig"`
		}{*s.ImageConfig}
	}
	if s.SnapStart != nil {
		switch s.SnapStart.ApplyOn {
		case "None", "PublishedVersions":
			cfg.SnapStart.ApplyOn = s.SnapStart.ApplyOn
		default:
			return validation(s.SnapStart.ApplyOn, "snapStart.applyOn", "Member must satisfy enum value set: [PublishedVersions, None]")
		}
	}
	if s.LoggingConfig != nil {
		if f := s.LoggingConfig.LogFormat; f != "" {
			if f != "Text" && f != "JSON" {
				return validation(f, "loggingConfig.logFormat", "Member must satisfy enum value set: [JSON, Text]")
			}
			cfg.LoggingConfig.LogFormat = f
		}
		if g := s.LoggingConfig.LogGroup; g != "" {
			cfg.LoggingConfig.LogGroup = g
		}
	}
	return nil
}

var envKeyRE = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9_])+$`)

// reservedEnv are the variables the runtime sets itself.
var reservedEnv = map[string]bool{
	"_HANDLER": true, "_X_AMZN_TRACE_ID": true, "AWS_DEFAULT_REGION": true, "AWS_REGION": true, "AWS_EXECUTION_ENV": true,
	"AWS_LAMBDA_FUNCTION_NAME": true, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": true, "AWS_LAMBDA_FUNCTION_VERSION": true,
	"AWS_LAMBDA_INITIALIZATION_TYPE": true, "AWS_LAMBDA_LOG_GROUP_NAME": true, "AWS_LAMBDA_LOG_STREAM_NAME": true,
	"AWS_ACCESS_KEY": true, "AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
	"AWS_LAMBDA_RUNTIME_API": true, "LAMBDA_TASK_ROOT": true, "LAMBDA_RUNTIME_DIR": true,
}

// checkRole validates an execution role: well-formed, in the caller's
// account, and existing. (AWS also checks that the role's trust policy lets
// lambda.amazonaws.com assume it; Citadel functions never assume their role,
// so only existence is checked.)
func (h *Handler) checkRole(c *call, role string) error {
	m := roleRE.FindStringSubmatch(role)
	if m == nil {
		return validation(role, "role", "Member must satisfy regular expression pattern: "+rolePattern)
	}
	if m[2] != c.account {
		return errorf(403, "AccessDeniedException", "Cross-account pass role is not allowed.")
	}
	if h.IAM != nil {
		r, err := h.IAM.RoleByARN(c.ctx, c.account, role)
		if err != nil {
			return err
		}
		if r == nil {
			return invalidParam("The role defined for the function cannot be assumed by Lambda.")
		}
	}
	return nil
}

// ---- code -------------------------------------------------------------------------

type codeInput struct {
	ZipFile         []byte
	S3Bucket        string
	S3Key           string
	S3ObjectVersion string
	ImageUri        string
}

type storedCode struct {
	blob, imageURI string
	sha256         string // base64 (zip) or hex (image), as CodeSha256 reports
	size           int64
}

func (in *codeInput) empty() bool {
	return in.ZipFile == nil && in.S3Bucket == "" && in.S3Key == "" && in.ImageUri == ""
}

// storeCode puts a deployment package into the blob store and checks it is a
// zip. It does not record a reference: the caller's metadata transaction does
// (the sweeper's grace period covers the gap).
func (h *Handler) storeCode(c *call, in *codeInput, packageType string) (*storedCode, error) {
	if in.ImageUri != "" {
		if packageType != "Image" {
			return nil, invalidParam("Please provide ImageUri when updating a function with packageType Image.")
		}
		sum := sha256.Sum256([]byte(in.ImageUri))
		return &storedCode{imageURI: in.ImageUri, sha256: hex.EncodeToString(sum[:])}, nil
	}
	if packageType == "Image" {
		return nil, invalidParam("Please provide ImageUri when updating a function with packageType Image.")
	}
	var body io.Reader
	switch {
	case in.ZipFile != nil:
		if in.S3Bucket != "" || in.S3Key != "" {
			return nil, invalidParam("Please do not provide other FunctionCode parameters when providing a ZipFile.")
		}
		if len(in.ZipFile) > maxZipSize {
			return nil, errorf(413, "RequestEntityTooLargeException", "Request must be smaller than %d bytes for the CreateFunction operation", maxZipSize)
		}
		body = bytes.NewReader(in.ZipFile)
	case in.S3Bucket != "" && in.S3Key != "":
		if h.S3 == nil {
			return nil, errorf(501, "NotImplemented", "citadel: S3 deployment packages are not available")
		}
		rc, _, err := h.S3.OpenObject(c.ctx, c.account, in.S3Bucket, in.S3Key, in.S3ObjectVersion)
		if err != nil {
			code, msg := "InternalError", err.Error()
			var coded interface{ S3Error() (string, string) }
			if errors.As(err, &coded) {
				code, msg = coded.S3Error()
			} else {
				return nil, err
			}
			return nil, invalidParam("Error occurred while GetObject. S3 Error Code: %s. S3 Error Message: %s", code, msg)
		}
		defer rc.Close()
		body = rc
	default:
		return nil, invalidParam("Please provide a source for function code.")
	}
	p, err := h.st.Blobs.Write(io.LimitReader(body, maxZipSize+1))
	if err != nil {
		return nil, err
	}
	defer p.Abort()
	if p.Size > maxZipSize {
		return nil, invalidParam("Unzipped size must be smaller than %d bytes", maxWasmSize)
	}
	if err := p.Commit(); err != nil {
		return nil, err
	}
	f, err := h.st.Blobs.Open(p.SHA256)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := zip.NewReader(f, p.Size)
	if err != nil {
		return nil, invalidParam("Could not unzip uploaded file. Please check your file, then try to upload again.")
	}
	var unzipped uint64
	for _, zf := range zr.File {
		unzipped += zf.UncompressedSize64
	}
	if unzipped > maxWasmSize {
		return nil, invalidParam("Unzipped size must be smaller than %d bytes", maxWasmSize)
	}
	raw, _ := hex.DecodeString(p.SHA256)
	return &storedCode{blob: p.SHA256, sha256: base64.StdEncoding.EncodeToString(raw), size: p.Size}, nil
}

func (v *version) setCode(sc *storedCode) {
	v.CodeBlob, v.ImageURI = sc.blob, sc.imageURI
	v.Config.CodeSha256, v.Config.CodeSize = sc.sha256, sc.size
}

// codeLocation answers GetFunction's Code: a time-limited URL on this region
// for zips, the image reference for container images.
func (h *Handler) codeLocation(c *call, v *version) map[string]any {
	if v.ImageURI != "" {
		repo := v.ImageURI
		if i := strings.LastIndexAny(repo, ":@"); i > strings.LastIndexByte(repo, '/') {
			repo = repo[:i]
		}
		return map[string]any{"RepositoryType": "ECR", "ImageUri": v.ImageURI, "ResolvedImageUri": repo + "@sha256:" + v.Config.CodeSha256}
	}
	expires := h.now().Add(10 * time.Minute).Unix()
	loc := fmt.Sprintf("%s://%s/_citadel/lambda/code/%s?expires=%d&signature=%s",
		c.scheme, c.host, v.CodeBlob, expires, h.codeSignature(v.CodeBlob, expires))
	return map[string]any{"RepositoryType": "S3", "Location": loc}
}

func (h *Handler) codeSignature(blob string, expires int64) string {
	m := hmac.New(sha256.New, h.secret)
	fmt.Fprintf(m, "%s\n%d", blob, expires)
	return hex.EncodeToString(m.Sum(nil))
}

// ServeCode answers the download URLs codeLocation hands out
// (/_citadel/lambda/code/<blob>?expires=...&signature=...).
func (h *Handler) ServeCode(w http.ResponseWriter, r *http.Request) {
	blob := strings.TrimPrefix(r.URL.Path, "/_citadel/lambda/code/")
	expires, _ := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	want := h.codeSignature(blob, expires)
	if !hmac.Equal([]byte(want), []byte(r.URL.Query().Get("signature"))) || h.now().Unix() > expires {
		http.Error(w, "AccessDenied: the code location has expired or is invalid", http.StatusForbidden)
		return
	}
	f, err := h.st.Blobs.Open(blob)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/zip")
	if info, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	_, _ = io.Copy(w, f)
}

// loadCode opens a version's package for the runtime.
func (h *Handler) loadCode(blob string) func() (io.ReaderAt, int64, error) {
	return func() (io.ReaderAt, int64, error) {
		f, err := h.st.Blobs.Open(blob)
		if err != nil {
			return nil, 0, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, err
		}
		return f, info.Size(), nil
	}
}

var _ io.ReaderAt = (*os.File)(nil)

// ---- operations -------------------------------------------------------------------

type createRequest struct {
	settings
	FunctionName         string
	Code                 codeInput
	PackageType          string
	Publish              bool
	Tags                 map[string]string
	CodeSigningConfigArn string
}

func (h *Handler) createFunction(c *call) error {
	var req createRequest
	if err := c.decode(&req, maxCreateBody); err != nil {
		return err
	}
	if !nameRE.MatchString(req.FunctionName) {
		if f, err := parseRef(req.FunctionName); err == nil && f.qualifier == "" && (f.account == "" || f.account == c.account) {
			req.FunctionName = f.name // a function ARN names the function too
		} else {
			return validation(req.FunctionName, "functionName", "Member must satisfy regular expression pattern: (arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\\d{1}:)?(\\d{12}:)?(function:)?([a-zA-Z0-9-_]+)")
		}
	}
	if err := h.authorize(c, "CreateFunction", c.functionARN(req.FunctionName)); err != nil {
		return err
	}
	if req.PackageType == "" {
		req.PackageType = "Zip"
		if req.Code.ImageUri != "" {
			req.PackageType = "Image"
		}
	}
	if req.PackageType != "Zip" && req.PackageType != "Image" {
		return validation(req.PackageType, "packageType", "Member must satisfy enum value set: [Image, Zip]")
	}
	cfg := functionConfig{
		FunctionName: req.FunctionName, Timeout: 3, MemorySize: 128, PackageType: req.PackageType,
		State: "Active", LastUpdateStatus: "Successful", Architectures: []string{"x86_64"},
	}
	cfg.TracingConfig.Mode = "PassThrough"
	cfg.EphemeralStorage.Size = 512
	cfg.SnapStart.ApplyOn, cfg.SnapStart.OptimizationStatus = "None", "Off"
	cfg.LoggingConfig.LogFormat, cfg.LoggingConfig.LogGroup = "Text", "/aws/lambda/"+req.FunctionName
	if req.Role == nil {
		return validation("null", "role", "Member must not be null")
	}
	if err := h.apply(c, &req.settings, &cfg); err != nil {
		return err
	}
	if req.PackageType == "Zip" {
		if cfg.Runtime == "" {
			return invalidParam("Runtime and Handler are mandatory parameters for functions created with deployment packages.")
		}
		if cfg.Handler == "" && !strings.HasPrefix(cfg.Runtime, "provided") {
			return invalidParam("Runtime and Handler are mandatory parameters for functions created with deployment packages.")
		}
	}
	if err := validateTags(req.Tags); err != nil {
		return err
	}
	if req.Code.empty() {
		return invalidParam("Please provide a source for function code.")
	}
	sc, err := h.storeCode(c, &req.Code, req.PackageType)
	if err != nil {
		return err
	}
	now := h.now()
	cfg.LastModified = timestamp(now)
	cfg.RevisionId = newRevision()
	v := &version{Num: 0, Config: cfg}
	v.setCode(sc)
	tags := req.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	tagJSON, _ := json.Marshal(tags)
	out := *v
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := loadFunctionByName(c.ctx, tx, c.account, c.region, req.FunctionName)
		if err != nil {
			return err
		}
		if fn != nil {
			return conflict("Function already exist: %s", req.FunctionName)
		}
		res, err := tx.ExecContext(c.ctx, `INSERT INTO lambda_functions(account, region, name, created, tags, code_signing) VALUES (?,?,?,?,?,?)`,
			c.account, c.region, req.FunctionName, now.UnixMilli(), string(tagJSON), req.CodeSigningConfigArn)
		if err != nil {
			return err
		}
		fid, _ := res.LastInsertId()
		if err := saveVersion(c.ctx, tx, fid, v); err != nil {
			return err
		}
		if req.Publish {
			pub := *v
			pub.Num = 1
			if err := saveVersion(c.ctx, tx, fid, &pub); err != nil {
				return err
			}
			if _, err := tx.ExecContext(c.ctx, `UPDATE lambda_functions SET last_version=1, published=? WHERE id=?`, v.Config.RevisionId, fid); err != nil {
				return err
			}
			out = pub
		}
		return tx.Change("lambda", "CreateFunction", c.functionARN(req.FunctionName), map[string]any{"blob": v.CodeBlob, "publish": req.Publish})
	})
	if err != nil {
		return err
	}
	h.warm(v)
	writeJSON(c.w, 201, c.view(&out, false))
	return nil
}

func (h *Handler) getFunction(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "GetFunction", c.functionARN(f.name)); err != nil {
		return err
	}
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	v, _, err := c.resolve(h.st.DB(), fn, f)
	if err != nil {
		return err
	}
	out := map[string]any{"Configuration": c.view(v, f.qualifier != ""), "Code": h.codeLocation(c, v)}
	if len(fn.Tags) > 0 {
		out["Tags"] = fn.Tags
	}
	if fn.Concurrency.Valid {
		out["Concurrency"] = map[string]any{"ReservedConcurrentExecutions": fn.Concurrency.Int64}
	}
	writeJSON(c.w, 200, out)
	return nil
}

func (h *Handler) getFunctionConfiguration(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "GetFunctionConfiguration", c.functionARN(f.name)); err != nil {
		return err
	}
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	v, _, err := c.resolve(h.st.DB(), fn, f)
	if err != nil {
		return err
	}
	writeJSON(c.w, 200, c.view(v, f.qualifier != ""))
	return nil
}

// marker pages through a sorted list with an opaque offset.
func marker(c *call) (offset, limit int, err error) {
	limit = 50
	if s := c.query("MaxItems"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 10000 {
			return 0, 0, validation(s, "maxItems", "Member must have value between 1 and 10000")
		}
		limit = n
	}
	if s := c.query("Marker"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return 0, 0, invalidParam("Invalid marker: %s", s)
		}
		offset = n
	}
	return offset, limit, nil
}

func (h *Handler) listFunctions(c *call) error {
	if err := h.authorize(c, "ListFunctions", "*"); err != nil {
		return err
	}
	all := false
	switch fv := c.query("FunctionVersion"); fv {
	case "":
	case "ALL":
		all = true
	default:
		return validation(fv, "functionVersion", "Member must satisfy enum value set: [ALL]")
	}
	offset, limit, err := marker(c)
	if err != nil {
		return err
	}
	q := `SELECT v.version, v.config, v.code_blob, v.image_uri FROM lambda_versions v JOIN lambda_functions f ON f.id = v.function_id
		WHERE f.account=? AND f.region=?`
	if !all {
		q += ` AND v.version = 0`
	}
	q += ` ORDER BY f.name, v.version LIMIT ? OFFSET ?`
	vs, err := scanVersions(c.ctx, h.st.DB(), q, c.account, c.region, limit+1, offset)
	if err != nil {
		return err
	}
	list := []functionConfig{}
	for i := range vs {
		if i == limit {
			break
		}
		list = append(list, c.view(&vs[i], all))
	}
	out := map[string]any{"Functions": list}
	if len(vs) > limit {
		out["NextMarker"] = strconv.Itoa(offset + limit)
	}
	writeJSON(c.w, 200, out)
	return nil
}

func scanVersions(ctx context.Context, q querier, query string, args ...any) ([]version, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []version
	for rows.Next() {
		var v version
		var cfg string
		if err := rows.Scan(&v.Num, &cfg, &v.CodeBlob, &v.ImageURI); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cfg), &v.Config); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (h *Handler) listVersions(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "ListVersionsByFunction", c.functionARN(f.name)); err != nil {
		return err
	}
	f.qualifier = ""
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	offset, limit, err := marker(c)
	if err != nil {
		return err
	}
	vs, err := scanVersions(c.ctx, h.st.DB(), `SELECT version, config, code_blob, image_uri FROM lambda_versions
		WHERE function_id=? ORDER BY version LIMIT ? OFFSET ?`, fn.ID, limit+1, offset)
	if err != nil {
		return err
	}
	list := []functionConfig{}
	for i := range vs {
		if i == limit {
			break
		}
		list = append(list, c.view(&vs[i], true))
	}
	out := map[string]any{"Versions": list}
	if len(vs) > limit {
		out["NextMarker"] = strconv.Itoa(offset + limit)
	}
	writeJSON(c.w, 200, out)
	return nil
}

func (h *Handler) deleteFunction(c *call, raw string) error {
	f, err := c.ref(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "DeleteFunction", c.functionARN(f.name)); err != nil {
		return err
	}
	var stopped []string
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		switch {
		case f.qualifier == "":
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_functions WHERE id=?`, fn.ID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_async WHERE account=? AND region=? AND function=?`, c.account, c.region, fn.Name); err != nil {
				return err
			}
			return tx.Change("lambda", "DeleteFunction", c.functionARN(fn.Name), nil)
		case f.qualifier == latest:
			return invalidParam("$LATEST version cannot be deleted without deleting the function.")
		case !isDigits(f.qualifier):
			return invalidParam("Deletion of aliases is not supported.")
		}
		n, _ := strconv.Atoi(f.qualifier)
		v, err := loadVersion(c.ctx, tx, fn.ID, n)
		if err != nil {
			return err
		}
		if v == nil || n == 0 {
			return notFound("Function not found: %s", c.refARN(f))
		}
		rows, err := tx.QueryContext(c.ctx, `SELECT name FROM lambda_aliases WHERE function_id=? AND
			(json_extract(config, '$.FunctionVersion') = ? OR json_extract(config, '$.RoutingConfig.AdditionalVersionWeights."'||?||'"') IS NOT NULL) ORDER BY name`,
			fn.ID, f.qualifier, f.qualifier)
		if err != nil {
			return err
		}
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				rows.Close()
				return err
			}
			stopped = append(stopped, a)
		}
		rows.Close()
		if len(stopped) > 0 {
			return conflict("Unable to delete version because the following aliases reference it: [%s]", strings.Join(stopped, ", "))
		}
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_versions WHERE function_id=? AND version=?`, fn.ID, n); err != nil {
			return err
		}
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_settings WHERE function_id=? AND qualifier=?`, fn.ID, f.qualifier); err != nil {
			return err
		}
		return tx.Change("lambda", "DeleteFunctionVersion", c.refARN(f), nil)
	})
	if err != nil {
		return err
	}
	writeJSON(c.w, 204, nil)
	return nil
}

func (h *Handler) updateFunctionConfiguration(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "UpdateFunctionConfiguration", c.functionARN(f.name)); err != nil {
		return err
	}
	var req settings
	if err := c.decode(&req, 1<<20); err != nil {
		return err
	}
	f.qualifier = ""
	var out *version
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		v, err := loadVersion(c.ctx, tx, fn.ID, 0)
		if err != nil {
			return err
		}
		if req.RevisionId != "" && req.RevisionId != v.Config.RevisionId {
			return errorf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		if err := h.apply(c, &req, &v.Config); err != nil {
			return err
		}
		if v.Config.PackageType == "Zip" && req.Runtime != nil && v.Config.Runtime == "" {
			return invalidParam("Runtime is required for Zip functions.")
		}
		v.Config.LastModified = timestamp(h.now())
		v.Config.RevisionId = newRevision()
		if err := saveVersion(c.ctx, tx, fn.ID, v); err != nil {
			return err
		}
		out = v
		return tx.Change("lambda", "UpdateFunctionConfiguration", c.functionARN(fn.Name), nil)
	})
	if err != nil {
		return err
	}
	h.warm(out)
	writeJSON(c.w, 200, c.view(out, false))
	return nil
}

type updateCodeRequest struct {
	codeInput
	Publish       bool
	DryRun        bool
	RevisionId    string
	Architectures []string
}

func (h *Handler) updateFunctionCode(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "UpdateFunctionCode", c.functionARN(f.name)); err != nil {
		return err
	}
	var req updateCodeRequest
	if err := c.decode(&req, maxCreateBody); err != nil {
		return err
	}
	f.qualifier = ""
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	cur, err := loadVersion(c.ctx, h.st.DB(), fn.ID, 0)
	if err != nil {
		return err
	}
	if req.codeInput.empty() {
		return invalidParam("Please provide a source for function code.")
	}
	sc, err := h.storeCode(c, &req.codeInput, cur.Config.PackageType)
	if err != nil {
		return err
	}
	if req.Architectures != nil {
		if err := h.apply(c, &settings{Architectures: req.Architectures}, &cur.Config); err != nil {
			return err
		}
	}
	if req.DryRun {
		cur.setCode(sc)
		writeJSON(c.w, 200, c.view(cur, false))
		return nil
	}
	var out *version
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		v, err := loadVersion(c.ctx, tx, fn.ID, 0)
		if err != nil {
			return err
		}
		if req.RevisionId != "" && req.RevisionId != v.Config.RevisionId {
			return errorf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		v.setCode(sc)
		v.Config.Architectures = cur.Config.Architectures
		v.Config.LastModified = timestamp(h.now())
		v.Config.RevisionId = newRevision()
		if err := saveVersion(c.ctx, tx, fn.ID, v); err != nil {
			return err
		}
		out = v
		if req.Publish {
			if out, err = h.publishTx(c, tx, fn, v, nil); err != nil {
				return err
			}
		}
		return tx.Change("lambda", "UpdateFunctionCode", c.functionARN(fn.Name), map[string]any{"blob": v.CodeBlob, "publish": req.Publish})
	})
	if err != nil {
		return err
	}
	h.warm(out)
	writeJSON(c.w, 200, c.view(out, req.Publish))
	return nil
}

// publishTx publishes $LATEST as a new version, unless nothing changed since
// the last publish, in which case that version is returned.
func (h *Handler) publishTx(c *call, tx *store.Tx, fn *function, cur *version, description *string) (*version, error) {
	if fn.LastVersion > 0 && fn.Published == cur.Config.RevisionId {
		v, err := loadVersion(c.ctx, tx, fn.ID, fn.LastVersion)
		if err != nil || v != nil {
			return v, err
		}
	}
	pub := *cur
	pub.Num = fn.LastVersion + 1
	pub.Config.RevisionId = newRevision()
	if description != nil {
		pub.Config.Description = *description
	}
	if err := saveVersion(c.ctx, tx, fn.ID, &pub); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(c.ctx, `UPDATE lambda_functions SET last_version=?, published=? WHERE id=?`, pub.Num, cur.Config.RevisionId, fn.ID); err != nil {
		return nil, err
	}
	fn.LastVersion, fn.Published = pub.Num, cur.Config.RevisionId
	return &pub, tx.Change("lambda", "PublishVersion", c.functionARN(fn.Name)+":"+strconv.Itoa(pub.Num), nil)
}

func (h *Handler) publishVersion(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "PublishVersion", c.functionARN(f.name)); err != nil {
		return err
	}
	var req struct {
		CodeSha256  string
		Description *string
		RevisionId  string
	}
	if err := c.decode(&req, 1<<20); err != nil {
		return err
	}
	f.qualifier = ""
	var out *version
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		cur, err := loadVersion(c.ctx, tx, fn.ID, 0)
		if err != nil {
			return err
		}
		if req.CodeSha256 != "" && req.CodeSha256 != cur.Config.CodeSha256 {
			return invalidParam("CodeSHA256 (%s) is different from current CodeSHA256 in $LATEST (%s). Please try again with the CodeSHA256 in $LATEST.", req.CodeSha256, cur.Config.CodeSha256)
		}
		if req.RevisionId != "" && req.RevisionId != cur.Config.RevisionId {
			return errorf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		out, err = h.publishTx(c, tx, fn, cur, req.Description)
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(c.w, 201, c.view(out, true))
	return nil
}

func validateTags(tags map[string]string) error {
	if len(tags) > 50 {
		return invalidParam("Number of tags exceeds resource tag limit.")
	}
	for k, v := range tags {
		if k == "" || len(k) > 128 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalidParam("The tag key %q is invalid.", k)
		}
		if len(v) > 256 {
			return invalidParam("The tag value for %q is too long.", k)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// warm compiles a version's package in the background.
func (h *Handler) warm(v *version) {
	if v == nil || v.CodeBlob == "" {
		return
	}
	h.mu.Lock()
	ctx := h.ctx
	h.mu.Unlock()
	go h.runtime.Prepare(ctx, v.Config.MemorySize, v.CodeBlob, h.loadCode(v.CodeBlob))
}
