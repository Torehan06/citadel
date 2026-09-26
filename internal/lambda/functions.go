package lambda

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"citadel/internal/store"
)

func init() {
	handle("POST", "/2015-03-31/functions", "CreateFunction", (*Handler).createFunction)
	handle("GET", "/2015-03-31/functions", "ListFunctions", (*Handler).listFunctions)
	handle("GET", "/2015-03-31/functions/{FunctionName}", "GetFunction", (*Handler).getFunction)
	handle("DELETE", "/2015-03-31/functions/{FunctionName}", "DeleteFunction", (*Handler).deleteFunction)
	handle("GET", "/2015-03-31/functions/{FunctionName}/configuration", "GetFunctionConfiguration", (*Handler).getFunctionConfiguration)
	handle("PUT", "/2015-03-31/functions/{FunctionName}/configuration", "UpdateFunctionConfiguration", (*Handler).updateFunctionConfiguration)
	handle("PUT", "/2015-03-31/functions/{FunctionName}/code", "UpdateFunctionCode", (*Handler).updateFunctionCode)
	handle("POST", "/2015-03-31/functions/{FunctionName}/versions", "PublishVersion", (*Handler).publishVersion)
	handle("GET", "/2015-03-31/functions/{FunctionName}/versions", "ListVersionsByFunction", (*Handler).listVersionsByFunction)
}

// Limits from the Lambda quotas page.
const (
	maxZipUpload = 50 << 20  // direct upload, zipped
	maxUnzipped  = 262144000 // code and layers, unzipped
)

var rolePattern = regexp.MustCompile(`^arn:(aws[a-zA-Z-]*)?:iam::(\d{12}):role/?[a-zA-Z_0-9+=,.@\-_/]+$`)

// functionInput is the configuration part of CreateFunction and
// UpdateFunctionConfiguration. Pointers tell "absent" from "zero".
type functionInput struct {
	FunctionName         string
	Runtime              *string
	Role                 *string
	Handler              *string
	Description          *string
	Timeout              *int
	MemorySize           *int
	Publish              bool
	PackageType          string
	VpcConfig            map[string]any
	DeadLetterConfig     map[string]any
	Environment          *Environment
	KMSKeyArn            *string
	TracingConfig        map[string]string
	Tags                 map[string]string
	Layers               []string
	FileSystemConfigs    []map[string]any
	ImageConfig          map[string]any
	CodeSigningConfigArn string
	Architectures        []string
	EphemeralStorage     map[string]int
	SnapStart            map[string]string
	LoggingConfig        map[string]string
	RevisionId           string
	Code                 codeInput
}

type codeInput struct {
	ZipFile         []byte
	S3Bucket        string
	S3Key           string
	S3ObjectVersion string
	ImageUri        string
}

// code is an ingested deployment package.
type code struct {
	pending  *store.Pending // nil for images
	blob     string
	size     int64
	sha      string // CodeSha256 (base64)
	image    string
	resolved string
}

func (c *code) abort() {
	if c != nil && c.pending != nil {
		c.pending.Abort()
	}
}

// ingestCode stores a zip (inline or from S3) in the blob store, checking it
// unzips, or records an image URI.
func (h *Handler) ingestCode(c *call, in codeInput, packageType string) (*code, error) {
	if packageType == "Image" {
		if in.ImageUri == "" {
			return nil, invalid("Please provide ImageUri when PackageType is Image.")
		}
		sum := sha256.Sum256([]byte(in.ImageUri))
		digest := hex.EncodeToString(sum[:])
		repo := in.ImageUri
		if i := strings.LastIndexAny(repo, ":@"); i > strings.LastIndexByte(repo, '/') {
			repo = repo[:i]
		}
		return &code{image: in.ImageUri, resolved: repo + "@sha256:" + digest, sha: digest}, nil
	}
	if in.ImageUri != "" {
		return nil, invalid("Please don't provide ImageUri when updating a function with packageType Zip.")
	}
	var body io.Reader
	switch {
	case in.ZipFile != nil:
		if len(in.ZipFile) > maxZipUpload {
			return nil, errf(413, "RequestEntityTooLargeException", "Request must be smaller than %d bytes for the CreateFunction operation", maxZipUpload)
		}
		body = bytes.NewReader(in.ZipFile)
	case in.S3Bucket != "" || in.S3Key != "":
		if h.S3 == nil {
			return nil, invalid("Error occurred while GetObject. S3 Error Code: ServiceUnavailable. S3 Error Message: S3 is not available")
		}
		rc, _, err := h.S3.OpenObject(c.ctx, c.account, in.S3Bucket, in.S3Key)
		if err != nil {
			return nil, s3CodeError(err)
		}
		defer rc.Close()
		body = rc
	default:
		return nil, invalid("Please provide a source for function code.")
	}
	p, err := h.st.Blobs.Write(body)
	if err != nil {
		return nil, err
	}
	if err := checkZip(p); err != nil {
		p.Abort()
		return nil, err
	}
	return &code{pending: p, blob: p.SHA256, size: p.Size, sha: shaBase64(p.SHA256)}, nil
}

// s3CodeError reports a failed code fetch the way Lambda does.
func s3CodeError(err error) error {
	type coded interface{ S3Code() (string, string) }
	var ce coded
	if errors.As(err, &ce) {
		code, msg := ce.S3Code()
		return invalid("Error occurred while GetObject. S3 Error Code: %s. S3 Error Message: %s", code, msg)
	}
	return err
}

// checkZip verifies a pending upload is a zip within the unzipped-size quota.
func checkZip(p *store.Pending) error {
	f, err := p.OpenTemp()
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zip.NewReader(f, p.Size)
	if err != nil {
		return invalid("Could not unzip uploaded file. Please check your file, then try to upload again.")
	}
	var total uint64
	for _, zf := range zr.File {
		total += zf.UncompressedSize64
	}
	if total > maxUnzipped {
		return invalid("Unzipped size must be smaller than %d bytes", maxUnzipped)
	}
	return nil
}

// validateConfig applies the modelled constraints shared by create and update.
func validateConfig(in *functionInput) error {
	if in.Timeout != nil && (*in.Timeout < 1 || *in.Timeout > 900) {
		if *in.Timeout < 1 {
			return constraint(*in.Timeout, "timeout", "Member must have value greater than or equal to 1")
		}
		return constraint(*in.Timeout, "timeout", "Member must have value less than or equal to 900")
	}
	if in.MemorySize != nil && (*in.MemorySize < 128 || *in.MemorySize > 10240) {
		if *in.MemorySize < 128 {
			return constraint(*in.MemorySize, "memorySize", "Member must have value greater than or equal to 128")
		}
		return constraint(*in.MemorySize, "memorySize", "Member must have value less than or equal to 10240")
	}
	if in.EphemeralStorage != nil {
		size := in.EphemeralStorage["Size"]
		if size < 512 {
			return constraint(size, "ephemeralStorage.size", "Member must have value greater than or equal to 512")
		}
		if size > 10240 {
			return constraint(size, "ephemeralStorage.size", "Member must have value less than or equal to 10240")
		}
	}
	if in.Architectures != nil {
		if len(in.Architectures) != 1 || (in.Architectures[0] != "x86_64" && in.Architectures[0] != "arm64") {
			return validation("1 validation error detected: Value '%s' at 'architectures' failed to satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: [x86_64, arm64], Member must not be null]", pyList(in.Architectures))
		}
	}
	if in.TracingConfig != nil {
		if m := in.TracingConfig["Mode"]; m != "" && m != "Active" && m != "PassThrough" {
			return constraint(m, "tracingConfig.mode", "Member must satisfy enum value set: [Active, PassThrough]")
		}
	}
	if in.Description != nil && len(*in.Description) > 256 {
		return constraint(*in.Description, "description", "Member must have length less than or equal to 256")
	}
	return nil
}

// pyList formats a list the way Lambda's validation messages quote it.
func pyList(v []string) string {
	q := make([]string, len(v))
	for i, s := range v {
		q[i] = "'" + s + "'"
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// checkRole validates the execution role: well-formed, in the caller's
// account, and an existing IAM role.
func (h *Handler) checkRole(c *call, role string) error {
	m := rolePattern.FindStringSubmatch(role)
	if m == nil {
		return validation("1 validation error detected: Value '%s' at 'role' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:(aws[a-zA-Z-]*)?:iam::(\\d{12}):role/?[a-zA-Z_0-9+=,.@\\-_/]+", role)
	}
	if m[2] != c.account {
		return errf(403, "AccessDeniedException", "Cross-account pass role is not allowed.")
	}
	if h.IAM != nil {
		name := role[strings.LastIndexByte(role, '/')+1:]
		exists, err := h.IAM.RoleExists(c.ctx, c.account, name)
		if err != nil {
			return err
		}
		if !exists {
			return invalid("The role defined for the function cannot be assumed by Lambda.")
		}
	}
	return nil
}

func (h *Handler) createFunction(c *call) (*result, error) {
	var in functionInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if in.FunctionName == "" {
		return nil, validation("1 validation error detected: Value null at 'functionName' failed to satisfy constraint: Member must not be null")
	}
	ref, err := c.parseName(in.FunctionName, "")
	if err != nil {
		return nil, err
	}
	if ref.qualifier != "" {
		return nil, invalid("Unsupported function name: %s", in.FunctionName)
	}
	if err := h.authorize(c, "CreateFunction", ref.arn()); err != nil {
		return nil, err
	}
	if in.Role == nil {
		return nil, validation("1 validation error detected: Value null at 'role' failed to satisfy constraint: Member must not be null")
	}
	if err := h.checkRole(c, *in.Role); err != nil {
		return nil, err
	}
	if err := validateConfig(&in); err != nil {
		return nil, err
	}
	if in.PackageType == "" {
		in.PackageType = "Zip"
	}
	if in.PackageType != "Zip" && in.PackageType != "Image" {
		return nil, constraint(in.PackageType, "packageType", "Member must satisfy enum value set: [Image, Zip]")
	}
	if in.PackageType == "Image" && in.Code.ImageUri == "" && in.Code.ZipFile == nil && in.Code.S3Bucket == "" {
		return nil, invalid("Please provide ImageUri when PackageType is Image.")
	}
	if in.Code.ImageUri != "" && in.PackageType == "Zip" && in.Code.ZipFile == nil && in.Code.S3Bucket == "" {
		// An image URI alone implies an image package, as the console does.
		in.PackageType = "Image"
	}
	if err := checkTags(in.Tags); err != nil {
		return nil, err
	}
	cd, err := h.ingestCode(c, in.Code, in.PackageType)
	if err != nil {
		return nil, err
	}
	defer cd.abort()

	now := isoMillis(h.now())
	v := &version{Config: Config{
		FunctionName: ref.name, Role: *in.Role, Timeout: 3, MemorySize: 128,
		LastModified: now, Version: "$LATEST", RevisionId: newUUID(),
		TracingConfig: map[string]string{"Mode": "PassThrough"}, Layers: []map[string]any{},
		State: "Active", LastUpdateStatus: "Successful", PackageType: in.PackageType,
		Architectures:    []string{"x86_64"},
		EphemeralStorage: map[string]int{"Size": 512},
		SnapStart:        map[string]string{"ApplyOn": "None", "OptimizationStatus": "Off"},
		LoggingConfig:    map[string]string{"LogFormat": "Text", "LogGroup": "/aws/lambda/" + ref.name},
	}}
	applyConfig(v, &in, true)
	setCode(v, cd)

	f := &function{Tags: in.Tags, CodeSigningConfigArn: in.CodeSigningConfigArn, Dirty: true, Created: h.now().UnixMilli()}
	if cd.pending != nil {
		if err := cd.pending.Commit(); err != nil {
			return nil, err
		}
	}
	out := v
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		existing, err := loadFunction(c.ctx, tx, ref)
		if err != nil {
			return err
		}
		if existing != nil {
			return conflict("Function already exist: %s", ref.name)
		}
		if err := saveFunction(c.ctx, tx, ref, f); err != nil {
			return err
		}
		if err := saveVersion(c.ctx, tx, ref, 0, v); err != nil {
			return err
		}
		if in.Publish {
			if out, err = publish(c.ctx, tx, ref, f, v, nil); err != nil {
				return err
			}
			if err := saveFunction(c.ctx, tx, ref, f); err != nil {
				return err
			}
		}
		return tx.Change("lambda", "CreateFunction", ref.arn(), map[string]string{"version": out.Version})
	})
	if err != nil {
		return nil, err
	}
	return ok(201, out.out(ref.arn())), nil
}

// applyConfig copies the configuration fields present in the input onto a
// version. create also applies defaults that only creation sets.
func applyConfig(v *version, in *functionInput, create bool) {
	if in.Runtime != nil {
		v.Runtime = *in.Runtime
	}
	if in.Role != nil {
		v.Role = *in.Role
	}
	if in.Handler != nil {
		v.Handler = *in.Handler
	}
	if in.Description != nil {
		v.Description = *in.Description
	}
	if in.Timeout != nil {
		v.Timeout = *in.Timeout
	}
	if in.MemorySize != nil {
		v.MemorySize = *in.MemorySize
	}
	if in.VpcConfig != nil {
		if len(in.VpcConfig) == 0 {
			v.VpcConfig = nil
		} else {
			vpc := map[string]any{"SubnetIds": []any{}, "SecurityGroupIds": []any{}, "VpcId": ""}
			for k, val := range in.VpcConfig {
				vpc[k] = val
			}
			v.VpcConfig = vpc
		}
	}
	if in.DeadLetterConfig != nil {
		v.DeadLetterConfig = in.DeadLetterConfig
	}
	if in.Environment != nil {
		env := &Environment{Variables: in.Environment.Variables}
		if env.Variables == nil {
			env.Variables = map[string]string{}
		}
		v.Environment = env
	}
	if in.KMSKeyArn != nil {
		v.KMSKeyArn = *in.KMSKeyArn
	}
	if in.TracingConfig != nil && in.TracingConfig["Mode"] != "" {
		v.TracingConfig = map[string]string{"Mode": in.TracingConfig["Mode"]}
	}
	if in.Layers != nil {
		v.Layers = []map[string]any{}
		for _, l := range in.Layers {
			v.Layers = append(v.Layers, map[string]any{"Arn": l, "CodeSize": 0})
		}
	}
	if in.FileSystemConfigs != nil {
		v.FileSystemConfigs = in.FileSystemConfigs
	}
	if in.ImageConfig != nil {
		v.ImageConfigResponse = &ImageConfigResponse{ImageConfig: in.ImageConfig}
	}
	if in.Architectures != nil && create {
		v.Architectures = in.Architectures
	}
	if in.EphemeralStorage != nil {
		v.EphemeralStorage = map[string]int{"Size": in.EphemeralStorage["Size"]}
	}
	if in.SnapStart != nil {
		on := in.SnapStart["ApplyOn"]
		if on == "" {
			on = "None"
		}
		v.SnapStart = map[string]string{"ApplyOn": on, "OptimizationStatus": "Off"}
	}
	if in.LoggingConfig != nil {
		lc := map[string]string{"LogFormat": "Text", "LogGroup": "/aws/lambda/" + v.FunctionName}
		for k, val := range in.LoggingConfig {
			lc[k] = val
		}
		v.LoggingConfig = lc
	}
}

func setCode(v *version, cd *code) {
	v.CodeSha256 = cd.sha
	v.CodeSize = cd.size
	v.Blob = cd.blob
	v.ImageURI = cd.image
	v.ResolvedImageURI = cd.resolved
}

// publish creates version LastVersion+1 from $LATEST, unless nothing changed
// since the last publish, in which case that version is returned again.
func publish(ctx context.Context, q querier, ref fnRef, f *function, latest *version, description *string) (*version, error) {
	if !f.Dirty && f.LastVersion > 0 {
		v, err := loadVersion(ctx, q, ref, f.LastVersion)
		if err != nil || v != nil {
			return v, err
		}
	}
	f.LastVersion++
	f.Dirty = false
	v := *latest
	v.Version = strconv.Itoa(f.LastVersion)
	v.RevisionId = newUUID()
	if description != nil {
		v.Description = *description
	}
	return &v, saveVersion(ctx, q, ref, f.LastVersion, &v)
}

// codeLocation describes where a version's package can be fetched from.
func (c *call) codeLocation(ref fnRef, v *version) map[string]any {
	if v.PackageType == "Image" {
		return map[string]any{"RepositoryType": "ECR", "ImageUri": v.ImageURI, "ResolvedImageUri": v.ResolvedImageURI}
	}
	// AWS answers with a short-lived presigned URL into its code bucket.
	return map[string]any{
		"RepositoryType": "S3",
		"Location": "https://awslambda-" + ref.region + "-tasks.s3." + ref.region + ".amazonaws.com/snapshots/" +
			ref.account + "/" + ref.name + "-" + v.RevisionId + "?versionId=" + v.Blob[:min(len(v.Blob), 32)],
	}
}

func (h *Handler) getFunction(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetFunction", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	db := h.st.DB()
	v, qual, err := resolve(c.ctx, db, ref)
	if err != nil {
		return nil, err
	}
	f, err := mustFunction(c.ctx, db, ref)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"Configuration": v.out(ref.qualifiedARN(qual)),
		"Code":          c.codeLocation(ref, v),
	}
	if len(f.Tags) > 0 {
		out["Tags"] = f.Tags
	}
	if f.Reserved != nil {
		out["Concurrency"] = map[string]int{"ReservedConcurrentExecutions": *f.Reserved}
	}
	return ok(200, out), nil
}

func (h *Handler) getFunctionConfiguration(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetFunctionConfiguration", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	v, qual, err := resolve(c.ctx, h.st.DB(), ref)
	if err != nil {
		return nil, err
	}
	return ok(200, v.out(ref.qualifiedARN(qual))), nil
}

func (h *Handler) listFunctions(c *call) (*result, error) {
	if err := h.authorize(c, "ListFunctions", "*"); err != nil {
		return nil, err
	}
	all := c.query.Get("FunctionVersion") == "ALL"
	if fv := c.query.Get("FunctionVersion"); fv != "" && !all {
		return nil, constraint(fv, "functionVersion", "Member must satisfy enum value set: [ALL]")
	}
	maxItems, err := intParam(c.query, "MaxItems", 50)
	if err != nil {
		return nil, err
	}
	if maxItems < 1 || maxItems > 10000 {
		return nil, constraint(maxItems, "maxItems", "Member must have value less than or equal to 10000")
	}
	q := `SELECT name, num, config FROM lambda_versions WHERE account_id=? AND region=?`
	if !all {
		q += ` AND num = 0`
	}
	args := []any{c.account, c.region}
	if m := c.query.Get("Marker"); m != "" {
		name, num, ok := decodeMarker(m)
		if !ok {
			return nil, invalid("Invalid marker: %s", m)
		}
		q += ` AND (name > ? OR (name = ? AND num > ?))`
		args = append(args, name, name, num)
	}
	q += ` ORDER BY name, num LIMIT ?`
	args = append(args, maxItems+1)
	rows, err := h.st.DB().QueryContext(c.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fns := []Config{}
	var next string
	for rows.Next() {
		var name, doc string
		var num int
		if err := rows.Scan(&name, &num, &doc); err != nil {
			return nil, err
		}
		if len(fns) == maxItems {
			last := fns[len(fns)-1]
			n, _ := versionNumber(last.Version)
			next = encodeMarker(last.FunctionName, n)
			break
		}
		var v version
		if err := jsonUnmarshal(doc, &v); err != nil {
			return nil, err
		}
		ref := fnRef{account: c.account, region: c.region, name: name}
		arn := ref.arn()
		if all {
			arn = ref.qualifiedARN(v.Version)
		}
		fns = append(fns, v.out(arn))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]any{"Functions": fns}
	if next != "" {
		out["NextMarker"] = next
	}
	return ok(200, out), nil
}

func encodeMarker(name string, num int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x00" + strconv.Itoa(num)))
}

func decodeMarker(m string) (string, int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(m)
	if err != nil {
		return "", 0, false
	}
	name, num, found := strings.Cut(string(raw), "\x00")
	n, err := strconv.Atoi(num)
	return name, n, found && err == nil
}

func (h *Handler) deleteFunction(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "DeleteFunction", ref.qualifiedARN(ref.qualifier)); err != nil {
		return nil, err
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if _, err := mustFunction(c.ctx, tx, ref); err != nil {
			if ref.qualifier != "" {
				return functionNotFound(ref, ref.qualifier)
			}
			return err
		}
		if ref.qualifier == "" {
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_functions WHERE account_id=? AND region=? AND name=?`,
				ref.account, ref.region, ref.name); err != nil {
				return err
			}
			return tx.Change("lambda", "DeleteFunction", ref.arn(), nil)
		}
		if ref.qualifier == "$LATEST" {
			return invalid("$LATEST version cannot be deleted without deleting the function.")
		}
		num, isVersion := versionNumber(ref.qualifier)
		if !isVersion {
			return invalid("Deletion of aliases is not supported.")
		}
		aliases, err := listAliases(c.ctx, tx, ref)
		if err != nil {
			return err
		}
		var users []string
		for _, a := range aliases {
			if a.FunctionVersion == ref.qualifier {
				users = append(users, a.Name)
			}
		}
		if len(users) > 0 {
			return conflict("Unable to delete version because the following aliases reference it: [%s]", strings.Join(users, ", "))
		}
		res, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_versions WHERE account_id=? AND region=? AND name=? AND num=?`,
			ref.account, ref.region, ref.name, num)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return functionNotFound(ref, ref.qualifier)
		}
		return tx.Change("lambda", "DeleteFunctionVersion", ref.qualifiedARN(ref.qualifier), nil)
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}

// updateLatest runs fn on $LATEST in a transaction, checking the optional
// RevisionId precondition, and marks the function changed.
func (h *Handler) updateLatest(c *call, ref fnRef, revision string, fn func(f *function, v *version) error) (*function, *version, error) {
	var f *function
	var v *version
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		var err error
		if f, err = mustFunction(c.ctx, tx, ref); err != nil {
			return err
		}
		if v, err = loadVersion(c.ctx, tx, ref, 0); err != nil {
			return err
		}
		if revision != "" && revision != v.RevisionId {
			return errf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		if err := fn(f, v); err != nil {
			return err
		}
		v.RevisionId = newUUID()
		v.LastModified = isoMillis(h.now())
		v.LastUpdateStatus = "Successful"
		f.Dirty = true
		if err := saveVersion(c.ctx, tx, ref, 0, v); err != nil {
			return err
		}
		if err := saveFunction(c.ctx, tx, ref, f); err != nil {
			return err
		}
		return tx.Change("lambda", "UpdateFunction", ref.arn(), nil)
	})
	return f, v, err
}

func (h *Handler) updateFunctionConfiguration(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if ref.qualifier != "" {
		return nil, invalid("Unsupported function name: %s", c.params["FunctionName"])
	}
	if err := h.authorize(c, "UpdateFunctionConfiguration", ref.arn()); err != nil {
		return nil, err
	}
	var in functionInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := validateConfig(&in); err != nil {
		return nil, err
	}
	if in.Role != nil {
		if err := h.checkRole(c, *in.Role); err != nil {
			return nil, err
		}
	}
	_, v, err := h.updateLatest(c, ref, in.RevisionId, func(_ *function, v *version) error {
		if in.ImageConfig != nil && v.PackageType != "Image" {
			return invalid("ImageConfig is not supported for functions with packageType Zip.")
		}
		applyConfig(v, &in, false)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ok(200, v.out(ref.arn())), nil
}

type updateCodeInput struct {
	codeInput
	Publish       bool
	DryRun        bool
	RevisionId    string
	Architectures []string
}

func (h *Handler) updateFunctionCode(c *call) (*result, error) {
	ref, err := c.fnName()
	if err != nil {
		return nil, err
	}
	if ref.qualifier != "" {
		return nil, invalid("Unsupported function name: %s", c.params["FunctionName"])
	}
	if err := h.authorize(c, "UpdateFunctionCode", ref.arn()); err != nil {
		return nil, err
	}
	var in updateCodeInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if in.Architectures != nil {
		if err := validateConfig(&functionInput{Architectures: in.Architectures}); err != nil {
			return nil, err
		}
	}
	cur, _, err := resolve(c.ctx, h.st.DB(), fnRef{account: ref.account, region: ref.region, name: ref.name})
	if err != nil {
		return nil, err
	}
	cd, err := h.ingestCode(c, in.codeInput, cur.PackageType)
	if err != nil {
		return nil, err
	}
	defer cd.abort()
	if in.DryRun {
		v := *cur
		setCode(&v, cd)
		return ok(200, v.out(ref.arn())), nil
	}
	if cd.pending != nil {
		if err := cd.pending.Commit(); err != nil {
			return nil, err
		}
	}
	var out *version
	var arn string
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		f, err := mustFunction(c.ctx, tx, ref)
		if err != nil {
			return err
		}
		v, err := loadVersion(c.ctx, tx, ref, 0)
		if err != nil {
			return err
		}
		if in.RevisionId != "" && in.RevisionId != v.RevisionId {
			return errf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		setCode(v, cd)
		if in.Architectures != nil {
			v.Architectures = in.Architectures
		}
		v.RevisionId = newUUID()
		v.LastModified = isoMillis(h.now())
		v.LastUpdateStatus = "Successful"
		f.Dirty = true
		if err := saveVersion(c.ctx, tx, ref, 0, v); err != nil {
			return err
		}
		out, arn = v, ref.arn()
		if in.Publish {
			if out, err = publish(c.ctx, tx, ref, f, v, nil); err != nil {
				return err
			}
			arn = ref.qualifiedARN(out.Version)
		}
		if err := saveFunction(c.ctx, tx, ref, f); err != nil {
			return err
		}
		return tx.Change("lambda", "UpdateFunctionCode", ref.arn(), map[string]string{"sha": cd.sha})
	})
	if err != nil {
		return nil, err
	}
	return ok(200, out.out(arn)), nil
}

func (h *Handler) publishVersion(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "PublishVersion", ref.arn()); err != nil {
		return nil, err
	}
	var in struct {
		CodeSha256  string
		Description *string
		RevisionId  string
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	var out *version
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		f, err := loadFunction(c.ctx, tx, ref)
		if err != nil {
			return err
		}
		if f == nil {
			return functionNotFound(ref, "")
		}
		latest, err := loadVersion(c.ctx, tx, ref, 0)
		if err != nil {
			return err
		}
		if in.CodeSha256 != "" && in.CodeSha256 != latest.CodeSha256 {
			return invalid("CodeSHA256 (%s) is different from current CodeSHA256 in $LATEST (%s). Please try again with the CodeSHA256 in $LATEST.", in.CodeSha256, latest.CodeSha256)
		}
		if in.RevisionId != "" && in.RevisionId != latest.RevisionId {
			return errf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		if out, err = publish(c.ctx, tx, ref, f, latest, in.Description); err != nil {
			return err
		}
		if err := saveFunction(c.ctx, tx, ref, f); err != nil {
			return err
		}
		return tx.Change("lambda", "PublishVersion", ref.qualifiedARN(out.Version), nil)
	})
	if err != nil {
		return nil, err
	}
	return ok(201, out.out(ref.qualifiedARN(out.Version))), nil
}

func (h *Handler) listVersionsByFunction(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "ListVersionsByFunction", ref.arn()); err != nil {
		return nil, err
	}
	db := h.st.DB()
	if _, err := mustFunction(c.ctx, db, ref); err != nil {
		return nil, err
	}
	vs, err := listVersions(c.ctx, db, ref)
	if err != nil {
		return nil, err
	}
	maxItems, err := intParam(c.query, "MaxItems", 50)
	if err != nil {
		return nil, err
	}
	start := 0
	if m := c.query.Get("Marker"); m != "" {
		_, n, ok := decodeMarker(m)
		if !ok {
			return nil, invalid("Invalid marker: %s", m)
		}
		for start < len(vs) {
			num, _ := versionNumber(vs[start].Version)
			if num > n {
				break
			}
			start++
		}
	}
	out := map[string]any{}
	list := []Config{}
	for i := start; i < len(vs); i++ {
		if len(list) == maxItems {
			last := vs[i-1]
			n, _ := versionNumber(last.Version)
			out["NextMarker"] = encodeMarker(ref.name, n)
			break
		}
		list = append(list, vs[i].out(ref.qualifiedARN(vs[i].Version)))
	}
	out["Versions"] = list
	return ok(200, out), nil
}
