package ddb

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"citadel/internal/store"
)

// Table management: CreateTable, DescribeTable, DeleteTable, ListTables,
// UpdateTable. Tables become ACTIVE immediately: CreateTable and
// UpdateTable answer CREATING/UPDATING as DynamoDB does, and the next
// DescribeTable shows ACTIVE.

type keyElem struct {
	AttributeName string `json:"AttributeName"`
	KeyType       string `json:"KeyType"`
}

type attrDef struct {
	AttributeName string `json:"AttributeName"`
	AttributeType string `json:"AttributeType"`
}

type throughput struct {
	ReadCapacityUnits  int64 `json:"ReadCapacityUnits"`
	WriteCapacityUnits int64 `json:"WriteCapacityUnits"`
}

type projection struct {
	ProjectionType   string   `json:"ProjectionType,omitempty"`
	NonKeyAttributes []string `json:"NonKeyAttributes,omitempty"`
}

type indexDef struct {
	IndexName             string      `json:"IndexName"`
	KeySchema             []keyElem   `json:"KeySchema"`
	Projection            projection  `json:"Projection"`
	ProvisionedThroughput *throughput `json:"ProvisionedThroughput,omitempty"`
	// ID is the idx under which this index's rows are stored (never reused).
	ID int `json:"CitadelID"`
}

type streamSpec struct {
	StreamEnabled  bool   `json:"StreamEnabled"`
	StreamViewType string `json:"StreamViewType,omitempty"`
}

type tagKV struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// tableDesc is what desc_json holds.
type tableDesc struct {
	TableName            string      `json:"TableName"`
	TableID              string      `json:"TableId"`
	KeySchema            []keyElem   `json:"KeySchema"`
	AttributeDefinitions []attrDef   `json:"AttributeDefinitions"`
	BillingMode          string      `json:"BillingMode"`
	Provisioned          *throughput `json:"ProvisionedThroughput,omitempty"`
	GSIs                 []indexDef  `json:"GlobalSecondaryIndexes,omitempty"`
	LSIs                 []indexDef  `json:"LocalSecondaryIndexes,omitempty"`
	Stream               *streamSpec `json:"StreamSpecification,omitempty"`
	TTLAttribute         string      `json:"TTLAttribute,omitempty"`
	Tags                 []tagKV     `json:"Tags,omitempty"`
	DeletionProtection   bool        `json:"DeletionProtectionEnabled,omitempty"`
	TableClass           string      `json:"TableClass,omitempty"`
	NextIndexID          int         `json:"NextIndexID"`
}

// table is a loaded table: its row id, account and description.
type table struct {
	id      int64
	account string
	created time.Time
	desc    tableDesc
}

func (t *table) hashKey() string { return t.desc.KeySchema[0].AttributeName }

func (t *table) rangeKey() string {
	if len(t.desc.KeySchema) > 1 {
		return t.desc.KeySchema[1].AttributeName
	}
	return ""
}

func (t *table) attrType(name string) string {
	for _, d := range t.desc.AttributeDefinitions {
		if d.AttributeName == name {
			return d.AttributeType
		}
	}
	return ""
}

func (h *Handler) arn(account, name string) string {
	return fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", h.region, account, name)
}

var tableNameRE = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func validateTableName(name, field string) error {
	switch {
	case len(name) < 3:
		return validation("1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must have length greater than or equal to 3", name, field)
	case len(name) > 255:
		return validation("1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must have length less than or equal to 255", name, field)
	case !tableNameRE.MatchString(name):
		return validation("1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+", name, field)
	}
	return nil
}

// loadTable finds a table by name in the caller's account.
func (h *Handler) loadTable(c *call, name string) (*table, error) {
	if name == "" {
		return nil, validation("1 validation error detected: Value null at 'tableName' failed to satisfy constraint: Member must not be null")
	}
	if err := validateTableName(name, "tableName"); err != nil {
		return nil, err
	}
	var t table
	var created int64
	var desc string
	err := h.st.DB().QueryRowContext(c.ctx,
		`SELECT id, account_id, created, desc_json FROM ddb_tables WHERE account_id = ? AND name = ?`, c.account, name).
		Scan(&t.id, &t.account, &created, &desc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("Requested resource not found: Table: %s not found", name)
	}
	if err != nil {
		return nil, err
	}
	t.created = time.UnixMilli(created)
	if err := json.Unmarshal([]byte(desc), &t.desc); err != nil {
		return nil, err
	}
	return &t, nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---- CreateTable ------------------------------------------------------------

type indexInput struct {
	IndexName             string      `json:"IndexName"`
	KeySchema             []keyElem   `json:"KeySchema"`
	Projection            *projection `json:"Projection"`
	ProvisionedThroughput *throughput `json:"ProvisionedThroughput"`
}

type createTableInput struct {
	TableName                 string       `json:"TableName"`
	KeySchema                 []keyElem    `json:"KeySchema"`
	AttributeDefinitions      []attrDef    `json:"AttributeDefinitions"`
	BillingMode               string       `json:"BillingMode"`
	ProvisionedThroughput     *throughput  `json:"ProvisionedThroughput"`
	GlobalSecondaryIndexes    []indexInput `json:"GlobalSecondaryIndexes"`
	LocalSecondaryIndexes     []indexInput `json:"LocalSecondaryIndexes"`
	StreamSpecification       *streamSpec  `json:"StreamSpecification"`
	Tags                      []tagKV      `json:"Tags"`
	DeletionProtectionEnabled bool         `json:"DeletionProtectionEnabled"`
	TableClass                string       `json:"TableClass"`
	SSESpecification          *struct{}    `json:"SSESpecification"`
	OnDemandThroughput        *struct{}    `json:"OnDemandThroughput"`
	WarmThroughput            *struct{}    `json:"WarmThroughput"`
	ResourcePolicy            *string      `json:"ResourcePolicy"`
}

// validateKeySchema checks a table or index key schema against the
// attribute definitions. It returns the attribute names it uses.
func validateKeySchema(ks []keyElem, defs map[string]string, what string) ([]string, error) {
	if len(ks) == 0 {
		return nil, validation("1 validation error detected: Value null at '%s' failed to satisfy constraint: Member must not be null", what)
	}
	if len(ks) > 2 {
		return nil, validation("1 validation error detected: Value '%v' at '%s' failed to satisfy constraint: Member must have length less than or equal to 2", ks, what)
	}
	if ks[0].KeyType != "HASH" {
		return nil, validation("Invalid KeySchema: The first KeySchemaElement is not a HASH key type")
	}
	if len(ks) == 2 {
		if ks[1].KeyType != "RANGE" {
			return nil, validation("Invalid KeySchema: The second KeySchemaElement is not a RANGE key type")
		}
		if ks[0].AttributeName == ks[1].AttributeName {
			return nil, validation("Invalid KeySchema: Some index key attribute have no definition, or are defined twice")
		}
	}
	var names []string
	for _, k := range ks {
		if k.AttributeName == "" {
			return nil, validation("1 validation error detected: Value null at '%s.member.attributeName' failed to satisfy constraint: Member must not be null", what)
		}
		if len(k.AttributeName) > 255 {
			return nil, validation("One or more parameter values were invalid: Key attribute name %s is longer than 255 characters", k.AttributeName[:10]+"...")
		}
		if _, ok := defs[k.AttributeName]; !ok {
			return nil, validation("One or more parameter values were invalid: Some index key attributes are not defined in AttributeDefinitions. Keys: [%s], AttributeDefinitions: %v", k.AttributeName, sortedKeys(defs))
		}
		names = append(names, k.AttributeName)
	}
	return names, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validateThroughput(tp *throughput) error {
	if tp.ReadCapacityUnits < 1 || tp.WriteCapacityUnits < 1 {
		return validation("One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits must both be specified and greater than 0")
	}
	return nil
}

func buildIndex(in indexInput, defs map[string]string, used map[string]bool, billing string, what string) (indexDef, error) {
	if in.IndexName == "" {
		return indexDef{}, validation("1 validation error detected: Value null at '%s.member.indexName' failed to satisfy constraint: Member must not be null", what)
	}
	if len(in.IndexName) < 3 || len(in.IndexName) > 255 || !tableNameRE.MatchString(in.IndexName) {
		return indexDef{}, validation("1 validation error detected: Value '%s' at '%s.member.indexName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+ and length between 3 and 255", in.IndexName, what)
	}
	names, err := validateKeySchema(in.KeySchema, defs, what+".member.keySchema")
	if err != nil {
		return indexDef{}, err
	}
	for _, n := range names {
		used[n] = true
	}
	if in.Projection == nil || in.Projection.ProjectionType == "" {
		return indexDef{}, validation("1 validation error detected: Value null at '%s.member.projection' failed to satisfy constraint: Member must not be null", what)
	}
	switch in.Projection.ProjectionType {
	case "ALL", "KEYS_ONLY":
		if len(in.Projection.NonKeyAttributes) > 0 {
			return indexDef{}, validation("One or more parameter values were invalid: ProjectionType is %s, but NonKeyAttributes is specified", in.Projection.ProjectionType)
		}
	case "INCLUDE":
		if len(in.Projection.NonKeyAttributes) == 0 {
			return indexDef{}, validation("One or more parameter values were invalid: ProjectionType is INCLUDE, but NonKeyAttributes is not specified")
		}
	default:
		return indexDef{}, validation("1 validation error detected: Value '%s' at '%s.member.projection.projectionType' failed to satisfy constraint: Member must satisfy enum value set: [ALL, INCLUDE, KEYS_ONLY]", in.Projection.ProjectionType, what)
	}
	d := indexDef{IndexName: in.IndexName, KeySchema: in.KeySchema, Projection: *in.Projection}
	if billing == "PROVISIONED" {
		if in.ProvisionedThroughput == nil {
			return indexDef{}, validation("One or more parameter values were invalid: ProvisionedThroughput must be specified for index: %s", in.IndexName)
		}
		if err := validateThroughput(in.ProvisionedThroughput); err != nil {
			return indexDef{}, err
		}
		d.ProvisionedThroughput = in.ProvisionedThroughput
	} else if in.ProvisionedThroughput != nil {
		return indexDef{}, validation("One or more parameter values were invalid: ProvisionedThroughput should not be specified for index: %s when BillingMode is PAY_PER_REQUEST", in.IndexName)
	}
	return d, nil
}

func init() {
	register("CreateTable", (*Handler).createTable)
	register("DescribeTable", (*Handler).describeTable)
	register("DeleteTable", (*Handler).deleteTable)
	register("ListTables", (*Handler).listTables)
	register("UpdateTable", (*Handler).updateTable)
}

func (h *Handler) createTable(c *call) (any, error) {
	var in createTableInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if in.TableName == "" {
		return nil, validation("1 validation error detected: Value null at 'tableName' failed to satisfy constraint: Member must not be null")
	}
	if err := validateTableName(in.TableName, "tableName"); err != nil {
		return nil, err
	}
	if len(in.AttributeDefinitions) == 0 {
		return nil, validation("1 validation error detected: Value null at 'attributeDefinitions' failed to satisfy constraint: Member must not be null")
	}
	defs := map[string]string{}
	if err := checkKeyNameLengths(in); err != nil {
		return nil, err
	}
	for _, d := range in.AttributeDefinitions {
		if d.AttributeName == "" {
			return nil, validation("1 validation error detected: Value null at 'attributeDefinitions.member.attributeName' failed to satisfy constraint: Member must not be null")
		}
		if d.AttributeType != "S" && d.AttributeType != "N" && d.AttributeType != "B" {
			return nil, validation("1 validation error detected: Value '%s' at 'attributeDefinitions.member.attributeType' failed to satisfy constraint: Member must satisfy enum value set: [B, N, S]", d.AttributeType)
		}
		if _, dup := defs[d.AttributeName]; dup {
			return nil, validation("Cannot have two attributes with the same name: Duplicate attribute name: %s", d.AttributeName)
		}
		defs[d.AttributeName] = d.AttributeType
	}
	used := map[string]bool{}
	names, err := validateKeySchema(in.KeySchema, defs, "keySchema")
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		used[n] = true
	}
	billing := in.BillingMode
	if billing == "" {
		billing = "PROVISIONED"
	}
	desc := tableDesc{
		TableName: in.TableName, TableID: newUUID(), KeySchema: in.KeySchema, AttributeDefinitions: in.AttributeDefinitions,
		BillingMode: billing, Stream: in.StreamSpecification, Tags: in.Tags,
		DeletionProtection: in.DeletionProtectionEnabled, TableClass: in.TableClass, NextIndexID: 1,
	}
	switch billing {
	case "PROVISIONED":
		if in.ProvisionedThroughput == nil {
			return nil, validation("One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits must both be specified when BillingMode is PROVISIONED")
		}
		if err := validateThroughput(in.ProvisionedThroughput); err != nil {
			return nil, err
		}
		desc.Provisioned = in.ProvisionedThroughput
	case "PAY_PER_REQUEST":
		if in.ProvisionedThroughput != nil {
			return nil, validation("One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST")
		}
	default:
		return nil, validation("1 validation error detected: Value '%s' at 'billingMode' failed to satisfy constraint: Member must satisfy enum value set: [PROVISIONED, PAY_PER_REQUEST]", billing)
	}
	indexNames := map[string]bool{}
	for _, gi := range in.GlobalSecondaryIndexes {
		d, err := buildIndex(gi, defs, used, billing, "globalSecondaryIndexes")
		if err != nil {
			return nil, err
		}
		if indexNames[d.IndexName] {
			return nil, validation("One or more parameter values were invalid: Duplicate index name: %s", d.IndexName)
		}
		indexNames[d.IndexName] = true
		d.ID = desc.NextIndexID
		desc.NextIndexID++
		desc.GSIs = append(desc.GSIs, d)
	}
	if in.GlobalSecondaryIndexes != nil && len(in.GlobalSecondaryIndexes) == 0 {
		return nil, validation("One or more parameter values were invalid: List of GlobalSecondaryIndexes is empty")
	}
	for _, li := range in.LocalSecondaryIndexes {
		d, err := buildIndex(li, defs, used, "PAY_PER_REQUEST", "localSecondaryIndexes")
		if err != nil {
			return nil, err
		}
		if len(d.KeySchema) != 2 || d.KeySchema[0].AttributeName != desc.KeySchema[0].AttributeName {
			return nil, validation("One or more parameter values were invalid: Index KeySchema does not have a range key for index: %s", d.IndexName)
		}
		if len(desc.KeySchema) != 2 {
			return nil, validation("One or more parameter values were invalid: Table KeySchema does not have a range key, which is required when specifying a LocalSecondaryIndex")
		}
		if indexNames[d.IndexName] {
			return nil, validation("One or more parameter values were invalid: Duplicate index name: %s", d.IndexName)
		}
		indexNames[d.IndexName] = true
		d.ID = desc.NextIndexID
		desc.NextIndexID++
		desc.LSIs = append(desc.LSIs, d)
	}
	if in.LocalSecondaryIndexes != nil && len(in.LocalSecondaryIndexes) == 0 {
		return nil, validation("One or more parameter values were invalid: List of LocalSecondaryIndexes is empty")
	}
	if len(used) != len(defs) {
		return nil, validation("One or more parameter values were invalid: Number of attributes in KeySchema does not exactly match number of attributes defined in AttributeDefinitions")
	}
	if s := in.StreamSpecification; s != nil && s.StreamEnabled {
		switch s.StreamViewType {
		case "KEYS_ONLY", "NEW_IMAGE", "OLD_IMAGE", "NEW_AND_OLD_IMAGES":
		default:
			return nil, validation("One or more parameter values were invalid: You must specify a StreamViewType when enabling a stream")
		}
	}
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}

	raw, _ := json.Marshal(desc)
	var t *table
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		var one int
		if err := tx.QueryRowContext(c.ctx, `SELECT 1 FROM ddb_tables WHERE account_id = ? AND name = ?`, c.account, in.TableName).Scan(&one); err == nil {
			return errf(400, "ResourceInUseException", "Table already exists: %s", in.TableName)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		res, err := tx.ExecContext(c.ctx, `INSERT INTO ddb_tables(account_id, name, created, desc_json, hlc) VALUES (?, ?, ?, ?, ?)`,
			c.account, in.TableName, tx.HLC().WallMs(), string(raw), int64(tx.HLC()))
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		t = &table{id: id, account: c.account, created: tx.HLC().Time(), desc: desc}
		return tx.Change("dynamodb", "CreateTable", in.TableName, map[string]any{"account": c.account})
	})
	if err != nil {
		return nil, err
	}
	d, err := h.describe(c, t, "CREATING")
	if err != nil {
		return nil, err
	}
	return map[string]any{"TableDescription": d}, nil
}

// ---- DescribeTable ------------------------------------------------------------

func (h *Handler) describe(c *call, t *table, status string) (map[string]any, error) {
	var count, size int64
	if err := h.st.DB().QueryRowContext(c.ctx,
		`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM ddb_items WHERE table_id = ? AND idx = 0`, t.id).Scan(&count, &size); err != nil {
		return nil, err
	}
	created := float64(t.created.UnixMilli()) / 1000
	d := map[string]any{
		"TableName":            t.desc.TableName,
		"TableId":              t.desc.TableID,
		"TableArn":             h.arn(t.account, t.desc.TableName),
		"TableStatus":          status,
		"KeySchema":            t.desc.KeySchema,
		"AttributeDefinitions": t.desc.AttributeDefinitions,
		"CreationDateTime":     created,
		"ItemCount":            count,
		"TableSizeBytes":       size,
	}
	pt := map[string]any{"ReadCapacityUnits": 0, "WriteCapacityUnits": 0, "NumberOfDecreasesToday": 0}
	if t.desc.Provisioned != nil {
		pt["ReadCapacityUnits"], pt["WriteCapacityUnits"] = t.desc.Provisioned.ReadCapacityUnits, t.desc.Provisioned.WriteCapacityUnits
		d["BillingModeSummary"] = map[string]any{"BillingMode": "PROVISIONED"}
	} else {
		d["BillingModeSummary"] = map[string]any{"BillingMode": "PAY_PER_REQUEST", "LastUpdateToPayPerRequestDateTime": created}
	}
	d["ProvisionedThroughput"] = pt
	if len(t.desc.GSIs) > 0 {
		var gs []map[string]any
		for _, g := range t.desc.GSIs {
			gs = append(gs, h.describeIndex(c, t, g, true))
		}
		d["GlobalSecondaryIndexes"] = gs
	}
	if len(t.desc.LSIs) > 0 {
		var ls []map[string]any
		for _, l := range t.desc.LSIs {
			ls = append(ls, h.describeIndex(c, t, l, false))
		}
		d["LocalSecondaryIndexes"] = ls
	}
	if s := t.desc.Stream; s != nil && s.StreamEnabled {
		d["StreamSpecification"] = s
		d["LatestStreamLabel"] = t.created.UTC().Format("2006-01-02T15:04:05.000")
		d["LatestStreamArn"] = h.arn(t.account, t.desc.TableName) + "/stream/" + d["LatestStreamLabel"].(string)
	}
	if t.desc.DeletionProtection {
		d["DeletionProtectionEnabled"] = true
	}
	if t.desc.TableClass != "" {
		d["TableClassSummary"] = map[string]any{"TableClass": t.desc.TableClass}
	}
	return d, nil
}

func (h *Handler) describeIndex(c *call, t *table, ix indexDef, global bool) map[string]any {
	var count, size int64
	_ = h.st.DB().QueryRowContext(c.ctx,
		`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM ddb_items WHERE table_id = ? AND idx = ?`, t.id, ix.ID).Scan(&count, &size)
	d := map[string]any{
		"IndexName":      ix.IndexName,
		"KeySchema":      ix.KeySchema,
		"Projection":     ix.Projection,
		"IndexArn":       h.arn(t.account, t.desc.TableName) + "/index/" + ix.IndexName,
		"ItemCount":      count,
		"IndexSizeBytes": size,
	}
	if global {
		d["IndexStatus"] = "ACTIVE"
		pt := map[string]any{"ReadCapacityUnits": 0, "WriteCapacityUnits": 0, "NumberOfDecreasesToday": 0}
		if ix.ProvisionedThroughput != nil {
			pt["ReadCapacityUnits"], pt["WriteCapacityUnits"] = ix.ProvisionedThroughput.ReadCapacityUnits, ix.ProvisionedThroughput.WriteCapacityUnits
		}
		d["ProvisionedThroughput"] = pt
	}
	return d
}

type tableNameInput struct {
	TableName string `json:"TableName"`
}

func (h *Handler) describeTable(c *call) (any, error) {
	var in tableNameInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	d, err := h.describe(c, t, "ACTIVE")
	if err != nil {
		return nil, err
	}
	return map[string]any{"Table": d}, nil
}

func (h *Handler) deleteTable(c *call) (any, error) {
	var in tableNameInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if t.desc.DeletionProtection {
		return nil, validation("Resource cannot be deleted as it is currently protected against deletion. Disable deletion protection first.")
	}
	d, err := h.describe(c, t, "DELETING")
	if err != nil {
		return nil, err
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM ddb_items WHERE table_id = ?`, t.id); err != nil {
			return err
		}
		res, err := tx.ExecContext(c.ctx, `DELETE FROM ddb_tables WHERE id = ?`, t.id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return notFound("Requested resource not found: Table: %s not found", in.TableName)
		}
		return tx.Change("dynamodb", "DeleteTable", in.TableName, map[string]any{"account": c.account})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"TableDescription": d}, nil
}

type listTablesInput struct {
	ExclusiveStartTableName string `json:"ExclusiveStartTableName"`
	Limit                   *int   `json:"Limit"`
}

func (h *Handler) listTables(c *call) (any, error) {
	var in listTablesInput
	if len(c.body) > 0 {
		if err := decode(c, &in); err != nil {
			return nil, err
		}
	}
	limit := 100
	if in.Limit != nil {
		if *in.Limit < 1 || *in.Limit > 100 {
			return nil, validation("1 validation error detected: Value '%d' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 100 and greater than or equal to 1", *in.Limit)
		}
		limit = *in.Limit
	}
	rows, err := h.st.DB().QueryContext(c.ctx,
		`SELECT name FROM ddb_tables WHERE account_id = ? AND name > ? ORDER BY name LIMIT ?`,
		c.account, in.ExclusiveStartTableName, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	out := map[string]any{}
	if len(names) > limit {
		names = names[:limit]
		out["LastEvaluatedTableName"] = names[limit-1]
	}
	out["TableNames"] = names
	return out, rows.Err()
}

// saveDesc writes a table's description back.
func saveDesc(c *call, tx *store.Tx, t *table) error {
	raw, _ := json.Marshal(t.desc)
	_, err := tx.ExecContext(c.ctx, `UPDATE ddb_tables SET desc_json = ?, hlc = ? WHERE id = ?`, string(raw), int64(tx.HLC()), t.id)
	return err
}

// checkKeyNameLengths rejects key attribute names over 255 characters before
// any other schema check, so the error names the real problem.
func checkKeyNameLengths(in createTableInput) error {
	check := func(ks []keyElem) error {
		for _, k := range ks {
			if len(k.AttributeName) > 255 {
				return validation("One or more parameter values were invalid: Key attribute name is longer than 255 characters")
			}
		}
		return nil
	}
	if err := check(in.KeySchema); err != nil {
		return err
	}
	for _, ix := range append(append([]indexInput{}, in.GlobalSecondaryIndexes...), in.LocalSecondaryIndexes...) {
		if err := check(ix.KeySchema); err != nil {
			return err
		}
	}
	return nil
}
