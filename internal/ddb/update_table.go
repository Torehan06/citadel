package ddb

import (
	"encoding/json"

	"citadel/internal/ddb/expr"
	"citadel/internal/store"
)

// UpdateTable: billing mode, provisioned throughput, streams, deletion
// protection and global secondary index changes.

type gsiUpdate struct {
	deletedID int         // idx of the index being deleted
	Create    *indexInput `json:"Create"`
	Delete    *struct {
		IndexName string `json:"IndexName"`
	} `json:"Delete"`
	Update *struct {
		IndexName             string      `json:"IndexName"`
		ProvisionedThroughput *throughput `json:"ProvisionedThroughput"`
	} `json:"Update"`
}

type updateTableInput struct {
	TableName                   string                       `json:"TableName"`
	AttributeDefinitions        []attrDef                    `json:"AttributeDefinitions"`
	BillingMode                 string                       `json:"BillingMode"`
	ProvisionedThroughput       *throughput                  `json:"ProvisionedThroughput"`
	GlobalSecondaryIndexUpdates []map[string]json.RawMessage `json:"GlobalSecondaryIndexUpdates"`
	StreamSpecification         *streamSpec                  `json:"StreamSpecification"`
	DeletionProtectionEnabled   *bool                        `json:"DeletionProtectionEnabled"`
	TableClass                  string                       `json:"TableClass"`
	ReplicaUpdates              []interface{}                `json:"ReplicaUpdates"`
}

func (h *Handler) updateTable(c *call) (any, error) {
	var in updateTableInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if in.ReplicaUpdates != nil {
		return nil, errf(501, "NotImplemented", "citadel: global table replicas arrive with multi-region replication")
	}
	if in.BillingMode == "" && in.ProvisionedThroughput == nil && in.GlobalSecondaryIndexUpdates == nil &&
		in.StreamSpecification == nil && in.DeletionProtectionEnabled == nil && in.TableClass == "" {
		return nil, validation("At least one of ProvisionedThroughput, BillingMode, UpdateStreamEnabled, GlobalSecondaryIndexUpdates or SSESpecification or ReplicaUpdates is required")
	}
	switch in.BillingMode {
	case "":
	case "PAY_PER_REQUEST":
		if in.ProvisionedThroughput != nil {
			return nil, validation("One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST")
		}
		t.desc.BillingMode, t.desc.Provisioned = "PAY_PER_REQUEST", nil
	case "PROVISIONED":
		if in.ProvisionedThroughput == nil {
			return nil, validation("One or more parameter values were invalid: ProvisionedThroughput must be specified when BillingMode is PROVISIONED")
		}
		t.desc.BillingMode = "PROVISIONED"
	default:
		return nil, validation("1 validation error detected: Value '%s' at 'billingMode' failed to satisfy constraint: Member must satisfy enum value set: [PROVISIONED, PAY_PER_REQUEST]", in.BillingMode)
	}
	if in.ProvisionedThroughput != nil {
		if t.desc.BillingMode == "PAY_PER_REQUEST" {
			return nil, validation("One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST")
		}
		if err := validateThroughput(in.ProvisionedThroughput); err != nil {
			return nil, err
		}
		t.desc.Provisioned = in.ProvisionedThroughput
	}
	if s := in.StreamSpecification; s != nil {
		if s.StreamEnabled && s.StreamViewType == "" {
			return nil, validation("One or more parameter values were invalid: You must specify a StreamViewType when enabling a stream")
		}
		if s.StreamEnabled {
			t.desc.Stream = s
		} else {
			t.desc.Stream = nil
		}
	}
	if in.DeletionProtectionEnabled != nil {
		t.desc.DeletionProtection = *in.DeletionProtectionEnabled
	}
	if in.TableClass != "" {
		t.desc.TableClass = in.TableClass
	}
	var gu *gsiUpdate
	if in.GlobalSecondaryIndexUpdates != nil {
		if gu, err = parseGSIUpdates(in.GlobalSecondaryIndexUpdates); err != nil {
			return nil, err
		}
		if in.StreamSpecification != nil && (gu.Create != nil || gu.Delete != nil) {
			return nil, validation("One or more parameter values were invalid: cannot create or delete index while changing stream status")
		}
	}
	var backfill *indexDef
	if gu != nil {
		if backfill, err = applyGSIUpdate(t, gu, in.AttributeDefinitions); err != nil {
			return nil, err
		}
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if gu != nil && gu.Delete != nil {
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM ddb_items WHERE table_id = ? AND idx = ?`, t.id, gu.deletedID); err != nil {
				return err
			}
		}
		if backfill != nil {
			if err := backfillIndex(c, tx, t, *backfill); err != nil {
				return err
			}
		}
		if err := saveDesc(c, tx, t); err != nil {
			return err
		}
		return tx.Change("dynamodb", "UpdateTable", t.desc.TableName, nil)
	})
	if err != nil {
		return nil, err
	}
	d, err := h.describe(c, t, "UPDATING")
	if err != nil {
		return nil, err
	}
	return map[string]any{"TableDescription": d}, nil
}

// parseGSIUpdates checks the shape of GlobalSecondaryIndexUpdates: every
// entry holds exactly one of Create/Update/Delete, and one UpdateTable may
// create or delete at most one index.
func parseGSIUpdates(raw []map[string]json.RawMessage) (*gsiUpdate, error) {
	if len(raw) == 0 {
		return nil, validation("One or more parameter values were invalid: GlobalSecondaryIndexUpdates must not be empty")
	}
	var out gsiUpdate
	creates := 0
	for _, entry := range raw {
		if len(entry) == 0 {
			return nil, validation("One or more parameter values were invalid: One of GlobalSecondaryIndexUpdate.Create, GlobalSecondaryIndexUpdate.Update or GlobalSecondaryIndexUpdate.Delete must be specified")
		}
		if len(entry) > 1 {
			return nil, validation("One or more parameter values were invalid: Only one of GlobalSecondaryIndexUpdate.Create, GlobalSecondaryIndexUpdate.Update or GlobalSecondaryIndexUpdate.Delete may be specified per GlobalSecondaryIndexUpdate")
		}
		for k, v := range entry {
			switch k {
			case "Create":
				if err := json.Unmarshal(v, &out.Create); err != nil {
					return nil, asError(err)
				}
				creates++
			case "Delete":
				if err := json.Unmarshal(v, &out.Delete); err != nil {
					return nil, asError(err)
				}
				creates++
			case "Update":
				if err := json.Unmarshal(v, &out.Update); err != nil {
					return nil, asError(err)
				}
			default:
				return nil, validation("One or more parameter values were invalid: Unknown operation %s in GlobalSecondaryIndexUpdate", k)
			}
		}
	}
	if creates > 1 {
		return nil, errf(400, "LimitExceededException", "Subscriber limit exceeded: Only 1 online index can be created or deleted simultaneously per table")
	}
	return &out, nil
}

// applyGSIUpdate changes t.desc; it returns the new index when one needs a
// backfill.
func applyGSIUpdate(t *table, gu *gsiUpdate, newDefs []attrDef) (*indexDef, error) {
	defs := map[string]string{}
	for _, d := range t.desc.AttributeDefinitions {
		defs[d.AttributeName] = d.AttributeType
	}
	for _, d := range newDefs {
		if old, ok := defs[d.AttributeName]; ok && old != d.AttributeType {
			return nil, validation("One or more parameter values were invalid: Attribute %s is redefined with a different type (%s, was %s)", d.AttributeName, d.AttributeType, old)
		}
		if d.AttributeType != "S" && d.AttributeType != "N" && d.AttributeType != "B" {
			return nil, validation("1 validation error detected: Value '%s' at 'attributeDefinitions.member.attributeType' failed to satisfy constraint: Member must satisfy enum value set: [B, N, S]", d.AttributeType)
		}
		defs[d.AttributeName] = d.AttributeType
	}
	switch {
	case gu.Create != nil:
		if _, exists := t.findIndex(gu.Create.IndexName); exists {
			return nil, validation("One or more parameter values were invalid: Index with name %s already exists", gu.Create.IndexName)
		}
		used := map[string]bool{}
		billing := t.desc.BillingMode
		d, err := buildIndex(*gu.Create, defs, used, billing, "globalSecondaryIndexUpdates.member.create")
		if err != nil {
			return nil, err
		}
		for name := range used {
			if t.attrType(name) == "" {
				t.desc.AttributeDefinitions = append(t.desc.AttributeDefinitions, attrDef{AttributeName: name, AttributeType: defs[name]})
			}
		}
		d.ID = t.desc.NextIndexID
		t.desc.NextIndexID++
		t.desc.GSIs = append(t.desc.GSIs, d)
		return &d, nil
	case gu.Delete != nil:
		for i, g := range t.desc.GSIs {
			if g.IndexName == gu.Delete.IndexName {
				gu.deletedID = g.ID
				t.desc.GSIs = append(t.desc.GSIs[:i:i], t.desc.GSIs[i+1:]...)
				pruneAttributeDefinitions(t)
				return nil, nil
			}
		}
		return nil, notFound("Requested resource not found: Index: %s not found", gu.Delete.IndexName)
	case gu.Update != nil:
		for i, g := range t.desc.GSIs {
			if g.IndexName == gu.Update.IndexName {
				if gu.Update.ProvisionedThroughput != nil {
					t.desc.GSIs[i].ProvisionedThroughput = gu.Update.ProvisionedThroughput
				}
				return nil, nil
			}
		}
		return nil, notFound("Requested resource not found: Index: %s not found", gu.Update.IndexName)
	}
	return nil, nil
}

// pruneAttributeDefinitions drops definitions no key schema uses anymore.
func pruneAttributeDefinitions(t *table) {
	used := map[string]bool{}
	for _, k := range t.desc.KeySchema {
		used[k.AttributeName] = true
	}
	for _, ix := range t.indexes() {
		for _, k := range ix.def.KeySchema {
			used[k.AttributeName] = true
		}
	}
	var keep []attrDef
	for _, d := range t.desc.AttributeDefinitions {
		if used[d.AttributeName] {
			keep = append(keep, d)
		}
	}
	t.desc.AttributeDefinitions = keep
}

// backfillIndex adds every existing item to a new index. Items whose index
// key attribute has the wrong type or an invalid value are left out, as
// DynamoDB does during a backfill (new writes with such values are
// rejected instead).
func backfillIndex(c *call, tx *store.Tx, t *table, d indexDef) error {
	ix := index{def: d, global: true}
	rows, err := tx.QueryContext(c.ctx, `SELECT pk, sk, item FROM ddb_items WHERE table_id = ? AND idx = 0`, t.id)
	if err != nil {
		return err
	}
	type pending struct {
		k  itemKey
		it expr.Item
	}
	var all []pending
	for rows.Next() {
		var p pending
		var raw []byte
		if err := rows.Scan(&p.k.pk, &p.k.sk, &raw); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal(raw, &p.it); err != nil {
			rows.Close()
			return err
		}
		all = append(all, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range all {
		ik, ok, err := t.indexKey(ix, p.it)
		if err != nil || !ok {
			continue
		}
		proj := t.projectForIndex(ix, p.it)
		raw, _ := json.Marshal(proj)
		if _, err := tx.ExecContext(c.ctx, `INSERT OR REPLACE INTO ddb_items(table_id, idx, pk, sk, bk, item, size) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.id, d.ID, ik.pk, nonNil(ik.sk), p.k.baseKey(), raw, proj.Size()); err != nil {
			return err
		}
	}
	return nil
}
