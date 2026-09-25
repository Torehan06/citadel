package ddb

import (
	"citadel/internal/store"
)

// UpdateTable: billing mode, provisioned throughput, streams, deletion
// protection and global secondary index changes.

type gsiUpdate struct {
	Create *indexInput `json:"Create"`
	Delete *struct {
		IndexName string `json:"IndexName"`
	} `json:"Delete"`
	Update *struct {
		IndexName             string      `json:"IndexName"`
		ProvisionedThroughput *throughput `json:"ProvisionedThroughput"`
	} `json:"Update"`
}

type updateTableInput struct {
	TableName                   string        `json:"TableName"`
	AttributeDefinitions        []attrDef     `json:"AttributeDefinitions"`
	BillingMode                 string        `json:"BillingMode"`
	ProvisionedThroughput       *throughput   `json:"ProvisionedThroughput"`
	GlobalSecondaryIndexUpdates []gsiUpdate   `json:"GlobalSecondaryIndexUpdates"`
	StreamSpecification         *streamSpec   `json:"StreamSpecification"`
	DeletionProtectionEnabled   *bool         `json:"DeletionProtectionEnabled"`
	TableClass                  string        `json:"TableClass"`
	ReplicaUpdates              []interface{} `json:"ReplicaUpdates"`
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
	if len(in.GlobalSecondaryIndexUpdates) > 0 {
		return nil, errf(501, "NotImplemented", "citadel: GlobalSecondaryIndexUpdates is not implemented yet")
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
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
