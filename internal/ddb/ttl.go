package ddb

import (
	"encoding/json"

	"citadel/internal/store"
)

// Time to Live configuration (UpdateTimeToLive, DescribeTimeToLive) and
// DescribeEndpoints. M3 stores the TTL setting; deleting expired items is a
// later step.

func init() {
	register("UpdateTimeToLive", (*Handler).updateTTL)
	register("DescribeTimeToLive", (*Handler).describeTTL)
	register("DescribeEndpoints", (*Handler).describeEndpoints)
}

type ttlSpec struct {
	AttributeName *string `json:"AttributeName"`
	Enabled       *bool   `json:"Enabled"`
}

type updateTTLInput struct {
	TableName               string          `json:"TableName"`
	TimeToLiveSpecification json.RawMessage `json:"TimeToLiveSpecification"`
}

func (h *Handler) updateTTL(c *call) (any, error) {
	var in updateTTLInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if in.TimeToLiveSpecification == nil {
		return nil, validation("1 validation error detected: Value null at 'timeToLiveSpecification' failed to satisfy constraint: Member must not be null")
	}
	var spec ttlSpec
	if err := json.Unmarshal(in.TimeToLiveSpecification, &spec); err != nil {
		return nil, errf(400, "SerializationException", "%v", err)
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	if spec.AttributeName == nil {
		return nil, validation("1 validation error detected: Value null at 'timeToLiveSpecification.attributeName' failed to satisfy constraint: Member must not be null")
	}
	if spec.Enabled == nil {
		return nil, validation("1 validation error detected: Value null at 'timeToLiveSpecification.enabled' failed to satisfy constraint: Member must not be null")
	}
	name := *spec.AttributeName
	if len(name) < 1 || len(name) > 255 {
		return nil, validation("1 validation error detected: Value '%s' at 'timeToLiveSpecification.attributeName' failed to satisfy constraint: Member must have length less than or equal to 255 and greater than or equal to 1", name)
	}
	switch {
	case *spec.Enabled && t.desc.TTLAttribute != "":
		return nil, validation("TimeToLive is active on a different AttributeName: current value of AttributeName is %s", t.desc.TTLAttribute)
	case !*spec.Enabled && t.desc.TTLAttribute == "":
		return nil, validation("TimeToLive is already disabled")
	case !*spec.Enabled && t.desc.TTLAttribute != name:
		return nil, validation("TimeToLive is active on a different AttributeName: current value of AttributeName is %s", t.desc.TTLAttribute)
	}
	if *spec.Enabled {
		t.desc.TTLAttribute = name
	} else {
		t.desc.TTLAttribute = ""
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if err := saveDesc(c, tx, t); err != nil {
			return err
		}
		return tx.Change("dynamodb", "UpdateTimeToLive", t.desc.TableName, map[string]any{"attribute": name, "enabled": *spec.Enabled})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"TimeToLiveSpecification": map[string]any{"AttributeName": name, "Enabled": *spec.Enabled}}, nil
}

func (h *Handler) describeTTL(c *call) (any, error) {
	var in tableNameInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	t, err := h.loadTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	d := map[string]any{"TimeToLiveStatus": "DISABLED"}
	if t.desc.TTLAttribute != "" {
		d = map[string]any{"TimeToLiveStatus": "ENABLED", "AttributeName": t.desc.TTLAttribute}
	}
	return map[string]any{"TimeToLiveDescription": d}, nil
}

func (h *Handler) describeEndpoints(c *call) (any, error) {
	return map[string]any{"Endpoints": []map[string]any{{
		"Address":              "dynamodb." + h.region + ".citadel.internal",
		"CachePeriodInMinutes": 1440,
	}}}, nil
}
