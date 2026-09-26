package ddb

import (
	"encoding/json"
	"errors"
	"time"

	"citadel/internal/store"
)

// Point-in-time recovery settings: DescribeContinuousBackups and
// UpdateContinuousBackups. Citadel records the setting and reports AWS's
// restore window; restoring to a point in time is not implemented.

func init() {
	register("DescribeContinuousBackups", (*Handler).describeContinuousBackups)
	register("UpdateContinuousBackups", (*Handler).updateContinuousBackups)
}

// pitrState lives in the table description.
type pitrState struct {
	Enabled bool  `json:"Enabled"`
	Days    int   `json:"Days,omitempty"`
	Since   int64 `json:"Since,omitempty"` // unix ms PITR was (re-)enabled
	// Continuous backups switch on with the first PITR enablement and stay on,
	// as AWS reports ENABLED after PITR is disabled again.
	Continuous bool `json:"Continuous,omitempty"`
}

const defaultRecoveryDays = 35

// loadBackupTable is loadTable with the error DynamoDB's backup APIs use for
// a missing table.
func (h *Handler) loadBackupTable(c *call, name string) (*table, error) {
	t, err := h.loadTable(c, name)
	var e *Error
	if errors.As(err, &e) && e.Code == "ResourceNotFoundException" {
		return nil, errf(400, "TableNotFoundException", "Table not found: %s", name)
	}
	return t, err
}

func continuousBackupsDescription(p *pitrState, now time.Time) map[string]any {
	status, pitr := "DISABLED", map[string]any{"PointInTimeRecoveryStatus": "DISABLED"}
	if p != nil && p.Continuous {
		status = "ENABLED"
	}
	if p != nil && p.Enabled {
		pitr = map[string]any{
			"PointInTimeRecoveryStatus":  "ENABLED",
			"RecoveryPeriodInDays":       p.Days,
			"EarliestRestorableDateTime": float64(p.Since) / 1000,
			"LatestRestorableDateTime":   float64(now.UnixMilli()) / 1000,
		}
	}
	return map[string]any{"ContinuousBackupsStatus": status, "PointInTimeRecoveryDescription": pitr}
}

func (h *Handler) describeContinuousBackups(c *call) (any, error) {
	var in tableNameInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	t, err := h.loadBackupTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ContinuousBackupsDescription": continuousBackupsDescription(t.desc.PITR, time.Now())}, nil
}

type updateContinuousBackupsInput struct {
	TableName string `json:"TableName"`
	Spec      *struct {
		Enabled *bool `json:"PointInTimeRecoveryEnabled"`
		Days    *int  `json:"RecoveryPeriodInDays"`
	} `json:"PointInTimeRecoverySpecification"`
}

func (h *Handler) updateContinuousBackups(c *call) (any, error) {
	var in updateContinuousBackupsInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if in.Spec == nil {
		return nil, validation("1 validation error detected: Value null at 'pointInTimeRecoverySpecification' failed to satisfy constraint: Member must not be null")
	}
	if in.Spec.Enabled == nil {
		return nil, validation("1 validation error detected: Value null at 'pointInTimeRecoverySpecification.pointInTimeRecoveryEnabled' failed to satisfy constraint: Member must not be null")
	}
	if d := in.Spec.Days; d != nil && (*d < 1 || *d > 35) {
		return nil, validation("1 validation error detected: Value '%d' at 'pointInTimeRecoverySpecification.recoveryPeriodInDays' failed to satisfy constraint: Member must have value less than or equal to 35 and greater than or equal to 1", *d)
	}
	if in.Spec.Days != nil && !*in.Spec.Enabled {
		return nil, validation("RecoveryPeriodInDays can only be set when PointInTimeRecoveryEnabled is true")
	}
	t, err := h.loadBackupTable(c, in.TableName)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	p := t.desc.PITR
	if p == nil {
		p = &pitrState{}
	}
	if *in.Spec.Enabled {
		if !p.Enabled {
			p.Since = now.UnixMilli()
			p.Days = defaultRecoveryDays
		}
		if in.Spec.Days != nil {
			p.Days = *in.Spec.Days
		}
		p.Enabled, p.Continuous = true, true
	} else {
		p.Enabled, p.Days, p.Since = false, 0, 0
	}
	t.desc.PITR = p
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if err := saveDesc(c, tx, t); err != nil {
			return err
		}
		spec, _ := json.Marshal(p)
		return tx.Change("dynamodb", "UpdateContinuousBackups", t.desc.TableName, map[string]any{"pitr": string(spec)})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"ContinuousBackupsDescription": continuousBackupsDescription(p, now)}, nil
}
