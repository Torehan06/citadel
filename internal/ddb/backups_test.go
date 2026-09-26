package ddb

import (
	"reflect"
	"testing"
	"time"
)

func TestContinuousBackupsDescription(t *testing.T) {
	now := time.UnixMilli(1_790_000_000_000)
	disabled := map[string]any{"PointInTimeRecoveryStatus": "DISABLED"}
	cases := []struct {
		name       string
		p          *pitrState
		status     string
		pitrStatus map[string]any
	}{
		{"never enabled", nil, "DISABLED", disabled},
		{"enabled", &pitrState{Enabled: true, Days: 35, Since: 1_789_000_000_000, Continuous: true}, "ENABLED", map[string]any{
			"PointInTimeRecoveryStatus": "ENABLED", "RecoveryPeriodInDays": 35,
			"EarliestRestorableDateTime": 1_789_000_000.0, "LatestRestorableDateTime": 1_790_000_000.0,
		}},
		{"disabled again", &pitrState{Continuous: true}, "ENABLED", disabled},
	}
	for _, c := range cases {
		d := continuousBackupsDescription(c.p, now)
		if d["ContinuousBackupsStatus"] != c.status || !reflect.DeepEqual(d["PointInTimeRecoveryDescription"], c.pitrStatus) {
			t.Errorf("%s: got %v", c.name, d)
		}
	}
}

func TestWarmThroughput(t *testing.T) {
	cases := []struct {
		p    *throughput
		r, w int64
	}{
		{nil, 12000, 4000},
		{&throughput{5, 5}, 12000, 4000},
		{&throughput{20000, 1000}, 20000, 4000},
	}
	for _, c := range cases {
		got := warmThroughput(c.p, "ACTIVE")
		if got["ReadUnitsPerSecond"] != c.r || got["WriteUnitsPerSecond"] != c.w || got["Status"] != "ACTIVE" {
			t.Errorf("warmThroughput(%v) = %v", c.p, got)
		}
	}
}
