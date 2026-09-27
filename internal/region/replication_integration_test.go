//go:build unix

package region_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"citadel/internal/sigv4"
	"citadel/internal/store"
)

// M9: data-plane replication between real processes. S3 cross-region
// replication and a DynamoDB global table over three regions; a region that
// is down while writes happen catches up from the durable cursors when it
// returns; anti-entropy restores data a replica lost behind the stream's back.

func (c *cloud) ddb(name string, cred sigv4.Credentials, op, body string) (int, string) {
	return c.call(name, cred, "dynamodb", "POST", "/", map[string]string{
		"Content-Type": "application/x-amz-json-1.0", "X-Amz-Target": "DynamoDB_20120810." + op}, []byte(body))
}

func (c *cloud) mustDDB(name string, cred sigv4.Credentials, op, body string) string {
	c.t.Helper()
	code, out := c.ddb(name, cred, op, body)
	if code != 200 {
		c.t.Fatalf("dynamodb %s at %s: %d %s", op, name, code, out)
	}
	return out
}

func (c *cloud) mustS3(name string, cred sigv4.Credentials, method, path, body string) string {
	c.t.Helper()
	code, out := c.call(name, cred, "s3", method, path, nil, []byte(body))
	if code/100 != 2 {
		c.t.Fatalf("s3 %s %s at %s: %d %s", method, path, name, code, out)
	}
	return out
}

// eventually polls cond until it holds or within passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() (bool, string)) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		ok, state := cond()
		if ok {
			return time.Since(start)
		}
		if time.Since(start) > within {
			t.Fatalf("%s: not true after %v (last: %s)", what, within, state)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (c *cloud) itemValue(name string, cred sigv4.Credentials, table, key string) string {
	_, out := c.ddb(name, cred, "GetItem", fmt.Sprintf(`{"TableName":%q,"Key":{"pk":{"S":%q}},"ConsistentRead":true}`, table, key))
	var r struct {
		Item map[string]map[string]string
	}
	_ = json.Unmarshal([]byte(out), &r)
	if r.Item == nil {
		return "<none>"
	}
	return r.Item["v"]["S"]
}

func (c *cloud) objectBody(name string, cred sigv4.Credentials, path string) (int, string) {
	return c.call(name, cred, "s3", "GET", path, nil, nil)
}

func TestMultiRegionReplication(t *testing.T) {
	c := newCloud(t, "--anti-entropy", "500ms")
	admin := adminCredentials(t)
	all := []string{"home-1", "follow-1", "follow-2"}

	// S3: home-1/src replicates everything, delete markers included, to follow-1/dst.
	c.mustS3("home-1", admin, "PUT", "/src", "")
	c.mustS3("follow-1", admin, "PUT", "/dst", "")
	for _, at := range [][2]string{{"home-1", "/src"}, {"follow-1", "/dst"}} {
		c.mustS3(at[0], admin, "PUT", at[1]+"?versioning", `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	}
	c.mustS3("home-1", admin, "PUT", "/src?replication", `<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/r</Role>
		<Rule><ID>all</ID><Priority>1</Priority><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
		<DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>
		<Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule></ReplicationConfiguration>`)
	c.mustS3("home-1", admin, "PUT", "/src/k1", "one")
	d := eventually(t, 5*time.Second, "object replicated", func() (bool, string) {
		code, body := c.objectBody("follow-1", admin, "/dst/k1")
		return code == 200 && body == "one", body
	})
	t.Logf("S3 object replicated to follow-1 in %v", d.Round(time.Millisecond))

	// DynamoDB: a table in home-1 with replicas in both other regions.
	const table = "gtable"
	c.mustDDB("home-1", admin, "CreateTable", `{"TableName":"gtable","AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],
		"KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}`)
	c.mustDDB("home-1", admin, "PutItem", `{"TableName":"gtable","Item":{"pk":{"S":"old"},"v":{"S":"from before"}}}`)
	c.mustDDB("home-1", admin, "UpdateTable", `{"TableName":"gtable","ReplicaUpdates":[{"Create":{"RegionName":"follow-1"}},{"Create":{"RegionName":"follow-2"}}]}`)
	eventually(t, 5*time.Second, "replicas active", func() (bool, string) {
		out := c.mustDDB("home-1", admin, "DescribeTable", `{"TableName":"gtable"}`)
		return strings.Count(out, `"ReplicaStatus":"ACTIVE"`) == 2, out
	})
	for _, r := range all {
		eventually(t, 5*time.Second, "existing item backfilled in "+r, func() (bool, string) {
			v := c.itemValue(r, admin, table, "old")
			return v == "from before", v
		})
	}
	c.mustDDB("follow-2", admin, "PutItem", `{"TableName":"gtable","Item":{"pk":{"S":"k"},"v":{"S":"written in follow-2"}}}`)
	for _, r := range all {
		d := eventually(t, 5*time.Second, "item replicated to "+r, func() (bool, string) {
			v := c.itemValue(r, admin, table, "k")
			return v == "written in follow-2", v
		})
		t.Logf("DynamoDB item visible in %s after %v", r, d.Round(time.Millisecond))
	}

	// follow-1 is down while both services keep writing; the cursors hold
	// its backlog and it converges after it restarts.
	c.stop("follow-1")
	c.mustS3("home-1", admin, "PUT", "/src/k2", "two")
	c.mustS3("home-1", admin, "DELETE", "/src/k1", "")
	for i := 0; i < 20; i++ {
		c.mustDDB("home-1", admin, "PutItem", fmt.Sprintf(`{"TableName":"gtable","Item":{"pk":{"S":"down-%d"},"v":{"S":"home"}}}`, i))
	}
	c.mustDDB("follow-2", admin, "PutItem", `{"TableName":"gtable","Item":{"pk":{"S":"k"},"v":{"S":"newer from follow-2"}}}`)
	c.mustDDB("home-1", admin, "DeleteItem", `{"TableName":"gtable","Key":{"pk":{"S":"old"}}}`)
	time.Sleep(time.Second) // let the senders hit the closed port and back off
	c.start("follow-1")
	d = eventually(t, 15*time.Second, "follow-1 converged", func() (bool, string) {
		_, k2 := c.objectBody("follow-1", admin, "/dst/k2")
		k1, _ := c.objectBody("follow-1", admin, "/dst/k1")
		state := fmt.Sprintf("k2=%s k1=%d k=%s old=%s down-19=%s", k2, k1, c.itemValue("follow-1", admin, table, "k"),
			c.itemValue("follow-1", admin, table, "old"), c.itemValue("follow-1", admin, table, "down-19"))
		return state == "k2=two k1=404 k=newer from follow-2 old=<none> down-19=home", state
	})
	t.Logf("follow-1 converged %v after restart", d.Round(time.Millisecond))

	// Concurrent writes to one item in two regions: the later one wins
	// everywhere. (Within one millisecond neither is later; the HLC tie is
	// broken by region name, the same way in every region.)
	c.mustDDB("home-1", admin, "PutItem", `{"TableName":"gtable","Item":{"pk":{"S":"race"},"v":{"S":"first"}}}`)
	time.Sleep(5 * time.Millisecond)
	c.mustDDB("follow-1", admin, "PutItem", `{"TableName":"gtable","Item":{"pk":{"S":"race"},"v":{"S":"second"}}}`)
	for _, r := range all {
		eventually(t, 5*time.Second, "last writer wins in "+r, func() (bool, string) {
			v := c.itemValue(r, admin, table, "race")
			return v == "second", v
		})
	}

	// Anti-entropy: follow-2 loses an item and follow-1 loses an object
	// version behind the stream's back (the cursors have long moved past
	// them); the digest comparison finds and restores both.
	c.stop("follow-2")
	c.stop("follow-1")
	for _, r := range []string{"follow-1", "follow-2"} {
		st, err := store.Open(context.Background(), c.regions[r].dir, r)
		if err != nil {
			t.Fatal(err)
		}
		lost := map[string]int64{}
		err = st.Update(context.Background(), func(tx *store.Tx) error {
			for _, q := range []string{
				`DELETE FROM ddb_items WHERE pk = CAST('down-7' AS BLOB)`, // S keys are stored as their UTF-8 bytes
				`DELETE FROM ddb_item_versions WHERE pk = CAST('down-7' AS BLOB)`,
				`DELETE FROM s3_objects WHERE key = 'k2'`,
			} {
				res, err := tx.ExecContext(context.Background(), q)
				if err != nil {
					return err
				}
				lost[q[12:22]], _ = res.RowsAffected()
			}
			return nil
		})
		if lost["ddb_items "] != 1 || lost["ddb_item_v"] != 1 || r == "follow-1" && lost["s3_objects"] != 1 {
			t.Fatalf("test setup: rows removed in %s: %v", r, lost)
		}
		st.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	c.start("follow-1")
	c.start("follow-2")
	d = eventually(t, 10*time.Second, "anti-entropy repaired", func() (bool, string) {
		_, k2 := c.objectBody("follow-1", admin, "/dst/k2")
		state := fmt.Sprintf("follow-1 k2=%s follow-2 down-7=%s", k2, c.itemValue("follow-2", admin, table, "down-7"))
		return state == "follow-1 k2=two follow-2 down-7=home", state
	})
	t.Logf("anti-entropy repaired the lost item and object version in %v", d.Round(time.Millisecond))

	// The lag metric is reported per destination.
	repl, _ := c.health("home-1")["replication"].(map[string]any)
	f2, _ := repl["follow-2"].(map[string]any)
	if f2 == nil || f2["lag_p99_ms"] == nil || f2["healthy"] != true {
		t.Fatalf("replication status of home-1: %v", repl)
	}
	t.Logf("home-1 -> follow-2: p50 %vms p99 %vms over %v deliveries", f2["lag_p50_ms"], f2["lag_p99_ms"], f2["delivered"])
}
