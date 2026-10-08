"""M9's exit drill: writes converge after a region is stopped for a long time
and resumed, and replication lag stays under 5 s in steady state.

Run through drill.sh, which starts the three local regions first. Phases:

1. setup: a bucket in palaven-1 replicating (delete markers included) to a
   bucket in thessia-1 and one in tuchanka-1; a global table created in
   palaven-1 with replicas in tuchanka-1 and thessia-1.
2. steady: one write at a time (DynamoDB items in a random region, S3 objects
   in the source bucket), each followed by polling every other copy until it
   shows the write. The time from the write's response to its visibility is
   the end-to-end replication lag.
3. outage: thessia-1 is stopped (SIGSTOP, or killed with --mode kill) while
   writes, overwrites and deletes continue in the other two regions.
4. resume: thessia-1 continues; the drill polls until every replica of the
   table holds the same items and every destination bucket holds every
   source version, and reports how long that took.
5. steady again: lag measured as in 2, now including thessia-1's catch-up
   having finished.

Prints PASS/FAIL lines like harness/smoke.sh and a JSON summary.
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
import urllib.request

import boto3
from botocore.config import Config

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGIONS_SH = os.path.join(ROOT, "examples", "multiregion-local", "regions.sh")
OUTAGE_REGION = "thessia-1"


def load_regions():
    with open(os.path.join(ROOT, "examples", "multiregion-local", "regions.json")) as f:
        return {r["name"]: r["endpoint"] for r in json.load(f)["regions"]}


def client(svc, region, endpoint):
    cfg = Config(retries={"max_attempts": 1}, connect_timeout=2, read_timeout=5,
                 s3={"addressing_style": "path"})
    return boto3.client(svc, region_name=region, endpoint_url=endpoint, config=cfg)


def pctl(samples, p):
    if not samples:
        return None
    s = sorted(samples)
    return s[min(int(p * len(s)), len(s) - 1)]


def wait_for(cond, timeout, interval=0.01):
    """Poll cond until it returns True; return seconds waited or None."""
    start = time.monotonic()
    while True:
        try:
            if cond():
                return time.monotonic() - start
        except Exception:
            pass
        if time.monotonic() - start > timeout:
            return None
        time.sleep(interval)


class Drill:
    def __init__(self, args):
        self.args = args
        self.endpoints = load_regions()
        self.ddb = {r: client("dynamodb", r, ep) for r, ep in self.endpoints.items()}
        self.s3 = {r: client("s3", r, ep) for r, ep in self.endpoints.items()}
        tag = "%05d" % random.randrange(100000)
        self.table = "drill-" + tag
        self.src = "drill-src-" + tag
        self.dst = {"thessia-1": "drill-dst-th-" + tag, "tuchanka-1": "drill-dst-tu-" + tag}
        self.seq = 0
        self.results = []
        self.summary = {}

    def check(self, name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + "drill::" + name + (("  " + detail) if detail else ""), flush=True)
        self.results.append(ok)

    # ---- setup ----------------------------------------------------------------

    def setup(self):
        home = "palaven-1"
        s3 = self.s3[home]
        s3.create_bucket(Bucket=self.src, CreateBucketConfiguration={"LocationConstraint": home})
        s3.put_bucket_versioning(Bucket=self.src, VersioningConfiguration={"Status": "Enabled"})
        rules = []
        for prio, (region, bucket) in enumerate(sorted(self.dst.items()), start=1):
            c = self.s3[region]
            c.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
            c.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
            rules.append({"ID": "to-" + region, "Priority": prio, "Status": "Enabled", "Filter": {"Prefix": ""},
                          "DeleteMarkerReplication": {"Status": "Enabled"},
                          "Destination": {"Bucket": "arn:aws:s3:::" + bucket}})
        s3.put_bucket_replication(Bucket=self.src, ReplicationConfiguration={
            "Role": "arn:aws:iam::123456789012:role/drill", "Rules": rules})
        d = self.ddb[home]
        d.create_table(TableName=self.table, BillingMode="PAY_PER_REQUEST",
                       AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                       KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}])
        d.update_table(TableName=self.table, ReplicaUpdates=[
            {"Create": {"RegionName": "tuchanka-1"}}, {"Create": {"RegionName": "thessia-1"}}])
        active = wait_for(lambda: all(r["ReplicaStatus"] == "ACTIVE" for r in
                                      d.describe_table(TableName=self.table)["Table"]["Replicas"]), 10)
        self.check("setup", active is not None, "table %s, buckets %s -> %s" % (self.table, self.src, sorted(self.dst.values())))

    # ---- writes ------------------------------------------------------------------

    def write_item(self, regions):
        """Write (or delete) one item in a random region; return (key, value or None, region)."""
        self.seq += 1
        region = random.choice(regions)
        key = "k%03d" % random.randrange(200)
        if self.seq % 7 == 0:
            self.ddb[region].delete_item(TableName=self.table, Key={"pk": {"S": key}})
            return key, None, region
        val = "%s#%d" % (region, self.seq)
        self.ddb[region].put_item(TableName=self.table, Item={"pk": {"S": key}, "v": {"S": val}})
        return key, val, region

    def item_is(self, region, key, val):
        it = self.ddb[region].get_item(TableName=self.table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
        return (it is None) if val is None else (it is not None and it["v"]["S"] == val)

    def write_object(self):
        """Put (or delete) one key in the source bucket; return (key, version id)."""
        self.seq += 1
        key = "o%02d" % random.randrange(50)
        s3 = self.s3["palaven-1"]
        if self.seq % 11 == 0:
            return key, s3.delete_object(Bucket=self.src, Key=key)["VersionId"]
        return key, s3.put_object(Bucket=self.src, Key=key, Body=("v%d" % self.seq).encode())["VersionId"]

    def has_version(self, region, key, vid):
        out = self.s3[region].list_object_versions(Bucket=self.dst[region], Prefix=key)
        return any(v["VersionId"] == vid for v in out.get("Versions", []) + out.get("DeleteMarkers", []))

    # ---- phases --------------------------------------------------------------------

    def steady(self, name, seconds):
        lags = []
        misses = 0
        end = time.monotonic() + seconds
        regions = list(self.endpoints)
        while time.monotonic() < end:
            key, val, origin = self.write_item(regions)
            for r in regions:
                if r != origin:
                    lag = wait_for(lambda: self.item_is(r, key, val), 30)
                    misses += lag is None
                    lags.append(30.0 if lag is None else lag)
            key, vid = self.write_object()
            for r in self.dst:
                lag = wait_for(lambda: self.has_version(r, key, vid), 30)
                misses += lag is None
                lags.append(30.0 if lag is None else lag)
        p50, p99, mx = pctl(lags, 0.5), pctl(lags, 0.99), max(lags)
        self.summary[name] = {"samples": len(lags), "p50_ms": round(p50 * 1000), "p99_ms": round(p99 * 1000),
                              "max_ms": round(mx * 1000), "not_seen_in_30s": misses}
        self.check(name + "-lag-p99-under-5s", p99 < 5.0 and misses == 0,
                   "%d samples, p50 %.0f ms, p99 %.0f ms, max %.0f ms" % (len(lags), p50 * 1000, p99 * 1000, mx * 1000))

    def server_lag(self, name):
        """The regions' own lag metric (last minute, per destination)."""
        out = {}
        for r, ep in self.endpoints.items():
            with urllib.request.urlopen(ep + "/_citadel/healthz", timeout=5) as resp:
                h = json.load(resp)
            for dest, st in (h.get("replication") or {}).items():
                if st.get("lag_samples_1m"):
                    out[r + "->" + dest] = {"p99_ms_1m": st.get("lag_p99_ms_1m"), "samples_1m": st.get("lag_samples_1m")}
        self.summary[name + "_server_lag"] = out
        worst = max((v["p99_ms_1m"] for v in out.values()), default=0)
        self.check(name + "-server-lag-p99-under-5s", worst < 5000, "worst destination p99 over the last minute: %d ms" % worst)

    def regions_sh(self, *a):
        subprocess.run([REGIONS_SH, *a], check=True, stdout=subprocess.DEVNULL)

    def run_outage(self, seconds):
        if self.args.mode == "pause":
            self.regions_sh("pause", OUTAGE_REGION)
        else:
            self.regions_sh("stop", OUTAGE_REGION)
        alive = [r for r in self.endpoints if r != OUTAGE_REGION]
        writes = 0
        end = time.monotonic() + seconds
        last_report = time.monotonic()
        while time.monotonic() < end:
            self.write_item(alive)
            self.write_object()
            writes += 2
            if time.monotonic() - last_report > 60:
                print("     outage: %d writes, %.0f s left" % (writes, end - time.monotonic()), flush=True)
                last_report = time.monotonic()
            time.sleep(self.args.outage_interval)
        self.summary["outage"] = {"seconds": seconds, "mode": self.args.mode, "writes": writes}
        if self.args.mode == "pause":
            self.regions_sh("resume", OUTAGE_REGION)
        else:
            self.regions_sh("start", OUTAGE_REGION)
        start = time.monotonic()
        converged = wait_for(self.converged, self.args.converge_timeout, interval=0.5)
        self.summary["converge_s"] = None if converged is None else round(time.monotonic() - start, 2)
        self.check("converged-after-%ds-%s" % (seconds, self.args.mode), converged is not None,
                   "%d writes during the outage; all replicas equal %.1f s after %s returned"
                   % (writes, time.monotonic() - start, OUTAGE_REGION) if converged is not None else "not converged")

    # ---- convergence -------------------------------------------------------------

    def scan(self, region):
        items, kw = {}, {}
        while True:
            out = self.ddb[region].scan(TableName=self.table, ConsistentRead=True, **kw)
            for it in out["Items"]:
                items[it["pk"]["S"]] = it.get("v", {}).get("S")
            if "LastEvaluatedKey" not in out:
                return items
            kw = {"ExclusiveStartKey": out["LastEvaluatedKey"]}

    def versions(self, region, bucket):
        out, kw = set(), {}
        while True:
            page = self.s3[region].list_object_versions(Bucket=bucket, **kw)
            for v in page.get("Versions", []):
                out.add((v["Key"], v["VersionId"], False))
            for v in page.get("DeleteMarkers", []):
                out.add((v["Key"], v["VersionId"], True))
            if not page.get("IsTruncated"):
                return out
            kw = {"KeyMarker": page["NextKeyMarker"], "VersionIdMarker": page["NextVersionIdMarker"]}

    def converged(self):
        scans = [self.scan(r) for r in self.endpoints]
        if any(s != scans[0] for s in scans[1:]):
            return False
        src = self.versions("palaven-1", self.src)
        return all(src <= self.versions(r, b) for r, b in self.dst.items())

    def main(self):
        self.setup()
        self.steady("steady-before", self.args.steady)
        self.server_lag("steady-before")
        self.run_outage(self.args.outage)
        # Long enough that the regions' last-minute lag window no longer holds
        # the catch-up deliveries right after the outage.
        self.steady("steady-after", max(self.args.steady, 65))
        self.server_lag("steady-after")
        items = self.scan("palaven-1")
        self.summary["final"] = {"items": len(items), "source_versions": len(self.versions("palaven-1", self.src))}
        print(json.dumps(self.summary, indent=2))
        return 0 if all(self.results) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--outage", type=int, default=600, help="seconds thessia-1 stays stopped")
    ap.add_argument("--steady", type=int, default=60, help="seconds of each steady-state lag phase")
    ap.add_argument("--mode", choices=["pause", "kill"], default="pause", help="SIGSTOP/SIGCONT or stop/start")
    ap.add_argument("--outage-interval", type=float, default=0.5, help="pause between writes during the outage")
    ap.add_argument("--converge-timeout", type=int, default=120)
    sys.exit(Drill(ap.parse_args()).main())
