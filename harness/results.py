#!/usr/bin/env python3
"""Turn a pytest --report-log file into sorted pass/fail/skip node-id lists.

usage: results.py REPORT.jsonl OUT_PREFIX
Writes OUT_PREFIX.pass / .fail / .skip (pytest node ids, one per line) and
prints "passed failed skipped collect_errors".
Exit 3 when the report is missing or holds no tests: that is an
infrastructure problem (suite did not run), never a test result.
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    report, prefix = sys.argv[1], sys.argv[2]
    outcome = {}          # nodeid -> "passed" | "failed" | "skipped"
    collect_errors = []
    try:
        with open(report) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = rec.get("$report_type")
                if kind == "CollectReport" and rec.get("outcome") == "failed":
                    collect_errors.append(rec.get("nodeid", "?"))
                    continue
                if kind != "TestReport":
                    continue
                nid, when, res = rec["nodeid"], rec["when"], rec["outcome"]
                prev = outcome.get(nid)
                if res == "failed":
                    outcome[nid] = "failed"          # any failed phase fails the test
                elif res == "skipped" and prev != "failed":
                    outcome[nid] = "skipped"
                elif res == "passed" and when == "call" and prev is None:
                    outcome[nid] = "passed"
    except OSError as e:
        print(f"results.py: cannot read {report}: {e}", file=sys.stderr)
        return 3
    if not outcome:
        print("results.py: no tests ran" + (f" ({len(collect_errors)} collection errors)" if collect_errors else ""),
              file=sys.stderr)
        return 3
    buckets = {"pass": [], "fail": [], "skip": []}
    names = {"passed": "pass", "failed": "fail", "skipped": "skip"}
    for nid, res in outcome.items():
        buckets[names[res]].append(nid)
    for suffix, ids in buckets.items():
        with open(f"{prefix}.{suffix}", "w") as fh:
            fh.writelines(i + "\n" for i in sorted(ids))
    print(len(buckets["pass"]), len(buckets["fail"]), len(buckets["skip"]), len(collect_errors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
