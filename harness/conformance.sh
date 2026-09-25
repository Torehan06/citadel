#!/usr/bin/env bash
# Run one conformance suite against a fresh, throwaway Citadel region.
#
#   harness/conformance.sh s3                           full suite -> .harness/results/s3.{pass,fail,skip}
#   harness/conformance.sh s3 -k test_bucket_list_empty targeted run, short tracebacks (for agents)
#   harness/conformance.sh s3 --quiet                   full run, one-line summary (used by ratchet)
#   harness/conformance.sh s3 --nodes FILE              run exactly the node ids listed in FILE
#
# Suites: s3 (ceph/s3-tests), smoke-s3 (aws CLI round trips), ddb (Scylla
# Alternator's DynamoDB tests), sqs / iam / lambda / route53 (moto's tests in
# server mode).
#
# Exit: 0 suite ran (results written, pass or fail)
#       1 citadel failed to build or start      -> the code's fault
#       3 infrastructure problem (network, pip, port in use, suite crashed)
#
# Protected path: agents must not edit this file (selection = the scoreboard).
source "$(dirname "$0")/lib.sh"

SUITE="${1:-}"; shift || true
[ -n "$SUITE" ] || die "usage: harness/conformance.sh SUITE [--quiet] [--nodes FILE] [pytest args...]"
QUIET=0; NODES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1; shift ;;
    --nodes) NODES="$2"; shift 2 ;;
    *) break ;;
  esac
done
TARGETED=0; { [ $# -gt 0 ] || [ -n "$NODES" ]; } && TARGETED=1

RES="$H/results"
if [ $TARGETED = 1 ]; then OUT="$RES/targeted-$SUITE"; else OUT="$RES/$SUITE"; fi
rm -f "$OUT".{pass,fail,skip,summary,pytest.log,server.log,report.jsonl}

build_citadel || { echo "$SUITE: BUILD FAILED (see .harness/results/build.log)"; exit 1; }

PYTEST_COMMON=(-p no:cacheprovider -q -o addopts= --timeout=60 --timeout-method=signal --report-log="$OUT.report.jsonl")
if [ $TARGETED = 1 ]; then PYTEST_COMMON+=(--tb=short -rfE); else PYTEST_COMMON+=(--tb=no); fi
SUITE_TIMEOUT=2400   # a whole suite must finish within 40 minutes

# run_pytest VENV WORKDIR TESTS... [-- extra args] ; honours --nodes and user args
run_pytest() {
  local venv=$1 workdir=$2; shift 2
  local -a tests=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do tests+=("$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  local -a extra=("$@")
  if [ -n "$NODES" ]; then
    tests=()
    while IFS= read -r n; do [ -n "$n" ] && tests+=("$n"); done <"$NODES"
  fi
  (cd "$workdir" && run_with_timeout "$SUITE_TIMEOUT" \
      "$venv/bin/python" -m pytest "${PYTEST_COMMON[@]}" "${extra[@]}" "${USER_ARGS[@]}" "${tests[@]}") \
      >"$OUT.pytest.log" 2>&1
  local rc=$?
  [ $rc = 124 ] && log "$SUITE: suite timed out after ${SUITE_TIMEOUT}s"
  return $rc
}
USER_ARGS=("$@")

# ---------------------------------------------------------------------------- s3
S3_FILES=(s3tests/functional/test_s3.py s3tests/functional/test_headers.py)
# AWS-behaviour tests only. Excluded: RGW-only semantics, features not on the
# roadmap yet (select, website, SNS, STS/IAM accounts, SSE, lifecycle timers).
S3_MARKERS="not fails_on_aws and not appendobject and not auth_aws2 \
and not bucket_logging and not bucket_logging_cleanup and not fails_without_logging_rollover \
and not cloud_transition and not cloud_restore and not target_by_bucket \
and not lifecycle_expiration and not lifecycle_transition \
and not s3select and not s3website and not s3website_routing_rules and not s3website_redirect_location \
and not sns and not test_of_sts and not webidentity_test and not abac_test \
and not iam_account and not iam_cross_account and not iam_role and not iam_tenant and not iam_user \
and not group and not group_policy and not role_policy and not user_policy and not session_policy \
and not s3control and not sse_s3 and not encryption"
# RGW multi-tenancy ("tenant$bucket") is not an AWS concept.
S3_KEYWORDS="not tenant"

suite_s3() {
  local port=8421
  fetch_pinned s3-tests "$S3TESTS_URL" "$S3TESTS_SHA" || return 3
  ensure_venv "s3-${S3TESTS_SHA:0:8}" -r "$H/cache/s3-tests/requirements.txt" pytest-timeout pytest-reportlog || return 3
  sed "s/__PORT__/$port/" "$ROOT/harness/s3tests.conf" >"$RES/s3tests.conf"
  start_citadel $port "$OUT.server.log" || return $?
  S3TEST_CONF="$RES/s3tests.conf" run_pytest "$H/venv/s3-${S3TESTS_SHA:0:8}" "$H/cache/s3-tests" \
    "${S3_FILES[@]}" -- -m "$S3_MARKERS" -k "$S3_KEYWORDS"
  stop_citadel
}

# --------------------------------------------------------------------------- ddb
DDB_FILES=(test_batch.py test_condition_expression.py test_describe_endpoints.py test_describe_table.py
  test_expected.py test_filter_expression.py test_gsi.py test_gsi_updatetable.py test_item.py
  test_key_condition_expression.py test_key_conditions.py test_limits.py test_lsi.py
  test_manual_requests.py test_nested.py test_number.py test_projection_expression.py
  test_provisioned_throughput.py test_query.py test_query_filter.py test_returnconsumedcapacity.py
  test_returnvalues.py test_scan.py test_table.py test_tag.py test_transact.py test_ttl.py
  test_update_expression.py)

suite_ddb() {
  local port=8421
  fetch_pinned alternator "$ALTERNATOR_URL" "$ALTERNATOR_SHA" test/alternator test/pylib test/cqlpy scripts || return 3
  # The suite looks up Scylla roles over CQL; with no CQL server it falls back
  # to the unknownuser/unknownsecret key, which harness/bootstrap.json defines.
  CASS_DRIVER_NO_EXTENSIONS=1 ensure_venv "ddb-${ALTERNATOR_SHA:0:8}" boto3 "pytest<8.4" pytest-timeout pytest-reportlog requests cassandra-driver allure-pytest \
    aiohttp colorama humanfriendly packaging psutil treelib universalasync pyyaml || return 3
  start_citadel $port "$OUT.server.log" || return $?
  AWS_CONFIG_FILE=/dev/null run_pytest "$H/venv/ddb-${ALTERNATOR_SHA:0:8}" "$H/cache/alternator/test/alternator" \
    "${DDB_FILES[@]}" -- --url "http://127.0.0.1:$port" -c "$ROOT/harness/alternator.ini" \
    --rootdir "$H/cache/alternator" --confcutdir "$H/cache/alternator/test/alternator"
  stop_citadel
}

# ------------------------------------------------------------ moto (server mode)
# moto's own tests, pointed at Citadel. They hardcode localhost:5000 in some
# expected URLs, so this suite must use port 5000.
moto_files() {
  case "$1" in
    sqs)     echo "tests/test_sqs/test_sqs.py tests/test_sqs/test_sqs_message_attributes.py" ;;
    iam)     echo "tests/test_iam/test_iam.py tests/test_iam/test_iam_groups.py tests/test_iam/test_iam_policies.py" ;;
    lambda)  echo "tests/test_awslambda/test_lambda.py tests/test_awslambda/test_lambda_alias.py tests/test_awslambda/test_lambda_eventsourcemapping.py tests/test_awslambda/test_lambda_function_urls.py" ;;
    route53) echo "tests/test_route53/test_route53.py tests/test_route53/test_route53_healthchecks.py" ;;
  esac
}

suite_moto() {
  local svc=$1 port=5000 files
  read -r -a files <<<"$(moto_files "$svc")"
  fetch_pinned moto "$MOTO_URL" "$MOTO_SHA" moto tests || return 3
  ensure_venv "moto-${MOTO_SHA:0:8}" -e "$H/cache/moto[sqs,iam,awslambda,route53]" pytest pytest-timeout pytest-reportlog freezegun || return 3
  start_citadel $port "$OUT.server.log" || return $?
  TEST_SERVER_MODE=true TEST_SERVER_MODE_ENDPOINT="http://localhost:$port" \
  AWS_DEFAULT_REGION=us-east-1 AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    run_pytest "$H/venv/moto-${MOTO_SHA:0:8}" "$H/cache/moto" "${files[@]}"
  stop_citadel
}

# ------------------------------------------------------------------------ smoke
suite_smoke() {
  local what=$1 port=8421
  have aws || { log "aws CLI v2 not installed (brew install awscli)"; return 3; }
  start_citadel $port "$OUT.server.log" || return $?
  CITADEL_ENDPOINT="http://127.0.0.1:$port" "$ROOT/harness/smoke.sh" "$what" >"$OUT.pytest.log" 2>&1
  stop_citadel
  grep -E '^(PASS|FAIL) ' "$OUT.pytest.log" >"$OUT.steps" || true
  [ -s "$OUT.steps" ] || return 3
  awk '$1=="PASS"{print $2}' "$OUT.steps" | sort >"$OUT.pass"
  awk '$1=="FAIL"{print $2}' "$OUT.steps" | sort >"$OUT.fail"
  : >"$OUT.skip"
  echo "$(wc -l <"$OUT.pass" | tr -d ' ') $(wc -l <"$OUT.fail" | tr -d ' ') 0 0" >"$OUT.summary"
}

# ------------------------------------------------------------------------ dispatch
trap 'stop_citadel' EXIT
rc=0
case "$SUITE" in
  s3)                       suite_s3 || rc=$? ;;
  ddb)                      suite_ddb || rc=$? ;;
  sqs|iam|lambda|route53)   suite_moto "$SUITE" || rc=$? ;;
  smoke-*)                  suite_smoke "${SUITE#smoke-}" || rc=$? ;;
  *) die "unknown suite '$SUITE' (s3, smoke-s3, ddb, sqs, iam, lambda, route53)" ;;
esac

if [ $rc = 1 ] || [ $rc = 3 ]; then
  [ $rc = 1 ] && echo "$SUITE: citadel failed to start (see $OUT.server.log)"
  [ $rc = 3 ] && echo "$SUITE: INFRA problem, suite did not run (see $OUT.pytest.log)"
  exit $rc
fi

# pytest exit codes 0/1 mean "ran"; anything else we judge by the report itself.
if [[ "$SUITE" != smoke-* ]]; then
  if ! summary="$(python3 "$ROOT/harness/results.py" "$OUT.report.jsonl" "$OUT")"; then
    echo "$SUITE: INFRA problem, no test results (see $OUT.pytest.log)"
    tail -15 "$OUT.pytest.log" 2>/dev/null
    exit 3
  fi
  echo "$summary" >"$OUT.summary"
fi

read -r P F S C <"$OUT.summary"
line="$SUITE: $P passed, $F failed, $S skipped"
[ "${C:-0}" != 0 ] && line="$line, $C COLLECTION ERRORS"
if [ $QUIET = 1 ]; then
  echo "$line"
elif [ $TARGETED = 1 ]; then
  echo "$line"
  echo "---- pytest output (tail) ----"
  tail -80 "$OUT.pytest.log"
  echo "---- server log: $OUT.server.log ----"
else
  echo "$line"
  echo "failing ids: $OUT.fail   (first 20 below)"
  head -20 "$OUT.fail"
fi
exit 0
