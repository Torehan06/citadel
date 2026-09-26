#!/usr/bin/env bash
# Lambda smoke checks with the real aws CLI v2, in harness/smoke.sh's format
# ("PASS id" / "FAIL id" lines). Proposed as smoke.sh's "lambda" set; until it
# is wired in, run it against a running region:
#
#   make serve &
#   examples/functions/smoke.sh                  # CITADEL_ENDPOINT defaults to :8420
#
# It builds examples/functions/hello-go for wasip1, deploys it, invokes it,
# reads its logs, and checks that an SQS message triggers it within 2 seconds.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EP="${CITADEL_ENDPOINT:-http://127.0.0.1:8420}"
export AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$ROOT/harness/aws.config}"
export AWS_SHARED_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$ROOT/harness/aws.credentials}"
export AWS_PAGER=""
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
aws_() { aws --endpoint-url "$EP" --cli-read-timeout 30 --cli-connect-timeout 5 "$@"; }

step() { # step ID command...
  local id=$1; shift
  if "$@" >>"$TMP/log" 2>&1; then echo "PASS $id"; else echo "FAIL $id"; tail -5 "$TMP/log" | sed 's/^/    /'; fi
}

now() { python3 -c 'import time; print(time.time())'; }

build() {
  (cd "$ROOT/examples/functions/hello-go" && GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -o "$TMP/bootstrap.wasm" .) &&
    (cd "$TMP" && python3 -m zipfile -c function.zip bootstrap.wasm)
}

invoke_hello() {
  aws_ lambda invoke --function-name "$F" --cli-binary-format raw-in-base64-out \
    --payload '{"name":"Citadel"}' "$TMP/out.json" &&
    grep -q '"Hello, Citadel!"' "$TMP/out.json"
}

invoke_error() {
  aws_ lambda invoke --function-name "$F" --cli-binary-format raw-in-base64-out \
    --payload '{"fail":"boom"}' "$TMP/err.json" >"$TMP/err.meta" &&
    grep -q '"Unhandled"' "$TMP/err.meta" && grep -q '"boom"' "$TMP/err.json"
}

log_tail() {
  aws_ lambda invoke --function-name "$F" --log-type Tail --query LogResult --output text "$TMP/tail.json" |
    python3 -c 'import base64,sys; sys.stdout.write(base64.b64decode(sys.stdin.read()).decode())' | grep -q 'REPORT RequestId'
}

logs_stored() {
  aws_ logs filter-log-events --log-group-name "/aws/lambda/$F" --filter-pattern '"hello-go"' \
    --query 'length(events)' --output text | grep -qv '^0$'
}

# sqs_trigger sends a message to a queue mapped to the function and waits for
# the function's log line with that body: it must appear within 2 seconds.
sqs_trigger() {
  local url arn body start
  url=$(aws_ sqs create-queue --queue-name "$F-queue" --query QueueUrl --output text) || return 1
  arn=$(aws_ sqs get-queue-attributes --queue-url "$url" --attribute-names QueueArn --query Attributes.QueueArn --output text) || return 1
  aws_ lambda create-event-source-mapping --function-name "$F" --event-source-arn "$arn" --batch-size 1 >/dev/null || return 1
  sleep 1 # the mapping's poller starts its long poll
  body="smoke-$RANDOM$RANDOM"
  start=$(now)
  aws_ sqs send-message --queue-url "$url" --message-body "$body" >/dev/null || return 1
  for _ in $(seq 1 40); do
    if aws_ logs filter-log-events --log-group-name "/aws/lambda/$F" --filter-pattern "\"record: $body\"" \
      --query 'length(events)' --output text 2>/dev/null | grep -qv '^0$'; then
      python3 -c "import sys; d=$(now)-$start; print(f'triggered in {d:.2f}s'); sys.exit(0 if d <= 2.0 else 1)"
      return
    fi
    sleep 0.05
  done
  echo "no log line for $body" >&2
  return 1
}

cleanup() {
  for uuid in $(aws_ lambda list-event-source-mappings --function-name "$F" --query 'EventSourceMappings[].UUID' --output text); do
    aws_ lambda delete-event-source-mapping --uuid "$uuid" >/dev/null
  done
  aws_ lambda delete-function --function-name "$F"
}

F="smoke-$RANDOM$RANDOM"
ROLE="$F-role"
step smoke-lambda::build            build
step smoke-lambda::create-role      sh -c "aws --endpoint-url '$EP' iam create-role --role-name '$ROLE' --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}' --query Role.Arn --output text >'$TMP/role'"
step smoke-lambda::create-function  sh -c "aws --endpoint-url '$EP' lambda create-function --function-name '$F' --runtime provided.al2023 --handler bootstrap --role \"\$(cat '$TMP/role')\" --zip-file 'fileb://$TMP/function.zip' >/dev/null"
step smoke-lambda::invoke           invoke_hello
step smoke-lambda::invoke-error     invoke_error
step smoke-lambda::log-tail         log_tail
step smoke-lambda::logs             logs_stored
step smoke-lambda::sqs-trigger      sqs_trigger
step smoke-lambda::delete-function  cleanup
