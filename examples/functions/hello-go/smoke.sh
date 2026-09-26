#!/usr/bin/env bash
# End-to-end Lambda smoke checks with the aws CLI v2, in harness/smoke.sh's
# "PASS id" / "FAIL id" format (harness/smoke.sh can call smoke_lambda from
# here once a human wires it in; see PROGRESS.md).
#
#   CITADEL_ENDPOINT=http://127.0.0.1:8420 examples/functions/hello-go/smoke.sh
#
# Needs the aws CLI and Go (to build the function). Uses harness/aws.config.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
export AWS_CONFIG_FILE="$ROOT/harness/aws.config" AWS_SHARED_CREDENTIALS_FILE="$ROOT/harness/aws.credentials"
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_PROFILE
EP="${CITADEL_ENDPOINT:?set CITADEL_ENDPOINT, e.g. http://127.0.0.1:8420}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
aws_() { aws --endpoint-url "$EP" --cli-read-timeout 30 --cli-connect-timeout 5 --output json "$@"; }
step() { # step ID command...
  local id=$1; shift
  if "$@" >"$TMP/log" 2>&1; then echo "PASS $id"; else echo "FAIL $id"; tail -5 "$TMP/log" | sed 's/^/    /'; fi
}
account() { aws_ sts get-caller-identity --query Account --output text; }

smoke_lambda() {
  local fn="hello-$RANDOM$RANDOM" role="smoke-lambda-$RANDOM" q="smoke-q-$RANDOM" b="smoke-events-$RANDOM$RANDOM"
  local acct region trust
  acct="$(account)"
  region="$(aws configure get region 2>/dev/null || echo us-east-1)"
  trust='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

  step smoke-lambda::build            "$HERE/build.sh" "$TMP/function.zip"
  step smoke-lambda::create-role      aws_ iam create-role --role-name "$role" --assume-role-policy-document "$trust"
  step smoke-lambda::create-function  aws_ lambda create-function --function-name "$fn" --runtime provided.al2023 --handler bootstrap \
                                        --role "arn:aws:iam::$acct:role/$role" --zip-file "fileb://$TMP/function.zip" --timeout 10
  step smoke-lambda::wait-active      aws_ lambda wait function-active-v2 --function-name "$fn"
  step smoke-lambda::invoke           sh -c "aws --endpoint-url '$EP' lambda invoke --function-name '$fn' --cli-binary-format raw-in-base64-out \
                                        --payload '{\"name\":\"Citadel\"}' '$TMP/out.json' >/dev/null && grep -q 'Hello, Citadel!' '$TMP/out.json'"
  step smoke-lambda::invoke-log-tail  sh -c "aws --endpoint-url '$EP' lambda invoke --function-name '$fn' --log-type Tail --query LogResult --output text \
                                        '$TMP/out2.json' | base64 -d | grep -q 'hello-go: greeting world'"
  step smoke-lambda::logs             sh -c "aws --endpoint-url '$EP' logs filter-log-events --log-group-name '/aws/lambda/$fn' \
                                        --filter-pattern Citadel --query 'events[].message' --output text | grep -q 'greeting Citadel'"
  step smoke-lambda::publish-alias    sh -c "aws --endpoint-url '$EP' lambda publish-version --function-name '$fn' >/dev/null && \
                                        aws --endpoint-url '$EP' lambda create-alias --function-name '$fn' --name live --function-version 1 >/dev/null && \
                                        aws --endpoint-url '$EP' lambda invoke --function-name '$fn:live' '$TMP/out3.json' --query ExecutedVersion --output text | grep -qx 1"

  # SQS -> Lambda: a sent message must reach the function within 2 seconds.
  local qurl qarn
  qurl="$(aws_ sqs create-queue --queue-name "$q" --query QueueUrl --output text)"
  qarn="arn:aws:sqs:$region:$acct:$q"
  step smoke-lambda::event-source-mapping aws_ lambda create-event-source-mapping --function-name "$fn" --event-source-arn "$qarn" --batch-size 5
  local marker="sqs-$RANDOM$RANDOM"
  sqs_to_lambda() {
    local start end
    start=$(date +%s%N)
    aws --endpoint-url "$EP" sqs send-message --queue-url "$qurl" --message-body "$marker" >/dev/null || return 1
    for _ in $(seq 1 40); do
      if aws --endpoint-url "$EP" logs filter-log-events --log-group-name "/aws/lambda/$fn" --filter-pattern "$marker" \
           --query 'events[].message' --output text | grep -q "$marker"; then
        end=$(date +%s%N)
        echo "SQS -> Lambda in $(( (end - start) / 1000000 )) ms"
        [ $(( (end - start) / 1000000 )) -le 2000 ]
        return
      fi
      sleep 0.1
    done
    return 1
  }
  step smoke-lambda::sqs-trigger-2s   sqs_to_lambda
  step smoke-lambda::sqs-queue-drained sh -c "sleep 1; [ \"\$(aws --endpoint-url '$EP' sqs get-queue-attributes --queue-url '$qurl' \
                                        --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
                                        --query 'sum(map(&to_number(@), values(Attributes)))' --output text)\" = 0 ]"

  # S3 -> Lambda and S3 -> SQS notifications.
  local nq="smoke-nq-$RANDOM" nqurl
  nqurl="$(aws_ sqs create-queue --queue-name "$nq" --query QueueUrl --output text)"
  aws_ s3api create-bucket --bucket "$b" >/dev/null
  aws_ lambda add-permission --function-name "$fn" --statement-id s3 --action lambda:InvokeFunction \
    --principal s3.amazonaws.com --source-arn "arn:aws:s3:::$b" --source-account "$acct" >/dev/null
  cat >"$TMP/notify.json" <<EOF
{"LambdaFunctionConfigurations":[{"LambdaFunctionArn":"arn:aws:lambda:$region:$acct:function:$fn","Events":["s3:ObjectCreated:*"],
  "Filter":{"Key":{"FilterRules":[{"Name":"prefix","Value":"in/"}]}}}],
 "QueueConfigurations":[{"QueueArn":"arn:aws:sqs:$region:$acct:$nq","Events":["s3:ObjectRemoved:*"]}]}
EOF
  step smoke-lambda::s3-notification-config aws_ s3api put-bucket-notification-configuration --bucket "$b" --notification-configuration "file://$TMP/notify.json"
  echo hi >"$TMP/obj.txt"
  step smoke-lambda::s3-put-object    aws_ s3api put-object --bucket "$b" --key in/obj.txt --body "$TMP/obj.txt"
  s3_to_lambda() {
    for _ in $(seq 1 50); do
      aws --endpoint-url "$EP" logs filter-log-events --log-group-name "/aws/lambda/$fn" --filter-pattern "\"object $b/in/obj.txt\"" \
        --query 'events[].message' --output text | grep -q "in/obj.txt" && return 0
      sleep 0.2
    done
    return 1
  }
  step smoke-lambda::s3-to-lambda     s3_to_lambda
  step smoke-lambda::s3-delete-object aws_ s3api delete-object --bucket "$b" --key in/obj.txt
  s3_to_sqs() {
    for _ in $(seq 1 10); do
      aws --endpoint-url "$EP" sqs receive-message --queue-url "$nqurl" --wait-time-seconds 2 --max-number-of-messages 10 \
        --query 'Messages[].Body' --output text | grep -q '"eventName": *"ObjectRemoved:Delete"' && return 0
    done
    return 1
  }
  step smoke-lambda::s3-to-sqs        s3_to_sqs

  aws_ s3 rb "s3://$b" --force >/dev/null 2>&1
  step smoke-lambda::delete-function  aws_ lambda delete-function --function-name "$fn"
  aws_ iam delete-role --role-name "$role" >/dev/null 2>&1
}

smoke_lambda
