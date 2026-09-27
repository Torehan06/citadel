#!/usr/bin/env bash
# M8 exit checks with the aws CLI, in harness/smoke.sh's format ("PASS id" /
# "FAIL id"). Starts three fresh regions with regions.sh (its own data
# directory), then:
#   - a key created in the home region authenticates in both followers within 5 s;
#   - IAM calls sent to a follower are made in the home region;
#   - a follower that was stopped catches up on restart;
#   - with the home region stopped (SIGSTOP), followers serve S3, DynamoDB and
#     SQS with existing credentials, answer IAM reads from their replica and
#     refuse IAM writes with ServiceUnavailable;
#   - after SIGCONT, IAM writes through a follower work again.
# Needs aws, python3, curl and openssl.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RS="$ROOT/examples/multiregion-local/regions.sh"
export CITADEL_MR_DATA="${CITADEL_MR_DATA:-$ROOT/.harness/data/multiregion-smoke}"
export AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$ROOT/harness/aws.config}"
export AWS_SHARED_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$ROOT/harness/aws.credentials}"
export AWS_PAGER="" AWS_MAX_ATTEMPTS=1
HOME_EP=http://127.0.0.1:8441
FOLLOWERS="tuchanka-1=http://127.0.0.1:8440 thessia-1=http://127.0.0.1:8442"
TMP="$CITADEL_MR_DATA/smoke-tmp"

"$RS" clean >/dev/null 2>&1
trap '"$RS" clean >/dev/null 2>&1' EXIT
"$RS" start >/dev/null || { echo "FAIL regions-start"; exit 1; }
echo "PASS regions-start"
mkdir -p "$TMP"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1${2:+: $2}"; }
check() { # check ID command...
  local id=$1; shift
  if "$@" >"$TMP/log" 2>&1; then pass "$id"; else fail "$id"; tail -5 "$TMP/log" | sed 's/^/    /'; fi
}
now() { python3 -c 'import time; print(time.time())'; }
as_key() { # as_key FILE aws-args... : run aws with the access key saved in FILE
  local f=$1; shift
  AWS_ACCESS_KEY_ID=$(sed -n 1p "$f") AWS_SECRET_ACCESS_KEY=$(sed -n 2p "$f") aws "$@"
}
new_user() { # new_user ENDPOINT NAME : user with full access; key saved in $TMP/NAME.key
  aws --endpoint-url "$1" iam create-user --user-name "$2" >/dev/null &&
    aws --endpoint-url "$1" iam put-user-policy --user-name "$2" --policy-name all \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' &&
    aws --endpoint-url "$1" iam create-access-key --user-name "$2" \
      --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text | tr '\t' '\n' >"$TMP/$2.key"
}
authenticates_within() { # authenticates_within SECONDS ENDPOINT KEYFILE
  local deadline start t
  start=$(now); deadline=$(python3 -c "print($start + $1)")
  until as_key "$3" --endpoint-url "$2" sts get-caller-identity >/dev/null 2>&1; do
    t=$(now); python3 -c "import sys; sys.exit(0 if $t < $deadline else 1)" || return 1
    sleep 0.1
  done
  python3 -c "print('    accepted after %.2fs' % ($(now) - $start))"
}
home_reachable() { # home_reachable ENDPOINT true|false
  curl -fsS -m 1 "$1/_citadel/healthz" | python3 -c "import json,sys; sys.exit(0 if str(json.load(sys.stdin).get('home_reachable')).lower()=='$2' else 1)"
}
s3_roundtrip() { # s3_roundtrip ENDPOINT BUCKET KEYFILE
  as_key "$3" --endpoint-url "$1" s3 mb "s3://$2" &&
    echo still-here | as_key "$3" --endpoint-url "$1" s3 cp - "s3://$2/k" &&
    as_key "$3" --endpoint-url "$1" s3 cp "s3://$2/k" - | grep -q still-here
}
sqs_roundtrip() { # sqs_roundtrip ENDPOINT QUEUE KEYFILE
  local q
  q=$(as_key "$3" --endpoint-url "$1" sqs create-queue --queue-name "$2" --query QueueUrl --output text) &&
    as_key "$3" --endpoint-url "$1" sqs send-message --queue-url "$q" --message-body hi >/dev/null &&
    as_key "$3" --endpoint-url "$1" sqs receive-message --queue-url "$q" --query 'Messages[0].Body' --output text | grep -q hi
}
users_include() { # users_include ENDPOINT NAME
  aws --endpoint-url "$1" iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | grep -qx "$2"
}
forwarded_create() { # forwarded_create FOLLOWER_ENDPOINT NAME
  aws --endpoint-url "$1" iam create-user --user-name "$2" >/dev/null &&
    aws --endpoint-url "$HOME_EP" iam get-user --user-name "$2"
}
wait_home_reachable() { # wait_home_reachable ENDPOINT true|false
  for _ in $(seq 1 100); do home_reachable "$1" "$2" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}

# 1. A key created in the home region authenticates in both followers within 5 s.
if new_user "$HOME_EP" smoke-alice; then pass iam-create-key-home; else fail iam-create-key-home; fi
for f in $FOLLOWERS; do
  if out=$(authenticates_within 5 "${f#*=}" "$TMP/smoke-alice.key"); then pass "key-propagates-${f%%=*}"; echo "$out"; else fail "key-propagates-${f%%=*}"; fi
done

# 2. IAM calls sent to a follower are made in the home region.
check iam-forwarded forwarded_create http://127.0.0.1:8440 smoke-bob

# 3. A follower that was stopped catches up on restart.
"$RS" stop thessia-1 >/dev/null
new_user "$HOME_EP" smoke-carol
"$RS" start thessia-1 >/dev/null
check follower-restart-catches-up authenticates_within 5 http://127.0.0.1:8442 "$TMP/smoke-carol.key"
check follower-restart-keeps-state as_key "$TMP/smoke-alice.key" --endpoint-url http://127.0.0.1:8442 sts get-caller-identity
authenticates_within 5 http://127.0.0.1:8440 "$TMP/smoke-carol.key" >/dev/null

# 4. Static stability: the home region stops; followers keep serving.
"$RS" pause palaven-1 >/dev/null
for f in $FOLLOWERS; do
  name=${f%%=*}; ep=${f#*=}
  check "$name-notices-home-down" wait_home_reachable "$ep" false
  b="smoke-static-$name"
  check "$name-s3-home-stopped" s3_roundtrip "$ep" "$b" "$TMP/smoke-alice.key"
  check "$name-dynamodb-home-stopped" as_key "$TMP/smoke-carol.key" --endpoint-url "$ep" dynamodb create-table --table-name "$b" \
    --attribute-definitions AttributeName=pk,AttributeType=S --key-schema AttributeName=pk,KeyType=HASH --billing-mode PAY_PER_REQUEST
  check "$name-sqs-home-stopped" sqs_roundtrip "$ep" "$b" "$TMP/smoke-carol.key"
  check "$name-iam-read-from-replica" users_include "$ep" smoke-carol
  if aws --endpoint-url "$ep" iam create-user --user-name "smoke-dave-$name" >"$TMP/log" 2>&1; then
    fail "$name-iam-write-refused" "CreateUser succeeded with the home region stopped"
  elif grep -q ServiceUnavailable "$TMP/log"; then pass "$name-iam-write-refused"
  else fail "$name-iam-write-refused" "$(tail -1 "$TMP/log")"; fi
done

# 5. The home region returns.
"$RS" resume palaven-1 >/dev/null
check home-resumes wait_home_reachable http://127.0.0.1:8440 true
check iam-write-after-resume aws --endpoint-url http://127.0.0.1:8440 iam create-user --user-name smoke-erin
