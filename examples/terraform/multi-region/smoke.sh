#!/usr/bin/env bash
# Multi-region Terraform smoke checks in harness/smoke.sh's format
# ("PASS id" / "FAIL id"). Starts the three local regions of
# examples/multiregion-local (ports 8440-8442, data under
# .harness/data/tf-multiregion), then twice in a row from fresh state: init,
# apply, plan -detailed-exitcode (must exit 0: no changes), checks that S3 and
# the global table replicate across regions, destroy, and checks nothing is
# left. Needs terraform >= 1.6 (on PATH or in .harness/bin), aws, python3,
# curl and openssl.
#
#   examples/terraform/multi-region/smoke.sh
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
export AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$ROOT/harness/aws.config}"
export AWS_SHARED_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$ROOT/harness/aws.credentials}"
export AWS_PAGER=""
export TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$ROOT/.harness/terraform-plugins}"
export CITADEL_MR_DATA="${CITADEL_MR_DATA:-$ROOT/.harness/data/tf-multiregion}"
command -v terraform >/dev/null || PATH="$ROOT/.harness/bin:$PATH"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
REGIONS="$ROOT/examples/multiregion-local/regions.sh"
TMP="$(mktemp -d)"
trap '"$REGIONS" clean >/dev/null 2>&1; rm -rf "$TMP"' EXIT

P=http://127.0.0.1:8441 # palaven-1
T=http://127.0.0.1:8440 # tuchanka-1
H=http://127.0.0.1:8442 # thessia-1
awsr() { local ep=$1 region=$2; shift 2; aws --endpoint-url "$ep" --region "$region" "$@"; }

step() { # step ID command...
  local id=$1; shift
  if "$@" >>"$TMP/log" 2>&1; then echo "PASS $id"; else echo "FAIL $id"; tail -15 "$TMP/log" | sed 's/^/    /'; fi
  : >"$TMP/log"
}

tf() { local dir=$1; shift; terraform -chdir="$dir" "$@" -no-color; }

# until SECONDS command...: retry for up to SECONDS.
until_ok() {
  local deadline=$(($(date +%s) + $1)); shift
  until "$@"; do [ "$(date +%s)" -lt "$deadline" ] || return 1; sleep 0.2; done
}

s3_replicates() {
  echo "crr $NAME" >"$TMP/obj"
  awsr $P palaven-1 s3api put-object --bucket "$NAME-source" --key hello.txt --body "$TMP/obj" >/dev/null &&
    until_ok 10 sh -c "aws --endpoint-url $H --region thessia-1 s3 cp s3://$NAME-replica/hello.txt - 2>/dev/null | grep -q 'crr $NAME'"
}

table_replicates() {
  awsr $T tuchanka-1 dynamodb put-item --table-name "$NAME-sessions" --item '{"id":{"S":"from-tuchanka"},"v":{"S":"hi"}}' &&
    for r in "$P palaven-1" "$H thessia-1"; do
      # shellcheck disable=SC2086
      until_ok 10 sh -c "aws --endpoint-url ${r% *} --region ${r#* } dynamodb get-item --table-name $NAME-sessions \
        --key '{\"id\":{\"S\":\"from-tuchanka\"}}' --output text | grep -q hi" || return 1
    done
}

# The CLI prints "None" for a list the service leaves out (ListQueues sends
# no QueueUrls when there are none).
empty() { local out; out=$("$@" --output text) || return 1; [ -z "$out" ] || [ "$out" = None ] || { echo "left: $out"; return 1; }; }

nothing_left() {
  local ep region
  for r in "$P palaven-1" "$T tuchanka-1" "$H thessia-1"; do
    ep=${r% *}; region=${r#* }
    empty awsr "$ep" "$region" dynamodb list-tables --query 'TableNames[]' || return 1
    empty awsr "$ep" "$region" s3api list-buckets --query 'Buckets[].Name' || return 1
    empty awsr "$ep" "$region" sqs list-queues --query 'QueueUrls[]' || return 1
  done
}

command -v terraform >/dev/null || { echo "FAIL smoke-terraform::multi-region-terraform-installed"; exit 1; }
"$REGIONS" clean >/dev/null 2>&1
step smoke-terraform::multi-region-start "$REGIONS" start
NAME="tfm-$RANDOM"
for round in 1 2; do
  DIR="$TMP/multi-region-$round"
  id="smoke-terraform::multi-region-$round"
  cp -R "$ROOT/examples/terraform/multi-region" "$DIR" && rm -rf "$DIR/.terraform" "$DIR"/terraform.tfstate* "$DIR/smoke.sh"
  step "$id-init"        tf "$DIR" init
  step "$id-apply"       tf "$DIR" apply -auto-approve -var "name=$NAME"
  step "$id-plan"        tf "$DIR" plan -detailed-exitcode -var "name=$NAME"
  step "$id-s3-crr"      s3_replicates
  step "$id-global-table" table_replicates
  step "$id-destroy"     tf "$DIR" destroy -auto-approve -var "name=$NAME"
  step "$id-clean"       nothing_left
done
