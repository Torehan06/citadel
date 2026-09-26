#!/usr/bin/env bash
# Terraform smoke checks in harness/smoke.sh's format ("PASS id" / "FAIL id").
# Proposed as smoke.sh's "terraform" set; until it is wired in, run it against
# a running region:
#
#   make serve &
#   examples/terraform/smoke.sh                  # CITADEL_ENDPOINT defaults to :8420
#
# For each stack under examples/terraform/ it copies the configuration to a
# fresh directory (fresh state), builds the Lambda package, then runs init,
# apply, plan -detailed-exitcode (must exit 0: no changes), a check that the
# deployed function answers, and destroy - twice in a row, as M7's exit asks.
# Needs terraform >= 1.6 on PATH, go (wasip1 build) and python3 (zipping).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EP="${CITADEL_ENDPOINT:-http://127.0.0.1:8420}"
export AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$ROOT/harness/aws.config}"
export AWS_SHARED_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$ROOT/harness/aws.credentials}"
export AWS_PAGER=""
export TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1
# Providers are downloaded once and reused across runs.
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$ROOT/.harness/terraform-plugins}"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

step() { # step ID command...
  local id=$1; shift
  if "$@" >>"$TMP/log" 2>&1; then echo "PASS $id"; else echo "FAIL $id"; tail -15 "$TMP/log" | sed 's/^/    /'; fi
  : >"$TMP/log"
}

have_terraform() {
  command -v terraform >/dev/null || { echo "terraform is not on PATH" >&2; return 1; }
}

build_zip() { # DIR
  mkdir -p "$1/build" &&
    (cd "$ROOT/examples/functions/hello-go" && GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -o "$1/build/bootstrap.wasm" .) &&
    (cd "$1/build" && python3 -m zipfile -c function.zip bootstrap.wasm)
}

tf() { # DIR args...
  local dir=$1; shift
  terraform -chdir="$dir" "$@" -no-color
}

# plan -detailed-exitcode: 0 = no changes, 2 = changes (a read-back mismatch).
clean_plan() { # DIR
  tf "$1" plan -detailed-exitcode -var "endpoint=$EP" -var "name=$NAME"
}

invoke_worker() { # DIR
  local fn
  fn=$(tf "$1" output -raw function_arn) &&
    aws --endpoint-url "$EP" lambda invoke --function-name "$fn" --cli-binary-format raw-in-base64-out \
      --payload '{"name":"Terraform"}' "$TMP/out.json" >/dev/null &&
    grep -q '"Hello, Terraform!"' "$TMP/out.json"
}

step smoke-terraform::terraform-installed have_terraform
command -v terraform >/dev/null || exit 1
# Both rounds use the same names, so round 2 also proves destroy left nothing behind.
NAME="tf-$RANDOM"
for stack in single-region; do
  for round in 1 2; do
    DIR="$TMP/$stack-$round"
    id="smoke-terraform::$stack-$round"
    cp -R "$ROOT/examples/terraform/$stack" "$DIR" && rm -rf "$DIR/.terraform" "$DIR"/terraform.tfstate* "$DIR/build"
    step "$id-build"   build_zip "$DIR"
    step "$id-init"    tf "$DIR" init
    step "$id-apply"   tf "$DIR" apply -auto-approve -var "endpoint=$EP" -var "name=$NAME"
    step "$id-plan"    clean_plan "$DIR"
    step "$id-invoke"  invoke_worker "$DIR"
    step "$id-destroy" tf "$DIR" destroy -auto-approve -var "endpoint=$EP" -var "name=$NAME"
  done
done
