#!/usr/bin/env bash
# End-to-end smoke checks with the real aws CLI v2 (its defaults - SigV4,
# aws-chunked uploads with trailing CRC checksums, multipart above 8 MiB -
# are exactly what everyday clients send). Prints "PASS id" / "FAIL id" lines.
# Called by harness/conformance.sh smoke-<name>; CITADEL_ENDPOINT is set there.
source "$(dirname "$0")/lib.sh"
EP="${CITADEL_ENDPOINT:?set by conformance.sh}"
WHAT="${1:-s3}"
TMP="$(mktemp -d "$H/smoke.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
aws_() { aws --endpoint-url "$EP" --cli-read-timeout 30 --cli-connect-timeout 5 "$@"; }

step() { # step ID command...
  local id=$1; shift
  if "$@" >>"$TMP/log" 2>&1; then echo "PASS $id"; else echo "FAIL $id"; tail -5 "$TMP/log" | sed 's/^/    /'; fi
}

smoke_s3() {
  local b="smoke-$RANDOM$RANDOM"
  head -c 1024 /dev/urandom >"$TMP/small.bin"
  head -c $((20 * 1024 * 1024)) /dev/urandom >"$TMP/big.bin"   # > 8 MiB: CLI switches to multipart

  step smoke-s3::make-bucket        aws_ s3 mb "s3://$b"
  step smoke-s3::list-buckets       sh -c "aws --endpoint-url '$EP' s3 ls | grep -q '$b'"
  step smoke-s3::put-small          aws_ s3 cp "$TMP/small.bin" "s3://$b/small.bin"
  step smoke-s3::put-multipart      aws_ s3 cp "$TMP/big.bin" "s3://$b/dir/big.bin"
  step smoke-s3::list-recursive     sh -c "aws --endpoint-url '$EP' s3 ls 's3://$b' --recursive | grep -q 'dir/big.bin'"
  step smoke-s3::get-small          sh -c "aws --endpoint-url '$EP' s3 cp 's3://$b/small.bin' '$TMP/small.out' && cmp -s '$TMP/small.bin' '$TMP/small.out'"
  step smoke-s3::get-multipart      sh -c "aws --endpoint-url '$EP' s3 cp 's3://$b/dir/big.bin' '$TMP/big.out' && cmp -s '$TMP/big.bin' '$TMP/big.out'"
  step smoke-s3::head-object        sh -c "aws --endpoint-url '$EP' s3api head-object --bucket '$b' --key small.bin --query ContentLength --output text | grep -qx 1024"
  step smoke-s3::presigned-get      sh -c "curl -fsS \"\$(aws --endpoint-url '$EP' s3 presign 's3://$b/small.bin' --expires-in 300)\" -o '$TMP/presigned.out' && cmp -s '$TMP/small.bin' '$TMP/presigned.out'"
  step smoke-s3::sync-roundtrip     sh -c "mkdir -p '$TMP/tree/a/b' && for i in 1 2 3 4 5; do echo \$i >'$TMP/tree/a/f'\$i; echo \$i >'$TMP/tree/a/b/g'\$i; done \
                                          && aws --endpoint-url '$EP' s3 sync '$TMP/tree' 's3://$b/tree' \
                                          && aws --endpoint-url '$EP' s3 sync 's3://$b/tree' '$TMP/tree2' && diff -r '$TMP/tree' '$TMP/tree2'"
  step smoke-s3::delete-recursive   aws_ s3 rm "s3://$b" --recursive
  step smoke-s3::remove-bucket      aws_ s3 rb "s3://$b"
}

case "$WHAT" in
  s3) smoke_s3 ;;
  *) echo "unknown smoke set: $WHAT" >&2; exit 2 ;;
esac
