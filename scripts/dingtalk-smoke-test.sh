#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
EXPECTED_ENABLED="${DINGTALK_EXPECTED_ENABLED:-false}"
RESPONSE_FILE="$(mktemp)"

cleanup() {
  rm -f "$RESPONSE_FILE"
}
trap cleanup EXIT

status="$(curl --max-time 10 -s -o "$RESPONSE_FILE" -w "%{http_code}" \
  "$BASE_URL/api/v1/auth/providers" || true)"
if [[ "$status" != "200" ]]; then
  echo "FAIL: authentication provider catalog returned HTTP $status" >&2
  exit 1
fi

python3 - "$RESPONSE_FILE" "$EXPECTED_ENABLED" <<'PY'
import json
import sys

response_file, expected_enabled = sys.argv[1:]
with open(response_file, encoding="utf-8") as response:
    providers = json.load(response)["data"]

dingtalk = [provider for provider in providers if provider.get("id") == "dingtalk"]
if expected_enabled == "true":
    if len(dingtalk) != 1:
        raise SystemExit("FAIL: enabled DingTalk provider is missing from catalog")
    expected_url = "/oauth2/authorization/dingtalk"
    if dingtalk[0].get("authorizationUrl") != expected_url:
        raise SystemExit(
            "FAIL: DingTalk authorization URL is not the trusted route: "
            + repr(dingtalk[0].get("authorizationUrl")))
    print("PASS: enabled DingTalk provider exposes the trusted authorization route")
else:
    if dingtalk:
        raise SystemExit("FAIL: disabled DingTalk provider is visible in catalog")
    print("PASS: disabled DingTalk provider is hidden from catalog")
PY

if [[ "$EXPECTED_ENABLED" == "false" ]]; then
  route_status="$(curl --max-time 10 -s -o /dev/null -w "%{http_code}" \
    "$BASE_URL/oauth2/authorization/dingtalk" || true)"
  if [[ "$route_status" != "403" ]]; then
    echo "FAIL: disabled DingTalk route returned HTTP $route_status (expected 403)" >&2
    exit 1
  fi
  echo "PASS: disabled DingTalk route fails before upstream redirect (HTTP 403)"
fi
