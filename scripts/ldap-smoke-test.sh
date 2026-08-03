#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
PROVIDER="${LDAP_SMOKE_PROVIDER:-ldap}"
USERNAME="${LDAP_SMOKE_USERNAME:-}"
PASSWORD="${LDAP_SMOKE_PASSWORD:-}"
RENAMED_USERNAME="${LDAP_SMOKE_RENAMED_USERNAME:-}"
RENAMED_PASSWORD="${LDAP_SMOKE_RENAMED_PASSWORD:-$PASSWORD}"
WRONG_PASSWORD="${LDAP_SMOKE_WRONG_PASSWORD:-skillhub-invalid-password}"
UNKNOWN_USERNAME="${LDAP_SMOKE_UNKNOWN_USERNAME:-${USERNAME}-unknown}"
COOKIE_JAR="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
PASS=0
FAIL=0

cleanup() {
  rm -f "$COOKIE_JAR" "$RESPONSE_FILE"
}
trap cleanup EXIT

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
  echo "ERROR: LDAP_SMOKE_USERNAME and LDAP_SMOKE_PASSWORD are required" >&2
  exit 2
fi

csrf_token() {
  awk '$6 == "XSRF-TOKEN" { print $7 }' "$COOKIE_JAR" | tail -n 1
}

check_status() {
  local description="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "PASS: $description (HTTP $actual)"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $description (expected HTTP $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

json_user_id() {
  python3 - "$RESPONSE_FILE" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as response:
        print(json.load(response)["data"]["userId"])
except (KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
}

echo "=== SkillHub LDAP Operator Smoke Test ==="
echo "Target: $BASE_URL"
echo "Provider: $PROVIDER"
echo

HEALTH_STATUS="$(curl --retry 3 --retry-delay 1 --max-time 10 -s \
  -o /dev/null -w "%{http_code}" \
  "$BASE_URL/actuator/health" || true)"
check_status "Health endpoint" "$HEALTH_STATUS" "200"

METHODS_STATUS="$(curl --max-time 10 -s \
  -o "$RESPONSE_FILE" -w "%{http_code}" \
  "$BASE_URL/api/v1/auth/methods" || true)"
if [[ "$METHODS_STATUS" == "200" ]] \
  && PROVIDER_VALUE="$PROVIDER" python3 - "$RESPONSE_FILE" <<'PY'
import json
import os
import sys

provider = os.environ["PROVIDER_VALUE"]
try:
    methods = json.load(open(sys.argv[1], encoding="utf-8"))["data"]
except (OSError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)

raise SystemExit(0 if any(
    method.get("provider") == provider
    and method.get("methodType") == "DIRECT_PASSWORD"
    for method in methods
) else 1)
PY
then
  echo "PASS: LDAP provider is exposed as a direct-password method"
  PASS=$((PASS + 1))
else
  echo "FAIL: LDAP provider is not exposed as a direct-password method (HTTP $METHODS_STATUS)"
  FAIL=$((FAIL + 1))
fi

# Obtain a CSRF token before the first state-changing request.
curl --max-time 10 -s -c "$COOKIE_JAR" \
  "$BASE_URL/api/v1/auth/me" >/dev/null || true
CSRF_TOKEN="$(csrf_token)"
if [[ -z "$CSRF_TOKEN" ]]; then
  echo "FAIL: server did not issue an XSRF token"
  FAIL=$((FAIL + 1))
else
  echo "PASS: XSRF token issued"
  PASS=$((PASS + 1))
fi

LOGIN_STATUS="$(curl --max-time 15 -s \
  -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/auth/direct/login" \
  -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(python3 - "$PROVIDER" "$USERNAME" "$PASSWORD" <<'PY'
import json
import sys
print(json.dumps({
    "provider": sys.argv[1],
    "username": sys.argv[2],
    "password": sys.argv[3],
}))
PY
)" || true)"
check_status "LDAP first login" "$LOGIN_STATUS" "200"
FIRST_USER_ID=""
if [[ "$LOGIN_STATUS" == "200" ]]; then
  FIRST_USER_ID="$(json_user_id || true)"
  if [[ -n "$FIRST_USER_ID" ]]; then
    echo "PASS: first login returned a platform user id"
    PASS=$((PASS + 1))
  else
    echo "FAIL: first login response did not contain a user id"
    FAIL=$((FAIL + 1))
  fi
fi

LOGOUT_CSRF="$(csrf_token)"
LOGOUT_STATUS="$(curl --max-time 10 -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/auth/logout" \
  -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $LOGOUT_CSRF" || true)"
if [[ "$LOGIN_STATUS" == "200" ]]; then
  if [[ "$LOGOUT_STATUS" == "200" || "$LOGOUT_STATUS" == "204" || "$LOGOUT_STATUS" == "302" ]]; then
    echo "PASS: logout after first login (HTTP $LOGOUT_STATUS)"
    PASS=$((PASS + 1))
  else
    echo "FAIL: logout after first login (got HTTP $LOGOUT_STATUS)"
    FAIL=$((FAIL + 1))
  fi
fi

CSRF_TOKEN="$(csrf_token)"
REPEAT_STATUS="$(curl --max-time 15 -s \
  -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/auth/direct/login" \
  -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(python3 - "$PROVIDER" "$USERNAME" "$PASSWORD" <<'PY'
import json
import sys
print(json.dumps({
    "provider": sys.argv[1],
    "username": sys.argv[2],
    "password": sys.argv[3],
}))
PY
)" || true)"
check_status "LDAP repeat login" "$REPEAT_STATUS" "200"
if [[ "$REPEAT_STATUS" == "200" && -n "$FIRST_USER_ID" ]]; then
  REPEAT_USER_ID="$(json_user_id || true)"
  if [[ "$REPEAT_USER_ID" == "$FIRST_USER_ID" ]]; then
    echo "PASS: repeat login resolved the same platform user"
    PASS=$((PASS + 1))
  else
    echo "FAIL: repeat login resolved a different platform user"
    FAIL=$((FAIL + 1))
  fi
fi

if [[ -n "$RENAMED_USERNAME" && "$REPEAT_STATUS" == "200" ]]; then
  LOGOUT_CSRF="$(csrf_token)"
  curl --max-time 10 -s -o /dev/null \
    -X POST "$BASE_URL/api/v1/auth/logout" \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -H "X-XSRF-TOKEN: $LOGOUT_CSRF" || true
  CSRF_TOKEN="$(csrf_token)"
  RENAMED_STATUS="$(curl --max-time 15 -s \
    -o "$RESPONSE_FILE" -w "%{http_code}" \
    -X POST "$BASE_URL/api/v1/auth/direct/login" \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$(python3 - "$PROVIDER" "$RENAMED_USERNAME" "$RENAMED_PASSWORD" <<'PY'
import json
import sys
print(json.dumps({
    "provider": sys.argv[1],
    "username": sys.argv[2],
    "password": sys.argv[3],
}))
PY
)" || true)"
  check_status "LDAP login after username change" "$RENAMED_STATUS" "200"
  if [[ "$RENAMED_STATUS" == "200" && -n "$FIRST_USER_ID" ]]; then
    RENAMED_USER_ID="$(json_user_id || true)"
    if [[ "$RENAMED_USER_ID" == "$FIRST_USER_ID" ]]; then
      echo "PASS: username change preserved the stable platform identity"
      PASS=$((PASS + 1))
    else
      echo "FAIL: username change created or resolved another platform identity"
      FAIL=$((FAIL + 1))
    fi
  fi
else
  echo "INFO: LDAP_SMOKE_RENAMED_USERNAME not set; username-change check skipped"
fi

if [[ "$REPEAT_STATUS" == "200" ]]; then
  LOGOUT_CSRF="$(csrf_token)"
  curl --max-time 10 -s -o /dev/null \
    -X POST "$BASE_URL/api/v1/auth/logout" \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -H "X-XSRF-TOKEN: $LOGOUT_CSRF" || true
fi

CSRF_TOKEN="$(csrf_token)"
INVALID_PASSWORD_STATUS="$(curl --max-time 15 -s \
  -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/auth/direct/login" \
  -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(python3 - "$PROVIDER" "$USERNAME" "$WRONG_PASSWORD" <<'PY'
import json
import sys
print(json.dumps({
    "provider": sys.argv[1],
    "username": sys.argv[2],
    "password": sys.argv[3],
}))
PY
)" || true)"
check_status "Invalid LDAP password is rejected" "$INVALID_PASSWORD_STATUS" "401"
if grep -Eiq 'ldap|bind|entryuuid|objectguid|directory|upstream' "$RESPONSE_FILE"; then
  echo "FAIL: invalid-password response leaks upstream details"
  FAIL=$((FAIL + 1))
else
  echo "PASS: invalid-password response contains no upstream detail"
  PASS=$((PASS + 1))
fi

CSRF_TOKEN="$(csrf_token)"
UNKNOWN_STATUS="$(curl --max-time 15 -s \
  -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/auth/direct/login" \
  -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(python3 - "$PROVIDER" "$UNKNOWN_USERNAME" "$PASSWORD" <<'PY'
import json
import sys
print(json.dumps({
    "provider": sys.argv[1],
    "username": sys.argv[2],
    "password": sys.argv[3],
}))
PY
)" || true)"
check_status "Unknown LDAP identity is rejected" "$UNKNOWN_STATUS" "401"
if grep -Eiq 'ldap|bind|entryuuid|objectguid|directory|upstream' "$RESPONSE_FILE"; then
  echo "FAIL: unknown-identity response leaks upstream details"
  FAIL=$((FAIL + 1))
else
  echo "PASS: unknown-identity response contains no upstream detail"
  PASS=$((PASS + 1))
fi

if [[ "$PASS" -gt 0 && "$FAIL" -eq 0 ]]; then
  echo
  echo "LDAP smoke test passed: $PASS checks"
  exit 0
fi

echo
echo "LDAP smoke test failed: $PASS passed, $FAIL failed"
exit 1
