#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/validate-release-config.sh"

TMP_DIRS=()
cleanup() {
  local d
  for d in "${TMP_DIRS[@]+"${TMP_DIRS[@]}"}"; do
    rm -rf "$d"
  done
}
trap cleanup EXIT

new_tmp() {
  local d
  d="$(mktemp -d)"
  TMP_DIRS+=("$d")
  echo "$d"
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_env() {
  local file="$1"
  local secret="${2:-}"
  local include_secret="${3:-yes}"
  cat >"$file" <<EOF
SKILLHUB_PUBLIC_BASE_URL=https://skillhub.example.com
POSTGRES_DB=skillhub
POSTGRES_USER=skillhub
POSTGRES_PASSWORD=strong-postgres-password
SESSION_COOKIE_SECURE=true
BOOTSTRAP_ADMIN_ENABLED=false
SKILLHUB_TRUST_FORWARDED_PROTO=false
SKILLHUB_BUILTIN_SKILLS_ENABLED=true
SKILLHUB_STORAGE_PROVIDER=s3
SKILLHUB_STORAGE_S3_ENDPOINT=https://storage.example.com
SKILLHUB_STORAGE_S3_BUCKET=skillhub
SKILLHUB_STORAGE_S3_ACCESS_KEY=release-access-key
SKILLHUB_STORAGE_S3_SECRET_KEY=release-secret-key
SKILLHUB_STORAGE_S3_REGION=us-east-1
SKILLHUB_STORAGE_S3_FORCE_PATH_STYLE=false
SKILLHUB_STORAGE_S3_AUTO_CREATE_BUCKET=false
EOF
  if [[ "$include_secret" == "yes" ]]; then
    printf 'SKILLHUB_DOWNLOAD_ANON_COOKIE_SECRET=%s\n' "$secret" >>"$file"
  fi
}

expect_fail() {
  local file="$1"
  local expected="$2"
  local output
  if output="$("$SCRIPT" "$file" 2>&1)"; then
    fail "expected validation to fail for $file"
  fi
  if [[ "$output" != *"$expected"* ]]; then
    fail "expected output to contain '$expected', got: $output"
  fi
}

tmp="$(new_tmp)"

valid_env="$tmp/valid.env"
write_env "$valid_env" "release-download-secret-32-bytes-minimum"
"$SCRIPT" "$valid_env" >/dev/null

disabled_builtin_skills_env="$tmp/disabled-builtin-skills.env"
write_env "$disabled_builtin_skills_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SKILLHUB_BUILTIN_SKILLS_ENABLED=false" >>"$disabled_builtin_skills_env"
"$SCRIPT" "$disabled_builtin_skills_env" >/dev/null

valid_dingtalk_env="$tmp/valid-dingtalk.env"
write_env "$valid_dingtalk_env" "release-download-secret-32-bytes-minimum"
cat >>"$valid_dingtalk_env" <<'EOF'
SKILLHUB_AUTH_DINGTALK_ENABLED=true
SKILLHUB_AUTH_DINGTALK_AUTHORITY=dingtalk.corp
SKILLHUB_AUTH_DINGTALK_CONNECT_TIMEOUT=PT5S
SKILLHUB_AUTH_DINGTALK_READ_TIMEOUT=PT10S
SKILLHUB_AUTH_DINGTALK_MAX_RESPONSE_BYTES=1048576
OAUTH2_DINGTALK_CLIENT_ID=real-dingtalk-client
OAUTH2_DINGTALK_CLIENT_SECRET=real-dingtalk-secret
EOF
"$SCRIPT" "$valid_dingtalk_env" >/dev/null

missing_dingtalk_secret_env="$tmp/missing-dingtalk-secret.env"
grep -v '^OAUTH2_DINGTALK_CLIENT_SECRET=' "$valid_dingtalk_env" >"$missing_dingtalk_secret_env"
expect_fail "$missing_dingtalk_secret_env" "OAUTH2_DINGTALK_CLIENT_SECRET is required"

invalid_dingtalk_authority_env="$tmp/invalid-dingtalk-authority.env"
cp "$valid_dingtalk_env" "$invalid_dingtalk_authority_env"
sed -i 's/^SKILLHUB_AUTH_DINGTALK_AUTHORITY=.*/SKILLHUB_AUTH_DINGTALK_AUTHORITY=https:\/\/dingtalk.example.com/' "$invalid_dingtalk_authority_env"
expect_fail "$invalid_dingtalk_authority_env" "SKILLHUB_AUTH_DINGTALK_AUTHORITY contains invalid characters"

invalid_dingtalk_size_env="$tmp/invalid-dingtalk-size.env"
cp "$valid_dingtalk_env" "$invalid_dingtalk_size_env"
sed -i 's/^SKILLHUB_AUTH_DINGTALK_MAX_RESPONSE_BYTES=.*/SKILLHUB_AUTH_DINGTALK_MAX_RESPONSE_BYTES=512/' "$invalid_dingtalk_size_env"
expect_fail "$invalid_dingtalk_size_env" "SKILLHUB_AUTH_DINGTALK_MAX_RESPONSE_BYTES must be between 1024 and 1048576"

missing_env="$tmp/missing.env"
write_env "$missing_env" "" no
expect_fail "$missing_env" "SKILLHUB_DOWNLOAD_ANON_COOKIE_SECRET is required"

placeholder_env="$tmp/placeholder.env"
write_env "$placeholder_env" "change-me-in-production"
expect_fail "$placeholder_env" "SKILLHUB_DOWNLOAD_ANON_COOKIE_SECRET still uses placeholder/default value"

short_env="$tmp/short.env"
write_env "$short_env" "too-short"
expect_fail "$short_env" "SKILLHUB_DOWNLOAD_ANON_COOKIE_SECRET must be at least 32 characters"

invalid_forwarded_proto_env="$tmp/invalid-forwarded-proto.env"
write_env "$invalid_forwarded_proto_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SKILLHUB_TRUST_FORWARDED_PROTO=yes" >>"$invalid_forwarded_proto_env"
expect_fail "$invalid_forwarded_proto_env" "SKILLHUB_TRUST_FORWARDED_PROTO must be true or false"

invalid_builtin_skills_env="$tmp/invalid-builtin-skills.env"
write_env "$invalid_builtin_skills_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SKILLHUB_BUILTIN_SKILLS_ENABLED=yes" >>"$invalid_builtin_skills_env"
expect_fail "$invalid_builtin_skills_env" "SKILLHUB_BUILTIN_SKILLS_ENABLED must be true or false"

valid_redis_cluster_env="$tmp/valid-redis-cluster.env"
write_env "$valid_redis_cluster_env" "release-download-secret-32-bytes-minimum"
cat >>"$valid_redis_cluster_env" <<'EOF'
SPRING_DATA_REDIS_CLUSTER_NODES=redis-a.example.com:6379,redis-b.example.com:6380
SPRING_DATA_REDIS_CLUSTER_MAX_REDIRECTS=5
SPRING_DATA_REDIS_SSL_ENABLED=true
EOF
"$SCRIPT" "$valid_redis_cluster_env" >/dev/null

invalid_redis_cluster_node_env="$tmp/invalid-redis-cluster-node.env"
write_env "$invalid_redis_cluster_node_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SPRING_DATA_REDIS_CLUSTER_NODES=redis-a.example.com" >>"$invalid_redis_cluster_node_env"
expect_fail "$invalid_redis_cluster_node_env" "SPRING_DATA_REDIS_CLUSTER_NODES entries must use host:port"

invalid_redis_cluster_port_env="$tmp/invalid-redis-cluster-port.env"
write_env "$invalid_redis_cluster_port_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SPRING_DATA_REDIS_CLUSTER_NODES=redis-a.example.com:65536" >>"$invalid_redis_cluster_port_env"
expect_fail "$invalid_redis_cluster_port_env" "SPRING_DATA_REDIS_CLUSTER_NODES port must be between 1 and 65535"

invalid_redis_redirects_env="$tmp/invalid-redis-redirects.env"
write_env "$invalid_redis_redirects_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SPRING_DATA_REDIS_CLUSTER_MAX_REDIRECTS=-1" >>"$invalid_redis_redirects_env"
expect_fail "$invalid_redis_redirects_env" "SPRING_DATA_REDIS_CLUSTER_MAX_REDIRECTS must be a non-negative integer"

invalid_redis_database_env="$tmp/invalid-redis-database.env"
write_env "$invalid_redis_database_env" "release-download-secret-32-bytes-minimum"
cat >>"$invalid_redis_database_env" <<'EOF'
SPRING_DATA_REDIS_CLUSTER_NODES=redis-a.example.com:6379
SPRING_DATA_REDIS_DATABASE=1
EOF
expect_fail "$invalid_redis_database_env" "SPRING_DATA_REDIS_DATABASE must be 0 when SPRING_DATA_REDIS_CLUSTER_NODES is set"

valid_redis_sentinel_env="$tmp/valid-redis-sentinel.env"
write_env "$valid_redis_sentinel_env" "release-download-secret-32-bytes-minimum"
cat >>"$valid_redis_sentinel_env" <<'EOF'
SPRING_DATA_REDIS_SENTINEL_MASTER=mymaster
SPRING_DATA_REDIS_SENTINEL_NODES=sentinel-a.example.com:26379,sentinel-b.example.com:26379
SKILLHUB_REDIS_SENTINEL_CHECK_SENTINELS_LIST=false
EOF
"$SCRIPT" "$valid_redis_sentinel_env" >/dev/null

missing_redis_sentinel_nodes_env="$tmp/missing-redis-sentinel-nodes.env"
write_env "$missing_redis_sentinel_nodes_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SPRING_DATA_REDIS_SENTINEL_MASTER=mymaster" >>"$missing_redis_sentinel_nodes_env"
expect_fail "$missing_redis_sentinel_nodes_env" "SPRING_DATA_REDIS_SENTINEL_NODES is required when SPRING_DATA_REDIS_SENTINEL_MASTER is set"

missing_redis_sentinel_master_env="$tmp/missing-redis-sentinel-master.env"
write_env "$missing_redis_sentinel_master_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SPRING_DATA_REDIS_SENTINEL_NODES=sentinel-a.example.com:26379" >>"$missing_redis_sentinel_master_env"
expect_fail "$missing_redis_sentinel_master_env" "SPRING_DATA_REDIS_SENTINEL_MASTER is required when SPRING_DATA_REDIS_SENTINEL_NODES is set"

invalid_redis_sentinel_port_env="$tmp/invalid-redis-sentinel-port.env"
write_env "$invalid_redis_sentinel_port_env" "release-download-secret-32-bytes-minimum"
cat >>"$invalid_redis_sentinel_port_env" <<'EOF'
SPRING_DATA_REDIS_SENTINEL_MASTER=mymaster
SPRING_DATA_REDIS_SENTINEL_NODES=sentinel-a.example.com:70000
EOF
expect_fail "$invalid_redis_sentinel_port_env" "SPRING_DATA_REDIS_SENTINEL_NODES port must be between 1 and 65535"

invalid_redis_sentinel_check_env="$tmp/invalid-redis-sentinel-check.env"
write_env "$invalid_redis_sentinel_check_env" "release-download-secret-32-bytes-minimum"
printf '%s\n' "SKILLHUB_REDIS_SENTINEL_CHECK_SENTINELS_LIST=yes" >>"$invalid_redis_sentinel_check_env"
expect_fail "$invalid_redis_sentinel_check_env" "SKILLHUB_REDIS_SENTINEL_CHECK_SENTINELS_LIST must be true or false"

valid_ldaps_env="$tmp/valid-ldaps.env"
write_env "$valid_ldaps_env" "release-download-secret-32-bytes-minimum"
cat >>"$valid_ldaps_env" <<'EOF'
SKILLHUB_AUTH_LDAP_ENABLED=true
SKILLHUB_AUTH_LDAP_PROVIDER_CODE=ldap-main
SKILLHUB_AUTH_LDAP_DISPLAY_NAME=Corporate Directory
SKILLHUB_AUTH_LDAP_AUTHORITY=corp-directory
SKILLHUB_AUTH_LDAP_URL=ldaps://ldap.example.com:636
SKILLHUB_AUTH_LDAP_DIRECTORY_TYPE=OPENLDAP
SKILLHUB_AUTH_LDAP_BASE_DN=dc=example,dc=com
SKILLHUB_AUTH_LDAP_USER_SEARCH_FILTER=(uid={0})
SKILLHUB_AUTH_LDAP_BIND_DN=cn=skillhub,dc=example,dc=com
SKILLHUB_AUTH_LDAP_BIND_PASSWORD=release-ldap-bind-password
EOF
"$SCRIPT" "$valid_ldaps_env" >/dev/null

valid_starttls_env="$tmp/valid-starttls.env"
cp "$valid_ldaps_env" "$valid_starttls_env"
sed -i 's|ldaps://ldap.example.com:636|ldap://ldap.example.com:389|' "$valid_starttls_env"
printf '%s\n' "SKILLHUB_AUTH_LDAP_START_TLS=true" >>"$valid_starttls_env"
"$SCRIPT" "$valid_starttls_env" >/dev/null

insecure_ldap_env="$tmp/insecure-ldap.env"
cp "$valid_ldaps_env" "$insecure_ldap_env"
sed -i 's|ldaps://ldap.example.com:636|ldap://ldap.example.com:389|' "$insecure_ldap_env"
expect_fail "$insecure_ldap_env" "SKILLHUB_AUTH_LDAP_START_TLS must be true for an ldap URL"

missing_ldap_secret_env="$tmp/missing-ldap-secret.env"
grep -v '^SKILLHUB_AUTH_LDAP_BIND_PASSWORD=' "$valid_ldaps_env" >"$missing_ldap_secret_env"
expect_fail "$missing_ldap_secret_env" "SKILLHUB_AUTH_LDAP_BIND_PASSWORD is required"

custom_ldap_without_subject_env="$tmp/custom-ldap-without-subject.env"
cp "$valid_ldaps_env" "$custom_ldap_without_subject_env"
printf '%s\n' "SKILLHUB_AUTH_LDAP_DIRECTORY_TYPE=CUSTOM" >>"$custom_ldap_without_subject_env"
expect_fail "$custom_ldap_without_subject_env" "SKILLHUB_AUTH_LDAP_SUBJECT_ATTRIBUTE is required"

draft_env="$tmp/draft.env"
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    SKILLHUB_DOWNLOAD_ANON_COOKIE_SECRET=*)
      printf '%s\n' "SKILLHUB_DOWNLOAD_ANON_COOKIE_SECRET=release-download-secret-32-bytes-minimum"
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
done <"$REPO_ROOT/.env.release.draft" >"$draft_env"
expect_fail "$draft_env" "POSTGRES_PASSWORD"

echo "validate-release-config-test passed"
