#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="skillhub-identity-v2-$$"
POSTGRES_CONTAINER="${RUN_ID}-postgres"
NETWORK="${RUN_ID}-network"
POSTGRES_USER="identity_v2"
POSTGRES_PASSWORD="identity-v2-test-password"
POSTGRES_DB="identity_v2"
MAVEN_CACHE_DIR="${MAVEN_CACHE_DIR:-${HOME}/.m2}"

log() {
  printf '[identity-binding-v2] %s\n' "$*"
}

cleanup() {
  exit_code="$?"
  if [[ "${exit_code}" -ne 0 ]]; then
    log "failed with exit code ${exit_code}"
    docker ps -a \
      --filter "label=skillhub.test.run=${RUN_ID}" \
      --format 'resource={{.Names}} status={{.Status}}' || true
    docker logs "${POSTGRES_CONTAINER}" 2>&1 || true
  fi
  docker rm -f "${POSTGRES_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "creating isolated Docker network ${NETWORK}"
docker network create \
  --label "skillhub.test.run=${RUN_ID}" \
  "${NETWORK}" >/dev/null
log "starting isolated PostgreSQL container ${POSTGRES_CONTAINER}"
docker run -d \
  --name "${POSTGRES_CONTAINER}" \
  --label "skillhub.test.run=${RUN_ID}" \
  --network "${NETWORK}" \
  --memory=1g \
  --cpus=1 \
  -e "POSTGRES_USER=${POSTGRES_USER}" \
  -e "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" \
  -e "POSTGRES_DB=${POSTGRES_DB}" \
  -p 127.0.0.1::5432 \
  postgres:16-alpine >/dev/null

log "waiting for PostgreSQL readiness"
for _ in $(seq 1 60); do
  if docker exec "${POSTGRES_CONTAINER}" \
      pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
      >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${POSTGRES_CONTAINER}" \
  pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
  >/dev/null
log "PostgreSQL is ready"

run_test() {
  test_class="$1"
  flyway_target="${2:-}"
  java_version=""
  if command -v java >/dev/null 2>&1; then
    java_version="$(java -version 2>&1)"
  fi
  if [[ "${java_version}" == *'"21.'* ]]; then
    host_port="$(docker port "${POSTGRES_CONTAINER}" 5432/tcp \
      | sed -n 's/.*://p')"
    if [[ -z "${host_port}" ]]; then
      log "Docker did not publish a PostgreSQL host port"
      return 1
    fi
    log "running ${test_class} with host Java 21"
    (
      cd "${REPO_ROOT}/server"
      IDENTITY_BINDING_V2_POSTGRES_URL="jdbc:postgresql://127.0.0.1:${host_port}/${POSTGRES_DB}" \
      IDENTITY_BINDING_V2_POSTGRES_USERNAME="${POSTGRES_USER}" \
      IDENTITY_BINDING_V2_POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
      IDENTITY_BINDING_V2_FLYWAY_TARGET="${flyway_target}" \
      MAVEN_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m" \
        ./mvnw \
          -pl skillhub-app \
          -am \
          "-Dtest=${test_class}" \
          -Dsurefire.failIfNoSpecifiedTests=false \
          test
    )
    return
  fi

  log "running ${test_class} with containerized Java 21"
  mkdir -p "${MAVEN_CACHE_DIR}"
  docker run --rm \
    --name "${RUN_ID}-java" \
    --label "skillhub.test.run=${RUN_ID}" \
    --network "${NETWORK}" \
    --memory=4g \
    --cpus=2 \
    --user "$(id -u):$(id -g)" \
    -e MAVEN_USER_HOME=/tmp/skillhub-maven-home/.m2 \
    -e MAVEN_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m" \
    -e "IDENTITY_BINDING_V2_POSTGRES_URL=jdbc:postgresql://${POSTGRES_CONTAINER}:5432/${POSTGRES_DB}" \
    -e "IDENTITY_BINDING_V2_POSTGRES_USERNAME=${POSTGRES_USER}" \
    -e "IDENTITY_BINDING_V2_POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" \
    -e "IDENTITY_BINDING_V2_FLYWAY_TARGET=${flyway_target}" \
    -v "${REPO_ROOT}:/workspace" \
    -v "${MAVEN_CACHE_DIR}:/tmp/skillhub-maven-home/.m2" \
    -w /workspace/server \
    eclipse-temurin:21-jdk-alpine \
      ./mvnw \
        -Dmaven.repo.local=/tmp/skillhub-maven-home/.m2/repository \
        -pl skillhub-app \
        -am \
        "-Dtest=${test_class}" \
        -Dsurefire.failIfNoSpecifiedTests=false \
        test
}

run_test IdentityBindingV2MigrationPostgresTest
run_test \
  "IdentityBindingV2PostgresIntegrationTest#upgradesMixedVersionWriteAndPreservesLegacyReadColumn+concurrentFirstLoginConvergesOnOneBinding" \
  45
run_test IdentityBindingV2ContractPostgresTest 46
run_test \
  "IdentityBindingV2PostgresIntegrationTest#concurrentFirstLoginConvergesAfterContractGate" \
  46
