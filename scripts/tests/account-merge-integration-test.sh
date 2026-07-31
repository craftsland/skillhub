#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="skillhub-account-merge-$$"
POSTGRES_CONTAINER="${RUN_ID}-postgres"
REDIS_CONTAINER="${RUN_ID}-redis"
NETWORK="${RUN_ID}-network"
POSTGRES_USER="account_merge"
POSTGRES_PASSWORD="account-merge-test-password"
POSTGRES_DB="account_merge"
MAVEN_CACHE_DIR="${MAVEN_CACHE_DIR:-${HOME}/.m2}"
TEST_CLASSES="AccountMergeIntentMigrationPostgresTest,\
AccountMergePostgresIntegrationTest,\
AccountMergeSessionRevocationRepositoryPostgresTest,\
AccountMergeSessionRedisIntegrationTest"

log() {
  printf '[account-merge] %s\n' "$*"
}

cleanup() {
  exit_code="$?"
  if [[ "${exit_code}" -ne 0 ]]; then
    log "failed with exit code ${exit_code}"
    docker ps -a \
      --filter "label=skillhub.test.run=${RUN_ID}" \
      --format 'resource={{.Names}} status={{.Status}}' || true
    docker logs "${POSTGRES_CONTAINER}" 2>&1 || true
    docker logs "${REDIS_CONTAINER}" 2>&1 || true
  fi
  docker rm -f \
    "${POSTGRES_CONTAINER}" \
    "${REDIS_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "creating isolated Docker network ${NETWORK}"
docker network create \
  --label "skillhub.test.run=${RUN_ID}" \
  "${NETWORK}" >/dev/null

log "starting isolated PostgreSQL and Redis"
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
docker run -d \
  --name "${REDIS_CONTAINER}" \
  --label "skillhub.test.run=${RUN_ID}" \
  --network "${NETWORK}" \
  --memory=256m \
  --cpus=0.5 \
  -p 127.0.0.1::6379 \
  redis:7-alpine >/dev/null

log "waiting for PostgreSQL and Redis readiness"
postgres_ready="false"
redis_ready="false"
for _ in $(seq 1 60); do
  if [[ "${postgres_ready}" != "true" ]] \
    && [[ "$(docker exec "${POSTGRES_CONTAINER}" \
      cat /proc/1/comm 2>/dev/null || true)" == "postgres" ]] \
    && docker exec "${POSTGRES_CONTAINER}" \
      pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
      >/dev/null 2>&1; then
    postgres_ready="true"
  fi
  if [[ "${redis_ready}" != "true" ]] \
    && [[ "$(docker exec "${REDIS_CONTAINER}" \
      cat /proc/1/comm 2>/dev/null || true)" == "redis-server" ]] \
    && docker exec "${REDIS_CONTAINER}" redis-cli ping \
      2>/dev/null | grep -Fxq PONG; then
    redis_ready="true"
  fi
  if [[ "${postgres_ready}" == "true" \
    && "${redis_ready}" == "true" ]]; then
    break
  fi
  sleep 1
done
if [[ "${postgres_ready}" != "true" \
  || "${redis_ready}" != "true" ]]; then
  log "dependencies did not become ready"
  exit 1
fi

run_tests() {
  java_version=""
  if command -v java >/dev/null 2>&1; then
    java_version="$(java -version 2>&1)"
  fi
  if [[ "${java_version}" == *'"21.'* ]]; then
    postgres_port="$(docker port "${POSTGRES_CONTAINER}" 5432/tcp \
      | sed -n 's/.*://p')"
    redis_port="$(docker port "${REDIS_CONTAINER}" 6379/tcp \
      | sed -n 's/.*://p')"
    if [[ -z "${postgres_port}" || -z "${redis_port}" ]]; then
      log "Docker did not publish required loopback ports"
      return 1
    fi
    log "running integration tests with host Java 21"
    (
      cd "${REPO_ROOT}/server"
      IDENTITY_BINDING_V2_POSTGRES_URL="jdbc:postgresql://127.0.0.1:${postgres_port}/${POSTGRES_DB}" \
      IDENTITY_BINDING_V2_POSTGRES_USERNAME="${POSTGRES_USER}" \
      IDENTITY_BINDING_V2_POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
      REDIS_TEST_HOST="127.0.0.1" \
      REDIS_TEST_PORT="${redis_port}" \
      MAVEN_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m" \
        ./mvnw \
          -pl skillhub-app \
          -am \
          "-Dtest=${TEST_CLASSES}" \
          -Dsurefire.failIfNoSpecifiedTests=false \
          test
    )
    return
  fi

  log "running integration tests with containerized Java 21"
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
    -e "REDIS_TEST_HOST=${REDIS_CONTAINER}" \
    -e REDIS_TEST_PORT=6379 \
    -v "${REPO_ROOT}:/workspace" \
    -v "${MAVEN_CACHE_DIR}:/tmp/skillhub-maven-home/.m2" \
    -w /workspace/server \
    eclipse-temurin:21-jdk-alpine \
      ./mvnw \
        -Dmaven.repo.local=/tmp/skillhub-maven-home/.m2/repository \
        -pl skillhub-app \
        -am \
        "-Dtest=${TEST_CLASSES}" \
        -Dsurefire.failIfNoSpecifiedTests=false \
        test
}

run_tests
log "account merge PostgreSQL and Redis integration tests passed"
