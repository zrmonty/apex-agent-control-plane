#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ENV_FILE="${SCRIPT_DIR}/.env"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"

fail() {
  printf 'Compose preflight: %s\n' "$1" >&2
  exit 1
}

[[ -f "$ENV_FILE" ]] || fail "missing ${ENV_FILE}; copy .env.example to .env and replace placeholders"
[[ -f "$COMPOSE_FILE" ]] || fail "missing compose.yaml"

# Read simple KEY=VALUE entries without sourcing the file. This prevents
# command substitution, exports, and shell code in a developer-provided .env.
env_value() {
  local key="$1"
  awk -v key="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    index($0, "=") == 0 { next }
    { candidate=$0; sub(/=.*/, "", candidate); gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate); if (candidate == key) { value=$0; sub(/^[^=]*=/, "", value); sub(/\r$/, "", value); print value; exit } }
  ' "$ENV_FILE"
}

require_value() {
  local key="$1" value
  value="$(env_value "$key")"
  [[ -n "$value" && "$value" != *REPLACE_WITH* ]] || fail "${key} is missing or still contains a placeholder"
  printf '%s' "$value"
}

image_keys=(APEX_INGEST_IMAGE NATS_IMAGE CLICKHOUSE_IMAGE MINIO_IMAGE MINIO_MC_IMAGE CLICKHOUSE_API_IMAGE ARCHIVE_API_IMAGE)
for key in "${image_keys[@]}"; do
  value="$(require_value "$key")"
  [[ "$value" =~ @sha256:[0-9a-fA-F]{64}$ ]] || fail "${key} must be pinned by a 64-hex SHA-256 digest"
done

secret_keys=(
  GATEWAY_SERVER_CERT_FILE GATEWAY_SERVER_KEY_FILE GATEWAY_CLIENT_CA_FILE
  INGEST_BEARER_TOKEN_FILE NATS_USERNAME_FILE NATS_PASSWORD_FILE
  INGEST_NATS_CLIENT_CERT_FILE INGEST_NATS_CLIENT_KEY_FILE
  INGEST_CLICKHOUSE_CLIENT_CERT_FILE INGEST_CLICKHOUSE_CLIENT_KEY_FILE
  ARCHIVE_CLIENT_CA_FILE INGEST_ARCHIVE_CLIENT_CERT_FILE INGEST_ARCHIVE_CLIENT_KEY_FILE
  NATS_CONFIG_FILE CLICKHOUSE_USERS_CONFIG_FILE CLICKHOUSE_TLS_CONFIG_FILE
  CLICKHOUSE_SERVER_CERT_FILE CLICKHOUSE_SERVER_KEY_FILE CLICKHOUSE_CLIENT_CA_FILE
  MINIO_ROOT_USER_FILE MINIO_ROOT_PASSWORD_FILE MINIO_SERVER_CERT_FILE
  MINIO_SERVER_KEY_FILE MINIO_SERVER_CA_FILE NATS_SERVER_CERT_FILE NATS_SERVER_KEY_FILE
  CLICKHOUSE_API_SERVER_CERT_FILE CLICKHOUSE_API_SERVER_KEY_FILE CLICKHOUSE_API_CLIENT_CA_FILE
  CLICKHOUSE_WRITER_CERT_FILE CLICKHOUSE_WRITER_KEY_FILE
  ARCHIVE_API_SERVER_CERT_FILE ARCHIVE_API_SERVER_KEY_FILE ARCHIVE_API_CLIENT_CA_FILE
  ARCHIVE_WRITER_CERT_FILE ARCHIVE_WRITER_KEY_FILE
  ARCHIVE_BACKEND_ACCESS_KEY_FILE ARCHIVE_BACKEND_SECRET_KEY_FILE
)
for key in "${secret_keys[@]}"; do
  raw_path="$(require_value "$key")"
  if [[ "$raw_path" = /* ]]; then
    resolved="$raw_path"
  else
    resolved="${SCRIPT_DIR}/${raw_path}"
  fi
  [[ -f "$resolved" ]] || fail "secret file for ${key} does not exist"
done

object_lock="$(require_value APEX_ARCHIVE_REQUIRE_OBJECT_LOCK)"
[[ "$object_lock" == true || "$object_lock" == false ]] || fail 'APEX_ARCHIVE_REQUIRE_OBJECT_LOCK must be explicitly true or false'
bucket="$(require_value APEX_ARCHIVE_BUCKET)"
[[ "$bucket" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || fail 'APEX_ARCHIVE_BUCKET must be lowercase DNS-safe text'

command -v docker >/dev/null 2>&1 || fail 'Docker CLI is not installed'
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 || fail 'Docker daemon is unavailable; start Docker Desktop or the configured daemon'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet || fail 'rendered Compose configuration is invalid'

case "$(uname -s)" in
  Linux|Darwin) printf 'Compose preflight passed on %s; no secret values were printed.\n' "$(uname -s)" ;;
  *) fail 'unsupported host; use Linux or macOS' ;;
esac
