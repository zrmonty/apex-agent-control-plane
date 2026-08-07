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
# Private material the ingest gateway loads directly. It refuses any of these
# whose mode has a group or other bit set, and Compose cannot enforce that for
# us: `mode:` is ignored for file-based secrets outside Swarm, so the HOST
# file's mode and owner are what land in the container. Without this check the
# gateway simply exits at startup with INVALID_NATS_CONFIGURATION and never
# binds a listener -- a failure that looks like a code fault and is really a
# file permission.
gateway_private_keys=(
  GATEWAY_SERVER_KEY_FILE INGEST_BEARER_TOKEN_FILE
  NATS_USERNAME_FILE NATS_PASSWORD_FILE INGEST_NATS_CLIENT_KEY_FILE
  INGEST_CLICKHOUSE_CLIENT_KEY_FILE INGEST_ARCHIVE_CLIENT_KEY_FILE
)
# The uid apps/event-ingest/Dockerfile runs as. The container cannot read a
# 0400 file owned by anyone else, so ownership is as load-bearing as the mode.
gateway_uid=10001

is_gateway_private_key() {
  local needle="$1" candidate
  for candidate in "${gateway_private_keys[@]}"; do
    [[ "$candidate" == "$needle" ]] && return 0
  done
  return 1
}

for key in "${secret_keys[@]}"; do
  raw_path="$(require_value "$key")"
  if [[ "$raw_path" = /* ]]; then
    resolved="$raw_path"
  else
    resolved="${SCRIPT_DIR}/${raw_path}"
  fi
  [[ -f "$resolved" ]] || fail "secret file for ${key} does not exist"

  if is_gateway_private_key "$key"; then
    case "$(uname -s)" in
      Linux) mode="$(stat -c '%a' "$resolved")"; owner="$(stat -c '%u' "$resolved")" ;;
      Darwin) mode="$(stat -f '%Lp' "$resolved")"; owner="$(stat -f '%u' "$resolved")" ;;
      *) mode=""; owner="" ;;
    esac
    if [[ -n "$mode" ]]; then
      # Zero-pad so 400 and 0400 compare the same way.
      printf -v mode '%04d' "$((10#$mode))"
      if [[ "${mode: -2}" != "00" ]]; then
        fail "secret file for ${key} is mode ${mode}; the ingest gateway refuses private material readable or writable by group or other. Run: chmod 0400 '${resolved}'"
      fi
      if [[ "$owner" != "$gateway_uid" ]]; then
        fail "secret file for ${key} is owned by uid ${owner}, but the ingest gateway container runs as uid ${gateway_uid} and could not read it. Run: chown ${gateway_uid} '${resolved}'"
      fi
    fi
  fi
done

agent_id="$(require_value APEX_BEARER_AGENT_ID)"
[[ "$agent_id" =~ ^[A-Za-z0-9._:-]{1,256}$ && "$agent_id" != *..* ]] || fail 'APEX_BEARER_AGENT_ID must be a safe 1-256 character workload identifier'
bearer_cert_sha256="$(require_value APEX_BEARER_CERT_SHA256)"
[[ "$bearer_cert_sha256" =~ ^[A-Fa-f0-9]{64}$ ]] || fail 'APEX_BEARER_CERT_SHA256 must be exactly 64 hexadecimal characters'
provider_cert_sha256="$(require_value APEX_PROVIDER_CLIENT_CERT_SHA256)"
[[ "$provider_cert_sha256" =~ ^[A-Fa-f0-9]{64}$ ]] || fail 'APEX_PROVIDER_CLIENT_CERT_SHA256 must be exactly 64 hexadecimal characters'

object_lock="$(require_value APEX_ARCHIVE_REQUIRE_OBJECT_LOCK)"
[[ "$object_lock" == true || "$object_lock" == false ]] || fail 'APEX_ARCHIVE_REQUIRE_OBJECT_LOCK must be explicitly true or false'
bucket="$(require_value APEX_ARCHIVE_BUCKET)"
[[ "$bucket" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || fail 'APEX_ARCHIVE_BUCKET must be lowercase DNS-safe text'

bind="$(env_value APEX_INGEST_BIND)"
bind="${bind:-127.0.0.1}"
allow_nonlocal="$(env_value APEX_ALLOW_NONLOCAL_INGEST_BIND)"
if [[ "$bind" != 127.0.0.1 && "$bind" != ::1 && "$bind" != localhost && "$allow_nonlocal" != true ]]; then
  fail 'APEX_INGEST_BIND is non-local; set APEX_ALLOW_NONLOCAL_INGEST_BIND=true only with an approved network policy and client-certificate boundary'
fi
if [[ "$allow_nonlocal" == true && ( "$bind" == 0.0.0.0 || "$bind" == :: ) ]]; then
  printf 'Compose preflight warning: ingest is exposed on every interface; verify firewalling and mTLS before continuing.\n' >&2
fi

command -v docker >/dev/null 2>&1 || fail 'Docker CLI is not installed'
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 || fail 'Docker daemon is unavailable; start Docker Desktop or the configured daemon'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet || fail 'rendered Compose configuration is invalid'

case "$(uname -s)" in
  Linux|Darwin) printf 'Compose preflight passed on %s; no secret values were printed.\n' "$(uname -s)" ;;
  *) fail 'unsupported host; use Linux or macOS' ;;
esac
