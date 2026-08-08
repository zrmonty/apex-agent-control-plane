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

image_keys=(APEX_INGEST_IMAGE APEX_CONTROL_IMAGE NATS_IMAGE CLICKHOUSE_IMAGE MINIO_IMAGE MINIO_MC_IMAGE CLICKHOUSE_API_IMAGE ARCHIVE_API_IMAGE)
for key in "${image_keys[@]}"; do
  value="$(require_value "$key")"
  [[ "$value" =~ @sha256:[0-9a-fA-F]{64}$ ]] || fail "${key} must be pinned by a 64-hex SHA-256 digest"
done

secret_keys=(
  GATEWAY_SERVER_CERT_FILE GATEWAY_SERVER_KEY_FILE GATEWAY_CLIENT_CA_FILE
  CONTROL_SERVER_CERT_FILE CONTROL_SERVER_KEY_FILE CONTROL_CLIENT_CA_FILE
  CONTROL_OPERATOR_TOKENS_FILE CONTROL_AGENT_TOKENS_FILE
  CONTROL_NATS_CLIENT_CERT_FILE CONTROL_NATS_CLIENT_KEY_FILE
  CONTROL_NATS_USERNAME_FILE CONTROL_NATS_PASSWORD_FILE
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
# Private material a service loads directly. Each service refuses any of these
# whose mode has a group or other bit set, and Compose cannot enforce that for
# us: `mode:` is ignored for file-based secrets outside Swarm, so the HOST
# file's mode and owner are what land in the container. Without this check the
# service simply exits at startup (INVALID_NATS_CONFIGURATION for the ingest
# gateway, a "permissions are too broad" startup error for the control
# gateway) and never binds a listener -- a failure that looks like a code
# fault and is really a file permission.
#
# The two services run as different uids on purpose (ADR-0006: the control
# channel is a separate trust boundary from the ingest data path, and that
# separation is enforced at the OS layer, not just in application code). A
# container cannot read a 0400 file owned by anyone else, so ownership is as
# load-bearing as the mode -- and a file chowned to the *other* service's uid
# is just as unreadable as one left owned by root.
#
# uid -> the private material that uid's container must be able to read.
gateway_uid=10001   # apps/event-ingest/Dockerfile
control_uid=10002   # apps/control-plane-api/Dockerfile
gateway_private_keys=(
  GATEWAY_SERVER_KEY_FILE INGEST_BEARER_TOKEN_FILE
  NATS_USERNAME_FILE NATS_PASSWORD_FILE INGEST_NATS_CLIENT_KEY_FILE
  INGEST_CLICKHOUSE_CLIENT_KEY_FILE INGEST_ARCHIVE_CLIENT_KEY_FILE
)
# The operator and agent token tables are bearer credentials, not merely
# config: both are held to the same owner-only policy as a private key. The
# agent table additionally decides which workload may retrieve which agent's
# pending commands, so a readable copy is a way to read another agent's stops.
control_private_keys=(
  CONTROL_SERVER_KEY_FILE CONTROL_OPERATOR_TOKENS_FILE CONTROL_AGENT_TOKENS_FILE
  CONTROL_NATS_CLIENT_KEY_FILE CONTROL_NATS_USERNAME_FILE CONTROL_NATS_PASSWORD_FILE
)

# Echoes the uid that must own this secret, or nothing if it is not private
# material.
private_key_uid() {
  local needle="$1" candidate
  for candidate in "${gateway_private_keys[@]}"; do
    [[ "$candidate" == "$needle" ]] && { printf '%s' "$gateway_uid"; return 0; }
  done
  for candidate in "${control_private_keys[@]}"; do
    [[ "$candidate" == "$needle" ]] && { printf '%s' "$control_uid"; return 0; }
  done
  return 0
}

for key in "${secret_keys[@]}"; do
  raw_path="$(require_value "$key")"
  if [[ "$raw_path" = /* ]]; then
    resolved="$raw_path"
  else
    resolved="${SCRIPT_DIR}/${raw_path}"
  fi
  [[ -f "$resolved" ]] || fail "secret file for ${key} does not exist"

  required_uid="$(private_key_uid "$key")"
  if [[ -n "$required_uid" ]]; then
    case "$(uname -s)" in
      Linux) mode="$(stat -c '%a' "$resolved")"; owner="$(stat -c '%u' "$resolved")" ;;
      Darwin) mode="$(stat -f '%Lp' "$resolved")"; owner="$(stat -f '%u' "$resolved")" ;;
      *) mode=""; owner="" ;;
    esac
    if [[ -n "$mode" ]]; then
      # Zero-pad so 400 and 0400 compare the same way.
      printf -v mode '%04d' "$((10#$mode))"
      if [[ "${mode: -2}" != "00" ]]; then
        fail "secret file for ${key} is mode ${mode}; this service refuses private material readable or writable by group or other. Run: chmod 0400 '${resolved}'"
      fi
      if [[ "$owner" != "$required_uid" ]]; then
        fail "secret file for ${key} is owned by uid ${owner}, but the container that reads it runs as uid ${required_uid} and could not open it. Run: chown ${required_uid} '${resolved}'"
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

# Same gate for the OOB control gateway's published port. Separate from the
# ingest one on purpose: acknowledging that ingest may be reached off-host is
# not the same decision as acknowledging it for the channel that can stop,
# pause, or inject into a running agent.
control_bind="$(env_value APEX_CONTROL_BIND)"
control_bind="${control_bind:-127.0.0.1}"
allow_nonlocal_control="$(env_value APEX_ALLOW_NONLOCAL_CONTROL_BIND)"
if [[ "$control_bind" != 127.0.0.1 && "$control_bind" != ::1 && "$control_bind" != localhost && "$allow_nonlocal_control" != true ]]; then
  fail 'APEX_CONTROL_BIND is non-local; set APEX_ALLOW_NONLOCAL_CONTROL_BIND=true only with an approved network policy and operator client certificates issued'
fi
if [[ "$allow_nonlocal_control" == true && ( "$control_bind" == 0.0.0.0 || "$control_bind" == :: ) ]]; then
  printf 'Compose preflight warning: the out-of-band control channel is exposed on every interface; verify firewalling and operator certificate issuance before continuing.\n' >&2
fi

command -v docker >/dev/null 2>&1 || fail 'Docker CLI is not installed'
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 || fail 'Docker daemon is unavailable; start Docker Desktop or the configured daemon'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet || fail 'rendered Compose configuration is invalid'

case "$(uname -s)" in
  Linux|Darwin) printf 'Compose preflight passed on %s; no secret values were printed.\n' "$(uname -s)" ;;
  *) fail 'unsupported host; use Linux or macOS' ;;
esac
