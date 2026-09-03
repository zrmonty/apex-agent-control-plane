# Build with immutable, approved base-image digests, for example:
# docker build -f apps/event-ingest/Dockerfile \
#   --build-arg BUILD_IMAGE=rust:<approved>@sha256:<digest> \
#   --build-arg RUNTIME_IMAGE=debian:<approved>@sha256:<digest> .
# Optional Valkey acceleration:
#   --build-arg CARGO_FEATURES=valkey
#
# IMPORTANT: the build context is the REPOSITORY ROOT, not this directory.
# The shared `apex-contract` build.rs compiles
# `../../contracts/proto/apex/v1/event.proto`, which lives outside that crate,
# so a context rooted at `apps/event-ingest` cannot see it and protoc fails
# with "Could not make proto path relative".
#
# Both base-image args must be declared in the *global* scope, before the first
# FROM. An ARG declared after a FROM belongs to that build stage, and a later
# FROM cannot read a stage-scoped ARG -- it expands to the empty string and the
# build dies with "base name should not be blank".
ARG BUILD_IMAGE
ARG RUNTIME_IMAGE
FROM ${BUILD_IMAGE} AS build
WORKDIR /src
# The Rust workspace manifest must be present because Cargo resolves this
# package through the repository workspace. Copy every workspace member's
# source manifest and the shared crates required by the gateway without
# copying unrelated application trees or host build output.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/event-ingest ./apps/event-ingest
COPY apps/control-plane-api ./apps/control-plane-api
COPY apps/agent-supervisor ./apps/agent-supervisor
COPY contracts ./contracts
# `--features postgres` compiles deploy/postgres/*.sql into the binary with
# include_str!. Without this the documented feature build fails outright:
#
#   error: couldn't read `src/outbox/../../../../deploy/postgres/outbox.sql`
#
# which meant no image could ever be produced with the Postgres backends --
# the multi-process outbox and idempotency authority that compose.yaml's
# production profile is built around.
COPY deploy/postgres ./deploy/postgres
WORKDIR /src/apps/event-ingest
ARG CARGO_FEATURES=
RUN if [ -n "$CARGO_FEATURES" ]; then \
      cargo build --release --bin apex-event-ingest --features "$CARGO_FEATURES"; \
    else \
      cargo build --release --bin apex-event-ingest; \
    fi

FROM ${RUNTIME_IMAGE}
RUN useradd --system --uid 10001 --no-create-home apex
# Both directories MUST exist in the image, owned by the runtime uid.
#
# Docker initialises a fresh named volume from the image content at the mount
# point and copies that directory's ownership and mode with it. When the path
# does not exist in the image, Docker creates the volume root as `root:root
# 0755` instead, and this container -- which runs as uid 10001 -- cannot write
# to it. That made `FileOutbox::open` fail with EACCES and the process exit
# with INVALID_OUTBOX_CONFIGURATION on every fresh deployment of both
# deploy/compose/compose.yaml and deploy/compose/compose.gateway-ref.yaml.
#
# `apex-secrets` is the staging target for the secrets-init step. The gateway
# refuses private key material whose mode has any group/other bit set, and
# Compose ignores `mode:` on file-based secrets (it bind-mounts the host file,
# so the host's mode wins). An init container owned by this same uid restages
# the material at 0600 before the gateway starts; the gateway's own check
# stays strict and still fails closed if that step did not happen.
RUN install -d -o 10001 -g 10001 -m 0700 /var/lib/apex /var/lib/apex-secrets
COPY --from=build /src/apps/event-ingest/target/release/apex-event-ingest /usr/local/bin/apex-event-ingest
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/apex-event-ingest"]
