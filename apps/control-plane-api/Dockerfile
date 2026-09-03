# Build with immutable, approved base-image digests, for example:
# docker build -f apps/control-plane-api/Dockerfile \
#   --build-arg BUILD_IMAGE=rust:<approved>@sha256:<digest> \
#   --build-arg RUNTIME_IMAGE=debian:<approved>@sha256:<digest> .
# Optional multi-process outbox backend:
#   --build-arg CARGO_FEATURES=postgres
#
# IMPORTANT: the build context is the REPOSITORY ROOT, not this directory.
# `build.rs` compiles `../../contracts/proto/apex/v1/control.proto`, which
# lives outside this crate, so a context rooted at `apps/control-plane-api`
# cannot see it and protoc fails with "Could not make proto path relative".
# Same reason apps/event-ingest/Dockerfile needs a root context.
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
# source manifest and the shared crates required by the control gateway
# without copying unrelated application trees or host build output.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/control-plane-api ./apps/control-plane-api
# The workspace still declares event-ingest as a member even though this
# application now depends on shared crates directly. Keep its source present
# so Cargo can load the complete workspace manifest.
COPY apps/event-ingest ./apps/event-ingest
COPY apps/agent-supervisor ./apps/agent-supervisor
COPY contracts ./contracts
# `--features postgres` forwards to `apex-event-ingest/postgres`, which
# compiles deploy/postgres/*.sql into the binary with include_str!. Without
# this the documented feature build fails outright:
#
#   error: couldn't read `src/outbox/../../../../deploy/postgres/outbox.sql`
#
# exactly as it did for event-ingest, and no image could ever be produced with
# the multi-process outbox backend.
COPY deploy/postgres ./deploy/postgres
WORKDIR /src/apps/control-plane-api
ARG CARGO_FEATURES=
RUN if [ -n "$CARGO_FEATURES" ]; then \
      cargo build --release --bin apex-control-plane-api --features "$CARGO_FEATURES"; \
    else \
      cargo build --release --bin apex-control-plane-api; \
    fi

FROM ${RUNTIME_IMAGE}
# A distinct uid from the ingest gateway's 10001, deliberately. ADR-0006
# requires this service to be independently authenticated from the ingest
# data path; sharing a runtime uid would make that boundary invisible at the
# OS layer -- one container's compromise would already hold the other's
# file-level identity on any shared mount or volume.
RUN useradd --system --uid 10002 --no-create-home apex-control
# Both directories MUST exist in the image, owned by the runtime uid.
#
# Docker initialises a fresh named volume from the image content at the mount
# point and copies that directory's ownership and mode with it. When the path
# does not exist in the image, Docker creates the volume root as `root:root
# 0755` instead, and this container -- which runs as uid 10002 -- cannot write
# to it. That is exactly the bug that made `FileOutbox::open` fail with EACCES
# and exit with INVALID_OUTBOX_CONFIGURATION on every fresh deployment of
# event-ingest, before its Dockerfile grew the same `install -d` step.
#
# `apex-control-secrets` is the staging target for the secrets-init step. The
# gateway refuses private key material whose mode has any group/other bit set,
# and Compose ignores `mode:` on file-based secrets (it bind-mounts the host
# file, so the host's mode wins). An init container owned by this same uid
# restages the material at 0600 before the gateway starts; the gateway's own
# check stays strict and still fails closed if that step did not happen.
RUN install -d -o 10002 -g 10002 -m 0700 /var/lib/apex-control /var/lib/apex-control-secrets
COPY --from=build /src/apps/control-plane-api/target/release/apex-control-plane-api /usr/local/bin/apex-control-plane-api
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/apex-control-plane-api"]
