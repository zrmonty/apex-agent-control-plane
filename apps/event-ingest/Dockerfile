# Build with immutable, approved base-image digests, for example:
# docker build -f apps/event-ingest/Dockerfile \
#   --build-arg BUILD_IMAGE=rust:<approved>@sha256:<digest> \
#   --build-arg RUNTIME_IMAGE=debian:<approved>@sha256:<digest> .
# Optional Valkey acceleration:
#   --build-arg CARGO_FEATURES=valkey
#
# IMPORTANT: the build context is the REPOSITORY ROOT, not this directory.
# `build.rs` compiles `../../contracts/proto/apex/v1/event.proto`, which lives
# outside this crate, so a context rooted at `apps/event-ingest` cannot see it
# and protoc fails with "Could not make proto path relative".
#
# Both base-image args must be declared in the *global* scope, before the first
# FROM. An ARG declared after a FROM belongs to that build stage, and a later
# FROM cannot read a stage-scoped ARG -- it expands to the empty string and the
# build dies with "base name should not be blank".
ARG BUILD_IMAGE
ARG RUNTIME_IMAGE
FROM ${BUILD_IMAGE} AS build
WORKDIR /src
# Copy only what the crate needs, so the image does not carry the whole repo
# and a host `target/` directory cannot leak into the container build.
COPY apps/event-ingest ./apps/event-ingest
COPY contracts ./contracts
WORKDIR /src/apps/event-ingest
ARG CARGO_FEATURES=
RUN if [ -n "$CARGO_FEATURES" ]; then \
      cargo build --release --bin apex-event-ingest --features "$CARGO_FEATURES"; \
    else \
      cargo build --release --bin apex-event-ingest; \
    fi

FROM ${RUNTIME_IMAGE}
RUN useradd --system --uid 10001 --no-create-home apex
COPY --from=build /src/apps/event-ingest/target/release/apex-event-ingest /usr/local/bin/apex-event-ingest
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/apex-event-ingest"]
