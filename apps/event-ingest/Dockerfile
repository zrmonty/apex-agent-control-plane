# Build with immutable, approved base-image digests, for example:
# docker build --build-arg BUILD_IMAGE=rust:<approved>@sha256:<digest> \
#   --build-arg RUNTIME_IMAGE=debian:<approved>@sha256:<digest> .
ARG BUILD_IMAGE
FROM ${BUILD_IMAGE} AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin apex-event-ingest

ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
RUN useradd --system --uid 10001 --no-create-home apex
COPY --from=build /src/target/release/apex-event-ingest /usr/local/bin/apex-event-ingest
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/apex-event-ingest"]
