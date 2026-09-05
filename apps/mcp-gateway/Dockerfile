FROM node:24.16.0-bookworm-slim@sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203 AS dependencies

RUN corepack enable && corepack prepare pnpm@10.34.5 --activate
WORKDIR /app/apps/mcp-gateway
COPY packages/apex-contracts-ts/package.json /app/packages/apex-contracts-ts/package.json
COPY packages/apex-contracts-ts/src /app/packages/apex-contracts-ts/src
COPY apps/mcp-gateway/package.json apps/mcp-gateway/pnpm-lock.yaml ./

FROM dependencies AS build
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY apps/mcp-gateway/tsconfig.json apps/mcp-gateway/tsconfig.build.json ./
COPY apps/mcp-gateway/src ./src
RUN pnpm build

FROM dependencies AS production-dependencies
RUN pnpm install --frozen-lockfile --prod --ignore-scripts

FROM node:24.16.0-bookworm-slim@sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203

ENV NODE_ENV=production
ENV HOME=/tmp/apex
WORKDIR /app/apps/mcp-gateway

COPY --from=production-dependencies /app/apps/mcp-gateway/package.json ./
COPY --from=production-dependencies /app/apps/mcp-gateway/node_modules ./node_modules
COPY --from=build /app/apps/mcp-gateway/dist ./dist
# Preserve the source-tree relative contract path used by the live gRPC client.
COPY contracts/proto /app/contracts/proto
RUN mkdir -p /tmp/apex && chown 10001:10001 /tmp/apex

USER 10001:10001
ENTRYPOINT ["node", "dist/index.js"]
