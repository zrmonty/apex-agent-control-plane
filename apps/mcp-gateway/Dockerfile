FROM node:24.16.0-bookworm-slim AS build

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --ignore-scripts
COPY tsconfig.json README.md ./
COPY src ./src
RUN pnpm build

FROM node:24.16.0-bookworm-slim

ENV NODE_ENV=production
ENV HOME=/tmp/apex
WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --prod --ignore-scripts \
    && mkdir -p /tmp/apex \
    && chown -R 10001:10001 /app /tmp/apex
COPY --from=build --chown=10001:10001 /app/dist ./dist

USER 10001:10001
ENTRYPOINT ["node", "dist/index.js"]
