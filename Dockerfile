FROM ghcr.io/cloud-cli/image-node:latest AS builder

USER 0
COPY . .
RUN pnpm install --frozen-lockfile && pnpm build && pnpm prune --prod && rm -r src/

FROM ghcr.io/cloud-cli/image-node:latest

COPY --from=builder /home/app/ .
