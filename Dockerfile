FROM ghcr.io/cloud-cli/node:latest AS builder

USER 0
COPY . .
RUN pnpm i && pnpm build && rm -r node_modules/ src/

FROM ghcr.io/cloud-cli/node:latest

COPY --from=builder /home/app/ .
RUN pnpm i --prod