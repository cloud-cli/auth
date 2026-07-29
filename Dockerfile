FROM ghcr.io/cloud-cli/node:latest as builder

USER 0
RUN pnpm i && pnpm build && rm -r node_modules/ src/

FROM ghcr.io/cloud-cli/node:latest

COPY --from=builder /home/app/ .