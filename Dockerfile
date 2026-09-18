FROM ghcr.io/cloud-cli/image-node:latest AS builder

USER 0
COPY . .
ARG BUILD_TEST_ROUTES=false
RUN BUILD_TEST_ROUTES=$BUILD_TEST_ROUTES pnpm install --frozen-lockfile && BUILD_TEST_ROUTES=$BUILD_TEST_ROUTES pnpm build && pnpm prune --prod && rm -r src/ db/

FROM ghcr.io/cloud-cli/image-node:latest

COPY --from=builder /home/app/ .
