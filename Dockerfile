FROM ghcr.io/cloud-cli/node:latest
COPY . /home/app
RUN npm run ci && rm -r src