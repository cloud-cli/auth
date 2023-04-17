FROM ghcr.io/cloud-cli/node:latest
ADD . /home/app
RUN npm run ci