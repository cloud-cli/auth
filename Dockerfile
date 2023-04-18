FROM ghcr.io/cloud-cli/node:latest
COPY . /home/app
USER root
RUN chown -R node:node /home/app
USER node
RUN npm run ci && rm -r src
RUN ls -al /home/app