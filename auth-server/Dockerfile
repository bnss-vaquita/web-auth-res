FROM node:8-slim

ENV HTTPS_PORT=443 HTTP_PORT=80 IP=192.168.5.15 AUTH_SERVER_USR_PASSWORD=H4PsQOdjYS3dBsNbT3TFsZU
WORKDIR /usr/app
COPY package.json ./
COPY yarn.lock ./
COPY src ./src
COPY keys ./keys
RUN yarn 
CMD ["yarn", "run", "server"]

EXPOSE 443

