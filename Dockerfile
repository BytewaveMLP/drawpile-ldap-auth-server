FROM node:12.16.3-alpine AS builder
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
ADD . .
RUN yarn build

FROM node:12.16.3-alpine
WORKDIR /usr/src/app
COPY package.json yarn.lock ./
RUN yarn install --production --frozen-lockfile && yarn cache clean
COPY --from=builder dist/ ./dist/
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /usr/local/bin/tini
RUN chmod +rx /usr/local/bin/tini
ENTRYPOINT ["/usr/local/bin/tini", "-v", "--"]
USER node
ENV NODE_ENV=production
EXPOSE 8081
CMD [ "node", "." ]
