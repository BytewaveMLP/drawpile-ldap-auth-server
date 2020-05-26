FROM node:12.16.3-alpine AS builder
COPY package.json yarn.lock ./
RUN yarn install
ADD . .
RUN yarn build

FROM node:12.16.3-alpine
WORKDIR /usr/src/app
COPY package.json yarn.lock ./
RUN yarn install --production
COPY --from=builder dist/ ./dist/
ENV NODE_ENV=production
EXPOSE 8081
CMD [ "node", "." ]
