FROM node:12.16.3-alpine AS builder
COPY package.json yarn.lock ./
RUN yarn install
ADD . .
RUN yarn build

FROM node:12.16.3-alpine
WORKDIR /usr/src/app
COPY --from=builder dist/ ./dist/
COPY package.json yarn.lock ./
RUN yarn install --production
ENV NODE_ENV=production
EXPOSE 8081
CMD [ "node", "." ]
