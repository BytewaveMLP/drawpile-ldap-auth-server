FROM node:12.16.3-alpine

WORKDIR /usr/src/app

COPY package.json yarn.lock ./
RUN yarn install

ADD . .
RUN yarn build

CMD [ "node", "." ]
EXPOSE 8081
