FROM alpine:3.13

RUN apk add --no-cache bash git make build-base

COPY . /breakpad/
WORKDIR /breakpad/

CMD ./generate-so.sh
