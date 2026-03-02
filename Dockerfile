FROM --platform=$BUILDPLATFORM node:18.19.0 AS FRONT
WORKDIR /web

# Copy only dependency files first for better caching
COPY ./web/package.json ./web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile

# Copy source files and build
COPY ./web .
RUN NODE_OPTIONS="--max-old-space-size=4096" pnpm run build

FROM --platform=$BUILDPLATFORM golang:1.24.9 AS BACK
WORKDIR /go/src/hanzo-iam

# Copy only go.mod and go.sum first for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY . .

RUN go test -v -run TestGetVersionInfo ./util/system_test.go ./util/system.go ./util/variable.go
RUN ./build.sh

FROM alpine:latest AS STANDARD
LABEL MAINTAINER="https://hanzo.ai/"
ARG USER=hanzo
ARG TARGETOS
ARG TARGETARCH
ENV BUILDX_ARCH="${TARGETOS:-linux}_${TARGETARCH:-amd64}"

RUN sed -i 's/https/http/' /etc/apk/repositories
RUN apk add --update sudo
RUN apk add tzdata
RUN apk add curl
RUN apk add ca-certificates && update-ca-certificates

RUN adduser -D $USER -u 1000 \
    && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
    && chmod 0440 /etc/sudoers.d/$USER \
    && mkdir logs \
    && chown -R $USER:$USER logs

USER 1000
WORKDIR /
COPY --from=BACK --chown=$USER:$USER /go/src/hanzo-iam/server_${BUILDX_ARCH} ./server
COPY --from=BACK --chown=$USER:$USER /go/src/hanzo-iam/swagger ./swagger
COPY --from=BACK --chown=$USER:$USER /go/src/hanzo-iam/conf/app.prod.conf ./conf/app.conf
COPY --from=BACK --chown=$USER:$USER /go/src/hanzo-iam/init_data.json ./init_data.json
COPY --from=FRONT --chown=$USER:$USER /web/build ./web/build

ENTRYPOINT ["/server"]


FROM debian:latest AS ALLINONE
LABEL MAINTAINER="https://hanzo.ai/"
ARG TARGETOS
ARG TARGETARCH
ENV BUILDX_ARCH="${TARGETOS:-linux}_${TARGETARCH:-amd64}"

RUN apt update
RUN apt install -y ca-certificates lsof && update-ca-certificates

WORKDIR /
COPY --from=BACK /go/src/hanzo-iam/server_${BUILDX_ARCH} ./server
COPY --from=BACK /go/src/hanzo-iam/swagger ./swagger
COPY --from=BACK /go/src/hanzo-iam/docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=BACK /go/src/hanzo-iam/conf/app.prod.conf ./conf/app.conf
COPY --from=FRONT /web/build ./web/build

ENTRYPOINT ["/bin/bash"]
CMD ["/docker-entrypoint.sh"]
