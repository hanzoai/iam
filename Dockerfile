# syntax=docker/dockerfile:1
# ── Frontend build ─────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM node:18.19.0 AS front
WORKDIR /web

COPY ./web/package.json ./web/pnpm-lock.yaml ./web/.npmrc ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY ./web .
RUN NODE_OPTIONS="--max-old-space-size=4096" pnpm run build

# ── Go build (native per-arch, cached) ─────────────────────────
FROM golang:1.24.9 AS back
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /go/src/hanzo-iam

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy only Go source (web/, docs/, .github/ excluded by .dockerignore)
COPY . .

# Single-arch native build with persistent build cache
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-w -s" -o server .

# ── Production image ──────────────────────────────────────────
FROM alpine:3.21 AS standard
LABEL maintainer="https://hanzo.ai/"
ARG USER=hanzo

RUN apk add --no-cache sudo tzdata curl ca-certificates \
    && update-ca-certificates \
    && adduser -D $USER -u 1000 \
    && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
    && chmod 0440 /etc/sudoers.d/$USER \
    && mkdir logs \
    && chown -R $USER:$USER logs

USER 1000
WORKDIR /
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/server ./server
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/swagger ./swagger
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/conf/app.prod.conf ./conf/app.conf
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/init_data.json ./init_data.json
COPY --from=front --chown=$USER:$USER /web/build ./web/build

ENTRYPOINT ["/server"]

# ── All-in-one (dev/debug) ────────────────────────────────────
FROM debian:bookworm-slim AS allinone
LABEL maintainer="https://hanzo.ai/"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates lsof \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=back /go/src/hanzo-iam/server ./server
COPY --from=back /go/src/hanzo-iam/swagger ./swagger
COPY --from=back /go/src/hanzo-iam/docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=back /go/src/hanzo-iam/conf/app.prod.conf ./conf/app.conf
COPY --from=front /web/build ./web/build

ENTRYPOINT ["/bin/bash"]
CMD ["/docker-entrypoint.sh"]
