# ── Frontend build ─────────────────────────────────────────────
# Base images pulled from Docker Hub directly. The previous
# `mirror.gcr.io/library/*` references are dropped — we don't use any
# gcr.io path inside the Hanzo/Lux/Zoo ecosystems. DockerHub library/*
# is public and works without auth for these well-known upstreams; if
# the unauth pull cap becomes an issue, swap to public.ecr.aws/docker/library
# instead, never gcr.io.
FROM --platform=$BUILDPLATFORM docker.io/library/node:18.19.0 AS front
WORKDIR /web
ARG VITE_DEFAULT_APP=app-built-in

COPY ./web/package.json ./web/pnpm-lock.yaml ./web/pnpm-workspace.yaml ./web/.npmrc ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY ./web .
ENV VITE_DEFAULT_APP=$VITE_DEFAULT_APP
RUN NODE_OPTIONS="--max-old-space-size=4096" pnpm run build

# ── Go build ──────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine AS back
ARG TARGETOS TARGETARCH
# CGO + SQLCipher toolchain for the hanzoai/sqlite embedded driver (mattn-based).
# Built CGO-native per-arch on the native build runners (no cross-compile), musl
# throughout so the binary runs on the alpine runtime below.
RUN apk add --no-cache git gcc musl-dev sqlcipher-dev pkgconfig
WORKDIR /go/src/hanzo-iam

COPY go.mod go.sum ./
# Private Go modules (github.com/luxfi/*, github.com/hanzoai/*) need git auth.
# CI passes a buildkit secret; mark those prefixes private (so go fetches via
# git, not the public proxy/sumdb that can't see them) and configure git to
# present the token for github.com. The token rides a --mount secret, so it
# never lands in an image layer. No token → public-only build still works.
#
# Secret name: the canonical hanzoai/.github docker-build.yml reusable provides
# it as `gh_token`; the in-cluster Kaniko path uses `GIT_AUTH_TOKEN`. Accept
# either so BOTH build paths authenticate (this is what makes the GHA pipeline
# build — the old id=GIT_AUTH_TOKEN-only mount silently got nothing from the
# reusable and the private fetch failed).
ARG GOPRIVATE=github.com/luxfi/*,github.com/hanzoai/*
ENV GOPRIVATE=${GOPRIVATE}
RUN --mount=type=secret,id=gh_token --mount=type=secret,id=GIT_AUTH_TOKEN \
    sh -c 'set -e; \
      TOK=""; \
      if [ -s /run/secrets/gh_token ]; then TOK="$(cat /run/secrets/gh_token)"; \
      elif [ -s /run/secrets/GIT_AUTH_TOKEN ]; then TOK="$(cat /run/secrets/GIT_AUTH_TOKEN)"; fi; \
      if [ -n "$TOK" ]; then \
        export GIT_CONFIG_GLOBAL=/tmp/gitconfig; \
        git config --global url."https://x-access-token:${TOK}@github.com/".insteadOf "https://github.com/"; \
      fi; \
      go mod download; \
      rm -f /tmp/gitconfig'

COPY . .
# Per SCALE_STANDARD.md §2 — GOEXPERIMENT=jsonv2 in every production Go
# build. IAM emits JSON at the OAuth/OIDC endpoints (login flow,
# userinfo, JWKS); jsonv2 lands -12% time / -23% allocs on the edge.
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}
# -mod=mod lets the build resolve a module graph that needs a go.mod update
# (Go's default -mod=readonly hard-fails with "updates to go.mod needed"). The
# build can fetch a require not pre-downloaded, so re-present the private-module
# git auth here too — same tmp GIT_CONFIG_GLOBAL that never persists to a layer.
ENV GOFLAGS=-mod=mod
RUN --mount=type=secret,id=gh_token --mount=type=secret,id=GIT_AUTH_TOKEN \
    sh -c 'set -e; \
      TOK=""; \
      if [ -s /run/secrets/gh_token ]; then TOK="$(cat /run/secrets/gh_token)"; \
      elif [ -s /run/secrets/GIT_AUTH_TOKEN ]; then TOK="$(cat /run/secrets/GIT_AUTH_TOKEN)"; fi; \
      if [ -n "$TOK" ]; then \
        export GIT_CONFIG_GLOBAL=/tmp/gitconfig; \
        git config --global url."https://x-access-token:${TOK}@github.com/".insteadOf "https://github.com/"; \
      fi; \
      CGO_ENABLED=1 go build -tags "sqlcipher sqlite_fts5" -ldflags="-w -s" -o iamd ./cmd/iamd/; \
      CGO_ENABLED=1 go build -tags "sqlcipher sqlite_fts5" -ldflags="-w -s" -o iam ./cmd/iam/; \
      CGO_ENABLED=1 go build -tags "sqlcipher sqlite_fts5" -ldflags="-w -s" -o iamctl ./cmd/iamctl/; \
      rm -f /tmp/gitconfig'

# ── Production image ──────────────────────────────────────────
FROM docker.io/library/alpine:3.21 AS standard
LABEL maintainer="https://hanzo.ai/"
ARG USER=hanzo

RUN apk add --no-cache tzdata curl ca-certificates sqlite sqlcipher \
    && update-ca-certificates \
    && adduser -D $USER -u 1000 \
    && mkdir logs \
    && chown -R $USER:$USER logs

USER 1000
WORKDIR /
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/iamd ./iamd
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/iam ./iam
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/iamctl ./iamctl
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/swagger ./swagger
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/conf/app.prod.conf ./conf/app.conf
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/init_data.json ./init_data.json
COPY --from=front --chown=$USER:$USER /web/build ./web/build

ENTRYPOINT ["/iamd"]
CMD ["serve"]
