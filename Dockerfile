# Hanzo IAM — proprietary identity service (zip + orm, no Casdoor).
# Multi-stage Go build → distroless-style alpine. Pure-Go (CGO_ENABLED=0);
# hanzoai/sqlite uses the modernc engine so no cgo/musl toolchain is needed.

FROM golang:1.26.4@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS build
WORKDIR /src

# Cache the module graph before copying the source. iam imports private hanzoai
# modules (hanzoai/orm, hanzoai/sqlite), so mark them private (direct fetch, no
# sumdb) and — when a GIT_AUTH_TOKEN is mounted — rewrite github.com to an
# authenticated fetch so `go mod download` can read them. Same pattern as
# hanzoai/cloud; without the token it is a no-op (a public-only build still works).
ENV GOPRIVATE=github.com/hanzoai/*
COPY go.mod go.sum ./
RUN --mount=type=secret,id=GIT_AUTH_TOKEN \
    if [ -s /run/secrets/GIT_AUTH_TOKEN ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/GIT_AUTH_TOKEN)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download

COPY . .

# Per SCALE_STANDARD.md §2 — every Go production Dockerfile that emits JSON to a
# client builds with GOEXPERIMENT=jsonv2 (zip's edge JSON path).
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}

ARG VERSION=dev
# Two binaries from one build stage: the server (/out/iam) and the Phase-5
# cutover migrator (/out/migrate-v1) the migration Job runs. Both are pure-Go
# (CGO_ENABLED=0 + the same GOEXPERIMENT) and share the one module download above.
# The migrator carries no version symbol, so it is stamped -s -w only.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/iam . \
 && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w" \
      -o /out/migrate-v1 ./cmd/migrate-v1

FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS STANDARD
LABEL org.opencontainers.image.source="https://github.com/hanzoai/iam"
LABEL org.opencontainers.image.title="Hanzo IAM"
# sqlcipher is the C SQLCipher 4.x shell the migrator's --wal-inclusive path drives
# to checkpoint each shard's uncheckpointed -wal before extraction; alpine ships
# SQLCipher 4.x (4.5.6 on the stable branch, 4.6.x on edge), whose v4 on-disk
# format matches the production data and the pure-Go codec. The server never calls
# it — it rides along so this ONE image serves both the server and the migrator Job.
# alpine is digest-pinned: this runtime base is in the migrator's DEK trust path (it
# provides the sqlcipher the raw decryption key is piped to), so a floating :latest is
# not acceptable for a one-shot migration of irreplaceable auth data (RED, v1.32.6).
RUN apk add --no-cache ca-certificates sqlcipher && update-ca-certificates \
    && adduser -D -u 1000 hanzo \
    && mkdir -p /data && chown -R hanzo:hanzo /data
USER 1000
WORKDIR /
COPY --from=build --chown=hanzo:hanzo /out/iam /iam
COPY --from=build --chown=hanzo:hanzo /out/migrate-v1 /migrate-v1

# Serves the IAM API over ZAP (:9653) + the HTTP edge (:8080). Bootstrap the
# config with --init-data /etc/iam/init_data.json (mounted from the same
# init_data ConfigMap the Casdoor iam uses; ${VAR} creds from the KMS-synced env).
EXPOSE 8080 9653
ENTRYPOINT ["/iam"]
CMD ["serve", "--db", "/data/iam.db", "--http", "http://:8080", "--zap", ":9653"]
