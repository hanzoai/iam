# Hanzo IAM — identity service (zip + orm).
# Multi-stage Go build → distroless-style alpine. Pure-Go (CGO_ENABLED=0);
# hanzoai/sqlite uses the modernc engine so no cgo/musl toolchain is needed.

FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build
WORKDIR /src

# Cache the module graph before copying the source. Every module iam requires,
# hanzoai/orm and hanzoai/sqlite included, is served by the public proxy and
# recorded in the public checksum log, so this needs no credential and gets
# verification it did not have before.
#
# GOPRIVATE said the opposite and that is why a credential was here at all: it
# means "bypass the proxy AND the checksum database", and bypassing the proxy
# routes the fetch to github.com, which then has to be authenticated. The token
# also did not stay in the mount — `git config --global` wrote it to
# /root/.gitconfig inside this layer, where anyone with the image can read it.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Per SCALE_STANDARD.md §2 — every Go production Dockerfile that emits JSON to a
# client builds with GOEXPERIMENT=jsonv2 (zip's edge JSON path).
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}

ARG VERSION=dev
# One binary: the server (/out/iam), pure-Go (CGO_ENABLED=0 + GOEXPERIMENT).
#
# It used to build a second, /out/migrate-v1 — the Phase-5 cutover migrator. That
# command was deleted in 144db2add ("iam: one IAM — drop v1 and the iam2 name")
# and this stanza was not, so every image build since has failed at
# `stat /src/cmd/migrate-v1: directory not found`. The Dockerfile is the only
# consumer that still referenced it.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/iam .

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

# Serves the IAM API over ZAP (:9653) + the HTTP edge (:8080). Bootstrap the
# config with --init-data /etc/iam/init_data.json (mounted from the same
# init_data ConfigMap the legacy iam uses; ${VAR} creds from the KMS-synced env).
EXPOSE 8080 9653
ENTRYPOINT ["/iam"]
CMD ["serve", "--db", "/data/iam.db", "--http", "http://:8080", "--zap", ":9653"]
