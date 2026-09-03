# Hanzo IAM — identity service (zip + orm).
# Multi-stage Go build → distroless-style alpine. Pure-Go (CGO_ENABLED=0);
# hanzoai/sqlite uses the modernc engine so no cgo/musl toolchain is needed.

FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build
WORKDIR /src

# Cache the module graph before copying the source. Every module iam requires,
# hanzoai/orm and hanzoai/sqlite included, is public: the module proxy serves it
# and the checksum database records it, measured across the whole graph. So this
# needs no credential, and go.sum stays authoritative for every dependency.
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

# What the scratch stage copies in place of adduser and mkdir, which it lacks.
RUN printf 'hanzo:x:1000:1000::/data:/sbin/nologin\n' > /etc/passwd.iam && \
    printf 'hanzo:x:1000:\n' > /etc/group.iam && \
    mkdir -p /emptydata

# THE MIGRATOR, kept as a named target and nothing else.
#
# This stage exists for the one-shot encryption cutover, whose Job drives the C
# SQLCipher shell to checkpoint each shard's uncheckpointed -wal before
# extraction, and needs /bin/sh to do it. alpine is digest-pinned because it sits
# in that migrator's DEK trust path — it provides the sqlcipher the raw
# decryption key is piped to — and a floating :latest is not acceptable for a
# one-shot migration of irreplaceable auth data (RED, v1.32.6).
#
# IT IS NO LONGER WHAT THE SERVER SHIPS AS. The cutover Job pins its image by
# DIGEST (ghcr.io/hanzoai/iam:1.19.8@sha256:a6913f7b…, universe
# infra/k8s/iam/encryption-cutover-job.yaml), so it can never resolve to a build
# made after it was written and nothing here can affect it. The sqlcipher and the
# shell were riding along in every serving image for a Job that cannot see them.
#
# Build it with --target migrator if that cutover is ever re-cut. Doing so also
# means re-pinning the Job, which is the moment to check the DEK path again.
FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS migrator
LABEL org.opencontainers.image.source="https://github.com/hanzoai/iam"
LABEL org.opencontainers.image.title="Hanzo IAM (migrator)"
RUN apk add --no-cache ca-certificates sqlcipher && update-ca-certificates \
    && adduser -D -u 1000 hanzo \
    && mkdir -p /data && chown -R hanzo:hanzo /data
USER 1000
WORKDIR /
COPY --from=build --chown=hanzo:hanzo /out/iam /iam
ENTRYPOINT ["/iam"]

# THE IMAGE IS THE BINARY.
#
# iam is CGO_ENABLED=0 and statically linked — the comment at the top of this file
# has said so since it was written — and the server never called sqlcipher. What
# alpine supplied was the trust bundle (data), an account (two files the kernel
# reads to name a uid it already enforces), and a data directory. All three copy.
#
# This is the identity service. Every token in the estate is signed by it, so the
# smaller the surface that is not our code, the better: a shell in this image is a
# shell an attacker who reaches it does not have to bring.
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/hanzoai/iam"
LABEL org.opencontainers.image.title="Hanzo IAM"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The account and the data directory, written in the builder because scratch has
# neither adduser nor mkdir. A PersistentVolume replaces /data at run time; this
# is what the image holds when nothing is mounted.
COPY --from=build /etc/passwd.iam /etc/passwd
COPY --from=build /etc/group.iam /etc/group
COPY --from=build --chown=1000:1000 /emptydata /data

COPY --from=build --chown=1000:1000 /out/iam /iam

USER 1000:1000
WORKDIR /

# Serves the IAM API over ZAP (:9653) + the HTTP edge (:8080). Bootstrap the
# config with --init-data /etc/iam/init_data.json (mounted from the same
# init_data ConfigMap the legacy iam uses; ${VAR} creds from the KMS-synced env).
EXPOSE 8080 9653
ENTRYPOINT ["/iam"]
CMD ["serve", "--db", "/data/iam.db", "--http", "http://:8080", "--zap", ":9653"]
