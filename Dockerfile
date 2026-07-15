# Hanzo IAM v2 — proprietary identity service (zip + orm, no Casdoor).
# Multi-stage Go build → distroless-style alpine. Pure-Go (CGO_ENABLED=0);
# hanzoai/sqlite uses the modernc engine so no cgo/musl toolchain is needed.

FROM golang:1.26.4 AS build
WORKDIR /src

# Cache the module graph before copying the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Per SCALE_STANDARD.md §2 — every Go production Dockerfile that emits JSON to a
# client builds with GOEXPERIMENT=jsonv2 (zip's edge JSON path).
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/iam2 .

FROM alpine:latest AS STANDARD
LABEL org.opencontainers.image.source="https://github.com/hanzoai/iam2"
LABEL org.opencontainers.image.title="Hanzo IAM v2"
RUN apk add --no-cache ca-certificates && update-ca-certificates \
    && adduser -D -u 1000 hanzo \
    && mkdir -p /data && chown -R hanzo:hanzo /data
USER 1000
WORKDIR /
COPY --from=build --chown=hanzo:hanzo /out/iam2 /iam2

# Serves the IAM v2 API over ZAP (:9653) + the HTTP edge (:8080). Bootstrap the
# config with --init-data /etc/iam/init_data.json (mounted from the same
# init_data ConfigMap the Casdoor iam uses; ${VAR} creds from the KMS-synced env).
EXPOSE 8080 9653
ENTRYPOINT ["/iam2"]
CMD ["serve", "--db", "/data/iam2.db", "--http", "http://:8080", "--zap", ":9653"]
