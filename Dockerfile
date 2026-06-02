# ── Frontend build ─────────────────────────────────────────────
# Base images pulled from Docker Hub directly. The previous
# `mirror.gcr.io/library/*` references are dropped — we don't use any
# gcr.io path inside the Hanzo/Lux/Zoo ecosystems. DockerHub library/*
# is public and works without auth for these well-known upstreams; if
# the unauth pull cap becomes an issue, swap to public.ecr.aws/docker/library
# instead, never gcr.io.
FROM docker.io/library/node:18.19.0 AS front
WORKDIR /web
ARG VITE_DEFAULT_APP=app-built-in

COPY ./web/package.json ./web/pnpm-lock.yaml ./web/.npmrc ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY ./web .
ENV VITE_DEFAULT_APP=$VITE_DEFAULT_APP
RUN NODE_OPTIONS="--max-old-space-size=4096" pnpm run build

# ── Go build ──────────────────────────────────────────────────
FROM docker.io/library/golang:1.26 AS back
WORKDIR /go/src/hanzo-iam

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Per SCALE_STANDARD.md §2 — GOEXPERIMENT=jsonv2 in every production Go
# build. IAM emits JSON at the OAuth/OIDC endpoints (login flow,
# userinfo, JWKS); jsonv2 lands -12% time / -23% allocs on the edge.
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o iamd ./cmd/iamd/
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o iam ./cmd/iam/
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o iamctl ./cmd/iamctl/

# ── Production image ──────────────────────────────────────────
FROM docker.io/library/alpine:3.21 AS standard
LABEL maintainer="https://hanzo.ai/"
ARG USER=hanzo

RUN apk add --no-cache tzdata curl ca-certificates sqlite \
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
