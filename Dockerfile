# ── Frontend build ─────────────────────────────────────────────
FROM node:18.19.0 AS front
WORKDIR /web
ARG VITE_DEFAULT_APP=app-built-in

COPY ./web/package.json ./web/pnpm-lock.yaml ./web/.npmrc ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY ./web .
ENV VITE_DEFAULT_APP=$VITE_DEFAULT_APP
RUN NODE_OPTIONS="--max-old-space-size=4096" pnpm run build

# ── Go build ──────────────────────────────────────────────────
FROM golang:1.26 AS back
WORKDIR /go/src/hanzo-iam

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o iamd ./cmd/iamd/
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o iam ./cmd/iam/

# ── Production image ──────────────────────────────────────────
FROM alpine:3.21 AS standard
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
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/swagger ./swagger
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/conf/app.prod.conf ./conf/app.conf
COPY --from=back --chown=$USER:$USER /go/src/hanzo-iam/init_data.json ./init_data.json
COPY --from=front --chown=$USER:$USER /web/build ./web/build

ENTRYPOINT ["/iamd"]
CMD ["serve"]
