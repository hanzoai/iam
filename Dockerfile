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
# Pinned to alpine3.22 to MATCH the runtime base below — so the libsqlcipher the
# binary links against here is byte-identical to the one it loads at runtime
# (build==runtime by construction, not by hope). A version skew could leave the
# binary's DT_NEEDED satisfied by a different libsqlcipher than the codec proof
# tested against.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine3.22 AS back
ARG TARGETOS TARGETARCH
# CGO + SQLCipher toolchain for the hanzoai/sqlite embedded driver.
#
# REAL at-rest encryption requires linking the SYSTEM libsqlcipher (NOT mattn's
# vendored amalgamation) with the SQLCipher codec enabled. mainline mattn has no
# `sqlcipher` build tag — that tag is INERT and silently produces PLAINTEXT. The
# correct recipe is the `libsqlite3` tag + libsqlcipher + -DSQLITE_HAS_CODEC +
# -DSQLITE_USE_URI=1 (the URI `key` param is how the driver keys a DB so it can
# be reopened). hanzoai/sqlite's TestEncryptionProof fails the build if this is
# mis-linked, so a regression to plaintext cannot ship.
#
# Built CGO-native per-arch on the native build runners (no cross-compile), musl
# throughout so the binary runs on the alpine runtime below.
RUN apk add --no-cache git gcc musl-dev sqlcipher-dev pkgconfig
# mattn/go-sqlite3's `libsqlite3` tag hard-codes `#cgo linux LDFLAGS: -lsqlite3`,
# but alpine's sqlcipher-dev ships ONLY libsqlcipher (no libsqlite3.so) → the link
# fails with `ld: cannot find -lsqlite3`. SQLCipher *is* sqlite + the codec and
# exports the full sqlite3_* ABI, so point `-lsqlite3` at it via a dev symlink.
# This is deliberate: we want -lsqlite3 to resolve to the CODEC library, never to
# a plaintext libsqlite3 (which would silently disable encryption — exactly what
# the TestEncryptionProof gate below catches). Do NOT `apk add sqlite-dev`.
RUN set -e; \
    SC="$(find /usr/lib -name 'libsqlcipher.so*' | sort | head -1)"; \
    test -n "$SC" || { echo "libsqlcipher not found after sqlcipher-dev install" >&2; exit 1; }; \
    ln -sf "$SC" /usr/lib/libsqlite3.so; \
    ln -sf "$SC" /usr/lib/libsqlite3.so.0
# Codec + URI keying for SQLCipher, on top of alpine's sqlcipher.pc include/lib.
ENV CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I/usr/include/sqlcipher"
ENV CGO_LDFLAGS="-lsqlcipher"
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
      CGO_ENABLED=1 go build -tags "libsqlite3 sqlite_fts5" -ldflags="-w -s" -o iamd ./cmd/iamd/; \
      CGO_ENABLED=1 go build -tags "libsqlite3 sqlite_fts5" -ldflags="-w -s" -o iam ./cmd/iam/; \
      CGO_ENABLED=1 go build -tags "libsqlite3 sqlite_fts5" -ldflags="-w -s" -o iamctl ./cmd/iamctl/; \
      rm -f /tmp/gitconfig'

# ENCRYPTION GATE — fail the image build if at-rest encryption is not real.
# The shared CI `go test` job runs CGO_ENABLED=0, so the ciphertext assertions in
# these proofs only execute here, under the SAME CGO + libsqlcipher build the
# image ships. A regression that links plain sqlite (e.g. dropping the
# libsqlite3 tag / codec flags) makes these tests fail -> no image is produced,
# instead of silently shipping plaintext databases.
# SQLITE_REQUIRE_CODEC=1 turns TestEncryptionProof's "codec not linked" SKIP into
# a HARD FAILURE — without it, a build that links plain sqlite (CodecLinked()=false)
# goes GREEN by skipping, shipping plaintext (the "CI-theater" footgun). With the
# codec actually linked (libsqlite3.so -> libsqlcipher above), the test runs its
# full on-disk-ciphertext + wrong-key-rejected assertions instead of skipping.
# -count=1 defeats Go's test cache: a cached PASS from a prior layer could
# otherwise mask a codec regression. readelf/ldd below then prove the LINKED
# binary (not just the test) binds sqlite3_* to libsqlcipher.
RUN SQLITE_REQUIRE_CODEC=1 CGO_ENABLED=1 go test -count=1 -tags "libsqlite3 sqlite_fts5" -run TestEncryptionProof github.com/hanzoai/sqlite \
 && SQLITE_REQUIRE_CODEC=1 CGO_ENABLED=1 go test -count=1 -tags "libsqlite3 sqlite_fts5" -run TestOrgDBEncryptionPosture ./object/
# Prove the SHIPPED binary's sqlite3_* symbols come from libsqlcipher (not a
# plaintext libsqlite3). The DT_NEEDED string ld emits for the symlink chain can
# be libsqlcipher.so.0 OR libsqlite3.so.0; either must resolve to libsqlcipher,
# and there must be NO plaintext sqlite provider. Fail the build otherwise.
RUN set -e; \
    apk add --no-cache binutils >/dev/null; \
    echo "=== iamd DT_NEEDED ==="; readelf -d ./iamd | grep -E 'NEEDED.*(sqlite3|sqlcipher)' || true; \
    readelf -d ./iamd | grep -qE 'NEEDED.*(sqlcipher|sqlite3)' || { echo "FATAL: iamd links no sqlite/sqlcipher .so" >&2; exit 1; }; \
    ! ldd ./iamd 2>/dev/null | grep -E 'libsqlite3' | grep -vq 'libsqlcipher' || { echo "FATAL: iamd resolves a NON-sqlcipher libsqlite3 (plaintext risk)" >&2; exit 1; }

# ── Production image ──────────────────────────────────────────
# alpine:3.22 — same as the build base above, so libsqlcipher is identical
# build-side and runtime-side (the codec proof in `back` then transitively proves
# this image, since it's the same library version).
FROM docker.io/library/alpine:3.22 AS standard
LABEL maintainer="https://hanzo.ai/"
ARG USER=hanzo

# Runtime needs libsqlcipher (the codec the binary is linked against). It must
# NOT also carry a plaintext libsqlite3 — the binary's `-lsqlite3` DT_NEEDED would
# then resolve sqlite3_* to plaintext sqlite at runtime and silently disable the
# codec (PRAGMA key becomes a no-op), the exact build-vs-runtime mismatch the
# encryption gate cannot see. So install sqlcipher only, and alias libsqlite3.so.0
# to it (same as the build stage) so the loader binds sqlite3_* to the codec lib.
RUN apk add --no-cache tzdata curl ca-certificates sqlcipher \
    && SC="$(find /usr/lib -name 'libsqlcipher.so*' | sort | head -1)" \
    && test -n "$SC" \
    && ln -sf "$SC" /usr/lib/libsqlite3.so.0 \
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
