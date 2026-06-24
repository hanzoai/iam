#!/usr/bin/env bash
# Run the multi-chain wallet-login e2e: boot the REAL IAM backend, then drive
# the production WalletConnect.tsx flow in a real browser with a mock signer
# that produces GENUINE secp256k1 / ed25519 signatures. Nothing about the server
# verify is faked — only the wallet signer is injected.
#
# Usage:
#   web/e2e/run.sh            # boot backend (if needed) + run Playwright
#   IAM_BACKEND=...  web/e2e/run.sh   # point the Vite proxy at an existing IAM
#
# Prereqs: a built iamd binary (see below), pnpm, and Playwright browsers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # iam repo root
WEB="$ROOT/web"
E2E="$WEB/e2e"
WORK="${IAM_E2E_WORK:-/tmp/iam-e2e}"
mkdir -p "$WORK/data"

IAM_BACKEND="${IAM_BACKEND:-http://localhost:8000}"

# --- 1. backend ------------------------------------------------------------
# Only start one if nothing is already serving the web3 routes. We build with
# GOWORK=off (the shared ~/work/hanzo/go.work has a stale luxfi/threshold sum)
# and CGO_ENABLED=0 (pure-Go modernc sqlite, no SQLCipher headers needed).
if ! curl -fsS "$IAM_BACKEND/v1/iam/web3/nonce?chain=evm&address=0x0" >/dev/null 2>&1; then
  echo "[e2e] building iamd (GOWORK=off CGO_ENABLED=0)…"
  ( cd "$ROOT" && GOWORK=off CGO_ENABLED=0 go build -o "$WORK/iamd" ./cmd/iamd/ )

  # init_data seeds app-hanzo (org=hanzo, enableSignUp=true) so a first-seen
  # wallet provisions + logs in end-to-end. (Config is via env because Go's flag
  # pkg can't parse -config after the `serve` subcommand; GetConfigString reads
  # env before the file, so env wins.)
  cat > "$WORK/init_data.json" <<'JSON'
{
  "organizations": [
    {"owner":"admin","name":"admin","displayName":"Admin","passwordType":"argon2id","tags":["admin"],"languages":["en"],"initScore":2000},
    {"owner":"admin","name":"hanzo","displayName":"Hanzo","passwordType":"argon2id","languages":["en"],"initScore":100}
  ],
  "applications": [
    {"owner":"admin","name":"iam","organization":"admin","displayName":"IAM","enablePassword":true,"enableSignUp":false},
    {"owner":"admin","name":"app-hanzo","organization":"hanzo","displayName":"Hanzo Wallet Login (e2e)","enablePassword":true,"enableSignUp":true,"redirectUris":["http://localhost:7100/"]}
  ],
  "users": [], "certs": [], "providers": [], "syncer": [], "ldaps": []
}
JSON

  echo "[e2e] starting iamd on :8000…"
  ( cd "$ROOT" \
      && GOWORK=off ORIGIN="$IAM_BACKEND" httpport=8000 driverName=sqlite \
         dataSourceName="file:$WORK/iam.db?_journal_mode=WAL&_busy_timeout=5000&cache=shared" \
         dbName=iam_e2e orgIsolation=none dataDir="$WORK/data" \
         initDataFile="$WORK/init_data.json" initDataNewOnly=true \
         "$WORK/iamd" serve >"$WORK/server.log" 2>&1 & )
  for _ in $(seq 1 30); do
    curl -fsS "$IAM_BACKEND/v1/iam/web3/nonce?chain=evm&address=0x0" >/dev/null 2>&1 && break
    sleep 1
  done
  echo "[e2e] backend up (log: $WORK/server.log)"
else
  echo "[e2e] reusing IAM backend at $IAM_BACKEND"
fi

# --- 2. frontend + tests ---------------------------------------------------
# playwright.config.ts boots the Vite harness (vite.e2e.config.ts) which proxies
# /v1/iam -> $IAM_BACKEND, then runs the spec. Browsers come from the standard
# Playwright cache.
cd "$WEB"
export IAM_BACKEND
echo "[e2e] running Playwright…"
exec node_modules/.bin/playwright test --config "$E2E/playwright.config.ts" "$@"
