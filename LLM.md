# Hanzo IAM

## Overview

Identity & Access Management for the Hanzo + Liquidity ecosystems. OAuth 2.0 / OIDC / SAML / LDAP / SCIM / WebAuthn / MFA — all served behind a single canonical surface at `/v1/iam/*`.

Data lives in Base (`hanzoai/base`) — embedded SQLite with auto-migrations and replicate-to-S3 (no PostgreSQL, no Redis). Inter-service traffic uses native ZAP binary protocol.

## API surface

**Public:** `/v1/iam/*` only. Internal services and SDKs target this.

```
/v1/iam/login                       — username/password + MFA
/v1/iam/login/oauth/authorize       — OAuth2 authorization endpoint
/v1/iam/login/oauth/access_token    — OAuth2 token endpoint (incl. client_credentials)
/v1/iam/login/oauth/refresh_token
/v1/iam/login/oauth/introspect
/v1/iam/login/oauth/revoke
/v1/iam/oauth/register              — Dynamic Client Registration (RFC 7591)
/v1/iam/.well-known/openid-configuration
/v1/iam/.well-known/jwks
/v1/iam/users/...
/v1/iam/applications/...
/v1/iam/organizations/...
/v1/iam/...
```

A request filter rewrites `/v1/iam/X` → internal `/api/X` for all non-OAuth paths. The internal `/api/*` paths exist but should not be relied on by external callers — they may move.

ZAP RPC runs on a separate port for service-to-service auth (`AuthService.GetToken`, `AuthService.IntrospectToken`).

## Storage

Base under the hood. Each deployment gets its own SQLite file at `${IAM_DATA_DIR}/iam.db`. Per-org encrypted tables with a master key from KMS. WAL streamed to S3 via the replicate sidecar.

Schema migrations are managed by Base (Goose-style migration files in `migrations/`). On boot, IAM applies any pending migrations against its SQLite file.

For multi-tenant per-org isolation: each org gets a separate SQLite file under `${IAM_DATA_DIR}/orgs/{orgSlug}.db` with a HKDF-derived per-org DEK. See `feedback_no_postgres_anywhere.md` in memory for the broader policy.

## Auth flows

### User login

1. Browser hits `https://iam.{env}.satschel.com/v1/iam/login`
2. Form submit → Base verifies password + MFA
3. Sets session, redirects to OAuth `authorize` endpoint
4. Returns code → SPA exchanges via `/v1/iam/login/oauth/access_token`

### Service-to-service (client_credentials)

For machine identity (e.g. KMS pulling from IAM, or a CI job calling internal APIs):

```bash
curl -X POST https://iam.dev.satschel.com/v1/iam/login/oauth/access_token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>"
```

Returns `{"access_token": "...", "expires_in": 86400, "token_type": "Bearer"}`.

### JWKS for downstream JWT validation

`GET /v1/iam/.well-known/jwks` — RSA public keys for verifying issued JWTs. Liquid Gateway and ATS validate tokens using JWKS — no shared secret.

## Deployment

| Env | URL | Image | Storage |
|---|---|---|---|
| devnet | `https://iam.dev.satschel.com` | `liquidityio/iam:dev` | Base/SQLite (PVC) |
| testnet | `https://iam.test.satschel.com` | `liquidityio/iam:test` | Base/SQLite (PVC) |
| mainnet | `https://iam.main.satschel.com` | `liquidityio/iam:main` | Base/SQLite (PVC) |
| local | `http://localhost:8000` | `liquidityio/iam:dev` | SQLite (volume) |

Deployed via `LiquidIAM` CRD reconciled by `liquid-operator`. Source CR: `~/work/liquidity/universe/k8s/platforms/{env}.yaml`.

## Configuration

Env vars consumed at boot:

| Var | Purpose | Default |
|---|---|---|
| `IAM_DATA_DIR` | Base SQLite parent dir | `/data/iam` |
| `IAM_LISTEN` | HTTP listen address | `:8000` |
| `IAM_ZAP_LISTEN` | ZAP RPC listen | `:9653` |
| `IAM_KMS_MASTER_KEY` | Master encryption key (KMS-sourced) | required |
| `IAM_REPLICATE_BUCKET` | GCS bucket for WAL replication | optional |
| `IAM_REPLICATE_AGE_RECIPIENT` | age public key for at-rest encryption | optional (required if bucket set) |

**Don't** use `CASDOOR_*` env vars — they're legacy aliases retained for backward compatibility, not preferred. Use `IAM_*`.

## Build

```bash
cd ~/work/hanzo/iam
go build -o iam ./cmd/iam     # backend
cd web && pnpm build           # frontend (Vite)
```

CI builds multi-arch Docker image (`hanzo-build-linux-amd64` + `hanzo-build-linux-arm64` runners) and pushes to:
- `ghcr.io/hanzoai/iam:{tag}` (canonical for Hanzo)
- `us-docker.pkg.dev/liquidity-registry/liquidityio/iam:{tag}` (for Liquidity)

## Repository layout

```
iam/
├── cmd/iam/                 — main binary
├── controllers/             — HTTP handlers
├── routers/
│   ├── router.go            — route table (/api/* internal)
│   └── v1_iam_rewrite.go    — /v1/iam/* → /api/* filter
├── object/                  — domain logic (users, apps, orgs, sessions)
├── service/                 — auth flows (oauth, oidc, saml, ldap)
├── migrations/              — Base schema migrations
├── notification/            — email/SMS/webhook fan-out adapters
├── storage/                 — pluggable file backends (S3, GCS, Azure, ...)
├── web/                     — React SPA
├── compose.yml              — local dev stack
├── deployment/              — K8s manifests (operator-managed in prod)
├── conf/                    — sample app.conf templates
└── NOTICE                   — third-party license attributions
```

## Integration points (across the stack)

- **Liquid Gateway** (`liquid-gateway` in `liquidity` ns): validates inbound JWTs against IAM JWKS
- **KMS** (`liquid-kms`): authenticates clients via `/v1/iam/login/oauth/access_token` (client_credentials), then mints short-lived bearer for KMS sessions
- **ATS / BD / TA**: extract `sub` (user) and `owner` (org) from JWT claims
- **Liquidity Console / Exchange / Superadmin / Platform**: standard authorization_code + PKCE OAuth flow
- **MPC**: WebAuthn challenges issued via IAM, completed in browser, then user shard authorized via JWT bound to NodeID

## Security posture

- All secrets land in KMS first, synced to k8s `Secret` via `KMSSecret` CR — never push raw key bytes through `kubectl apply`
- Argon2id password hashing (NEVER plaintext, NEVER bcrypt)
- Per-org DEK derived from a master key stored in KMS — encrypted-at-rest tables
- TLS termination at Liquid Ingress; IAM serves plain HTTP internally
- JWKS rotation: keys are dual-published (current + previous) for graceful rollover

## Testing

```bash
go test ./...                       # backend unit tests
cd web && pnpm test                 # frontend
pnpm e2e                            # Playwright (hits live dev IAM)
```

E2E tests live at `tests/iam-e2e.spec.ts` and `tests/iam-login.spec.ts`. They run against a dev or staging IAM with a known seed user (`satoshi.nakamoto` per memory `feedback_seed_credentials.md`).

## Things this is NOT

- ❌ Casdoor (the upstream library this was originally derived from has its own deployment, ours is independent)
- ❌ A PostgreSQL service (no postgres anywhere — Base/SQLite only)
- ❌ A Redis user (no Redis — sessions live in Base)
- ❌ Available at `hanzo.id` for Liquidity workloads — Liquidity uses `iam.{env}.satschel.com`. `hanzo.id` is the public Hanzo brand origin, separate cluster.

## Related

- `~/work/hanzo/iam/NOTICE` — upstream library attributions (legal)
- `~/work/liquidity/operator/src/crd.rs` — `LiquidIAM` CRD spec
- `~/work/liquidity/universe/k8s/platforms/{env}.yaml` — per-env CR instances
- Memory notes (these are policy):
  - `feedback_iam_no_casdoor.md` — IAM is uniquely ours
  - `feedback_no_postgres_anywhere.md` — Base/SQLite only
  - `feedback_keys_from_mnemonic.md` — keys derive from mnemonic + KMS
  - `feedback_seed_credentials.md` — fixed dev seed users
