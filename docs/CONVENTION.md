# IAM Convention — Single Source of Truth

**This document is canon.** Every consumer of Hanzo IAM (and every fork —
`tenantio/iam`, `acme/iam`, `example/iam`, …) must follow these
rules. There is **one** way to do each thing. No aliases, no legacy
prefixes, no hardcoded hostnames.

---

## 1. Naming

| Concept | Value |
|---|---|
| Engine name (this repo) | `hanzo/iam` (image: `ghcr.io/hanzoai/iam:vX.Y.Z`) |
| Engine admin org | `admin` |
| Engine self-app | `admin/iam` (owner/name in IAM-native form) |
| Engine bootstrap user | `admin/root` |
| **Consumer app slug** | **`<consumer-org>-<appname>`** — e.g. `hanzo-brain`, `tenant-app`, `acme-verify`, `zoo-ngo`, `lux-cloud` |
| Consumer org | `<consumer-org>` — e.g. `hanzo`, `tenant`, `acme`, `zoo`, `lux` |

There is exactly one rule: **app slug = `<org>-<app>`**. If you're seeing
`hanzo-foundation`, `zoo-foundation`, `app-computer`, fix them to match
the rule.

## 2. Three namespaces — `IAM_*`, `HANZO_*`, `IDV_*`

Different concerns get different prefixes. Knowing which is which prevents
the historical mess where `HANZO_IAM_URL` / `HANZO_CLIENT_ID` /
`IAM_ENDPOINT` all meant the same thing in different files.

| Prefix | What it's for | Examples |
|---|---|---|
| `IAM_*` | The auth/OIDC engine (user identity, JWT issuance, session) | `IAM_URL`, `IAM_CLIENT_ID`, `IAM_CLIENT_SECRET`, `IAM_AUDIENCE`, `IAM_ORG`, `IAM_REDIRECT_URI` |
| `HANZO_*` | Hanzo **product** API access at `api.hanzo.ai` / `llm.hanzo.ai` / `chat.hanzo.ai` etc — your developer credentials to *use* Hanzo as a paid service | `HANZO_API_KEY`, `HANZO_OAUTH_CLIENT_ID`, `HANZO_OAUTH_CLIENT_SECRET`, `HANZO_OAUTH_REDIRECT_URI` |
| `IDV_*` | Identity-verification providers (biometric, KYC vendors) | `IDV_URL`, `IDV_CLIENT_ID`, `IDV_CLIENT_SECRET` |
| `CASDOOR_*` | **DEAD** — engine isn't Casdoor-branded anymore | (delete) |

A bot that **authenticates users via Hanzo IAM** AND **calls api.hanzo.ai for
LLM completions** uses BOTH namespaces. They don't merge. They live side
by side, distinct.

Use **only the canonical name in each namespace**. No aliases, no
fallbacks, no acceptance-of-multiple-names code.

| Variable | Purpose | Default for local-dev |
|---|---|---|
| `IAM_URL` | The IAM instance to talk to | `http://localhost:8000` |
| `IAM_ISSUER` | Pinned OIDC issuer claim to validate | same as `IAM_URL` |
| `IAM_AUDIENCE` | This consumer's own client_id (= `<org>-<app>`) | `<org>-<app>` |
| `IAM_CLIENT_ID` | OAuth client_id | `<org>-<app>` |
| `IAM_CLIENT_SECRET` | OAuth client_secret | KMS-sourced |
| `IAM_ORG` | The org this consumer belongs to | `<consumer-org>` |
| `IAM_REDIRECT_URI` | OAuth redirect URI | `https://<consumer-host>/callback` |

### Killed names (NEVER use, NEVER add)

These names duplicated an `IAM_*` or `HANZO_*` concept under a wrong
prefix. Pick the right namespace and use the canonical name:

```
HANZO_IAM_URL          → IAM_URL              (this is IAM auth, not Hanzo product API)
HANZO_IAM_ENDPOINT     → IAM_URL
HANZO_IAM_SERVER_URL   → IAM_URL
HANZO_IAM_CLIENT_ID    → IAM_CLIENT_ID
HANZO_IAM_CLIENT_SECRET→ IAM_CLIENT_SECRET
IAM_ENDPOINT           → IAM_URL
IAM_SERVER_URL         → IAM_URL
IAM_KEYS_URL           → derived from IAM_URL + /v1/iam/.well-known/jwks
CASDOOR_*              → IAM_*                (engine isn't Casdoor-branded anymore)
NEXT_PUBLIC_CASDOOR_*  → SPA runtime /config.json (§5)
VITE_IAM_URL           → SPA runtime /config.json (§5)
VITE_IAM_CLIENT_ID     → SPA runtime /config.json (§5)
```

**HANZO_OAUTH_*** is **NOT killed** — it's legitimate and lives in the
`HANZO_*` namespace for consuming Hanzo product APIs (api.hanzo.ai etc).
Rename to `IAM_*` only if the value is actually consumed by an
@hanzo/iam SDK / /v1/iam/* route / JWKS validator. The give-away is
where the value is consumed:

- Used by `@hanzo/iam` SDK, points at an IAM instance, validates JWKS,
  hits `/v1/iam/oauth/*`           →  IAM_*
- Used by `@hanzo/api` (or raw fetch) against `https://api.hanzo.ai` /
  `https://llm.hanzo.ai` for LLM/Chat/MCP                          →  HANZO_*
- Used by a biometric / KYC IDV provider                          →  IDV_*

A single app can (and often does) carry env vars from all three
namespaces. They don't merge.

## 3. Environment variables (server-side, IAM itself)

| Variable | Purpose | Default |
|---|---|---|
| `IAM_LISTEN` | HTTP listen address | `:8000` |
| `IAM_DATA_DIR` | Per-org SQLite parent dir | `/data/iam` |
| `IAM_ADMIN_ORG` | Admin org name | `admin` |
| `IAM_ADMIN_APP` | IAM self-app name | `iam` |
| `IAM_ADMIN_USER` | Bootstrap user name | `root` |
| `IAM_ADMIN_PASSWORD` | Bootstrap user password (Argon2id at boot) | `root` (dev) |
| `IAM_KMS_MASTER_KEY` | Per-org DEK master | KMS-sourced (prod), zero-key (dev) |
| `IAM_REPLICATE_BUCKET` | S3 bucket for WAL | unset (no replication) |
| `IAM_REPLICATE_AGE_RECIPIENT` | age X25519 recipient | unset |
| `ORIGIN` | Canonical front-door URL (used by sandbox guard + CORS) | `http://localhost:8000` |
| `SANDBOX_GLOBAL_OTP` | Sandbox OTP bypass code (dev-only) | `999999` (dev), empty (prod) |
| `SANDBOX_ORIGIN_ALLOWLIST` | Additional hosts allowed to use sandbox OTP | unset |
| `ENV` | Runtime env (anything ∉ {production, prod, main, mainnet} is dev) | `dev` |

**Storage is per-org SQLite at `${IAM_DATA_DIR}/orgs/{orgSlug}.db`.** No
Postgres, no Redis — anywhere, ever.

## 4. API surface

One path-prefix. No aliases. No rewrites.

```
/v1/iam/*
```

The legacy aliases (`/api/*`, `/api/iam/*`, `/login/oauth/*`, bare `/oauth/*`)
are gone. The IAM server returns 404 for anything off the canonical surface.

### Canonical endpoints

```
/v1/iam/login
/v1/iam/oauth/authorize
/v1/iam/oauth/token
/v1/iam/oauth/userinfo
/v1/iam/oauth/introspect
/v1/iam/oauth/revoke
/v1/iam/oauth/logout
/v1/iam/.well-known/openid-configuration
/v1/iam/.well-known/jwks
/v1/iam/.well-known/oauth-authorization-server
/v1/iam/.well-known/oauth-protected-resource
```

## 5. Multi-host serving

**One IAM image serves many hosts simultaneously.** The OIDC discovery
doc, issuer claim, JWKS URL, authorize/token URLs are all rewritten
per-request based on `X-Forwarded-Host` (set by the hanzoai/ingress + hanzoai/gateway
in front of IAM). See `controllers/wellknown_oidc_discovery.go ::
getEffectiveHost()`.

So a single deployment of `ghcr.io/hanzoai/iam:v1.14.29` can serve:

- `iam.hanzo.ai`
- `iam.dev.example.com`
- `iam.acme.com`
- `iam.zoo.ngo`
- `iam.lux.network`

…and each will return its own discovery doc with the right hostname
baked in. **Do not hardcode IAM hostnames in consumer code.** Always
read `IAM_URL` from env (backends) or `/config.json` (SPAs).

## 6. Consumer SPAs — `/config.json` runtime pattern (canonical)

For browser-side React/Vite/Next SPAs, **don't bake `IAM_URL` into the
build with `VITE_*`**. Use the `ghcr.io/hanzoai/spa` v1.1+ image which
writes `/config.json` at pod startup from `SPA_*` env vars on the
container.

The SPA fetches `/config.json` before mounting and reads every
env-specific URL from there. The operator (or compose) sets `SPA_*` env
vars on the container; the SPA image renders `/config.json` accordingly.
ONE place owns the hostname-fallback (the SPA's `loadConfig()`); every
other consumer reads from `getConfig()`.

See your tenant's runtime.ts (e.g., apps/web/src/lib/runtime.ts) for a reference
implementation. To copy the pattern to another SPA:

1. Use `ghcr.io/hanzoai/spa:v1.1.0+` as base image.
2. Set `SPA_IAM_URL`, `SPA_IAM_CLIENT_ID`, `SPA_IAM_APP_NAME`, `SPA_ORG_ID`
   (and any sibling-service URLs) on the container.
3. In the SPA, `fetch('/config.json')` and call `loadConfig()` before
   `ReactDOM.render`.
4. Read every URL via `getConfig().iamHost` etc — never inline a domain.

## 7. Tenant runtime config flow

```
HanzoApp / BaseApp CR     (kubectl-applied operator-managed CR)
        │
        ▼
ConfigMap                 (operator-rendered, namespace-scoped)
        │
        ▼
Pod env (SPA_*  or IAM_*) (container env from ConfigMap)
        │
        ├── /config.json   (rendered by ghcr.io/hanzoai/spa image at pod start, SPA fetches it)
        └── go-flag/env    (backend services read os.Getenv directly)
```

There is no fourth path. No `VITE_*` build-time injection. No hardcoded
TS hostname switches. No `if (host === 'iam.dev.example.com')` anywhere.

## 8. SDK

Frontend: **`@hanzo/iam`** (or `@hanzo/iam/browser` for PKCE). Pin to the
latest minor; bump along with IAM image bumps. The legacy
`@hanzo/iam-js-sdk` Casdoor SDK is **deprecated** — migrate any consumer
still on it.

Backend: read JWKS from `${IAM_URL}/v1/iam/.well-known/jwks`, validate
RS256, extract `sub` (user) and `owner` (org). No SDK needed in Go.

## 9. Local-dev quickstart (any consumer)

```bash
# 1. Start IAM
docker run --rm -d -p 8000:8000 --name iam ghcr.io/hanzoai/iam:v1.14.29

# 2. Configure your consumer
export IAM_URL=http://localhost:8000
export IAM_ISSUER=http://localhost:8000
export IAM_CLIENT_ID=<your-org>-<your-app>     # e.g. hanzo-brain, hanzo-console
export IAM_ORG=<your-org>
export IAM_REDIRECT_URI=http://localhost:<your-port>/callback

# 3. Sign in: admin/root · password: root · OTP: 999999
```

## 10. Production checklist

Before any deploy reachable from the public net:

- [ ] `ENV=production` (or `prod`/`main`/`mainnet`)
- [ ] `IAM_ADMIN_PASSWORD` from KMS — never plaintext
- [ ] `IAM_KMS_MASTER_KEY` from KMS — never plaintext
- [ ] `SANDBOX_GLOBAL_OTP=""` (empty — sandbox guard refuses to boot otherwise)
- [ ] `ORIGIN` set to the real hostname
- [ ] TLS via ingress (IAM serves plain HTTP behind the proxy)
- [ ] JWKS rotation period reviewed (`JWT_KEY_ROTATION_PERIOD`)
- [ ] Per-org SQLite replicated to S3 via `IAM_REPLICATE_BUCKET` + age recipient

## 11. Where to find what

| Need | Location |
|---|---|
| 5-line quickstart | [`docs/LOCAL_DEV.md`](./LOCAL_DEV.md) |
| This convention doc (you are here) | [`docs/CONVENTION.md`](./CONVENTION.md) |
| Sandbox guard implementation | `iamserver/sandbox_guard.go` |
| Bootstrap (admin org/app/user/cert) | `object/init.go` |
| Per-request host resolution | `controllers/wellknown_oidc_discovery.go` |
| Compose for local-dev | `compose.yml` |
| `.env` template | `.env.example` |

## 12. Adding a new consumer app

```
1. Pick org + appname     →  app slug = <org>-<appname>  (e.g. hanzo-brain)
2. Register in IAM        →  POST /v1/iam/applications  with owner=<org>, name=<org>-<appname>
3. Set env on your app    →  IAM_URL, IAM_CLIENT_ID, IAM_ORG, IAM_AUDIENCE
4. Validate JWTs          →  fetch ${IAM_URL}/v1/iam/.well-known/jwks once at boot
5. Trust the gateway      →  X-Org-Id, X-User-Id, X-User-Email headers are injected
                             by the upstream Hanzo Gateway after JWT validation
```

Nothing else is required. No SDK config, no /api/ prefix, no hostname
hardcoding, no Postgres.
