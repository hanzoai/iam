# IAM v2 Migration — Beego/xorm → Native Go on `hanzoai/orm` + `hanzoai/base` + `hanzoai/zip` + `hanzoai/authz` + `@hanzo/gui`

Status: **Phase 0 (scaffold)**. Phase 1 starts only after the decision points below are signed off.

---

## 1. Why

`~/work/hanzo/iam` is a Beego-style codebase: ~50k LOC backend (15k `controllers/` + 35k `object/`) + ~100k LOC React admin (Radix, not `@hanzo/gui`). 239 unique HTTP routes, all registered through Beego `// @router` annotations. xorm ORM (`hanzoai/xorm` v1.1.6). Mixed-vendor MySQL/Postgres support. The OIDC/OAuth2/OIDC-discovery/JWKS/SAML protocol surfaces are already in-tree (see §3.2) and stay in-tree across the migration.

The published policy in `LLM.md` already declares the target stack:

- Storage: **`hanzoai/orm` (typed Go records + KV cache) over `hanzoai/base` (embedded SQLite + WAL replicate to S3)**, no Postgres anywhere, no Redis.
- HTTP framework: **`hanzoai/zip` (Fiber v3)** — typed handlers, JSON-at-edge, 1 goroutine per conn per `SCALE_STANDARD`. No Beego, no chi, no gin.
- OIDC/OAuth2 protocol surface: **in-tree** (ported from `controllers/auth.go`, `controllers/wellknown_*`, `object/jwt_mldsa65.go`, `object/jwks_cache.go`, `object/wellknown_oidc_discovery.go`). No external OIDC library.
- Authz: **`hanzoai/authz`** — single canonical policy engine, called over ZAP RPC.
- Surface: **single `/v1/iam/*`** mount (HIP‑0026 RFC paths; legacy aliases rewritten).
- Token signing: Argon2id passwords, ML-DSA-65 (FIPS 204) post-quantum JWTs with classical RSA dual track, JWKS rotation (current + previous).
- Inter‑service: ZAP RPC (`github.com/luxfi/zap`) sibling on `:9653`. Native binary protocol, not HTTPS.
- Admin UI: `@hanzo/gui` umbrella, not bespoke React.

Today's repo only *speaks* that policy through `routers/path_rewrite_filter.go`; underneath, Beego + xorm + 239 hand‑annotated controllers carry the weight. v2's job is to make the implementation match the declared policy — one and only one way to do everything.

This document is the migration spec. Phase 0 is scaffolding *only*; everything below is plan, not code.

---

## 2. Target architecture

```
   client / SDK
       │  HTTPS  /v1/iam/*
       ▼
  ┌──────────────────────────────────────────────────────────┐
  │ iam-v2 binary  (single statically‑linked Go executable)  │
  │ ┌─────────────┐   ┌─────────────────────────────────────┐│
  │ │ zip         │   │ base.App                            ││
  │ │ (Fiber v3)  │   │  ├── SQLite (encrypted, per‑org)    ││
  │ │  HTTP +     │◀─▶│  ├── auto‑migrations                ││
  │ │  ZAP RPC    │   │  ├── replicate sidecar → S3/GCS     ││
  │ │  OpenAPI    │   │  └── collections (users/orgs/...)   ││
  │ └─────────────┘   └─────────────────────────────────────┘│
  │ ┌──────────────────────────────────────────────────────┐ │
  │ │ internal/v2/oidc — IN-TREE (ported from v1)          │ │
  │ │   • /oauth/authorize, /token, /userinfo, /introspect │ │
  │ │   • /oauth/revoke, /device, /register, /logout       │ │
  │ │   • OIDC discovery + JWKS + OAuth2 RFC 8414 metadata │ │
  │ │   • ML-DSA-65 (FIPS 204) post-quantum JWT signing    │ │
  │ └──────────────────────────────────────────────────────┘ │
  │ ┌────────────────────┐  ┌──────────────────────────────┐ │
  │ │ providers/         │  │ saml/ldap/scim/webauthn      │ │
  │ │ github,google,...  │  │ (lazily extracted from v1)   │ │
  │ └────────────────────┘  └──────────────────────────────┘ │
  └────────────────────┬─────────────────────────────────────┘
                       │  embed.FS
                       ▼
            @hanzo/gui admin SPA  (apps/admin-iam)
```

Hard rules:

1. **One HTTP framework**: `hanzoai/zip` (Fiber v3) for the entire HTTP surface. Typed handlers via `zip.Get[In, Out]` / `zip.Post[In, Out]`, JSON-at-edge, 1 goroutine per conn per `SCALE_STANDARD`. No Beego, no chi, no gin, no net/http hand-routing, no `AdaptNetHTTP` shims. Aliases live in zip middleware, not duplicated in two routers.
2. **One storage stack, two orthogonal layers**:
   - **`hanzoai/orm`** — typed Go records, KV cache, memory cache. Wraps SQLite/Postgres uniformly; v2 uses SQLite. All non-collection reads/writes (token store, JWKS cache, session probes, anything in the hot path of `/oauth/token`) go through `orm` so the KV cache covers them.
   - **`hanzoai/base`** — collections, realtime feed, admin SPA mount, replicate-to-S3 sidecar. The 13 v2 collections live here.
   Both, orthogonal, not one-or-the-other. No xorm, no `hanzoai/dbx` direct imports, no Postgres anywhere in v2.
3. **One OIDC server — ours, in-tree**. Port the existing OIDC server logic from Beego to `hanzoai/zip` handlers:
   - `controllers/auth.go` → `internal/v2/oidc/auth.go` (authorization endpoint, token endpoint, refresh, device, revoke, introspect, userinfo, end-session)
   - `controllers/wellknown_oidc_discovery.go` → `internal/v2/oidc/discovery.go` (OIDC discovery doc)
   - `controllers/wellknown_oauth_prm.go` → `internal/v2/oidc/prm.go` (RFC 9728 protected resource metadata)
   - `object/wellknown_oidc_discovery.go` → `internal/v2/oidc/metadata.go` (RFC 8414 server metadata)
   - `object/jwt_mldsa65.go` → `internal/v2/oidc/jwt.go` (ML-DSA-65 / FIPS 204 post-quantum JWT signing — keep classical RSA dual track for clients that don't yet validate PQ algorithms)
   - `object/jwks_cache.go` → `internal/v2/oidc/jwks.go` (precomputed JSON bytes per app key; this is the cache that makes `/jwks` <1µs)
   No external OIDC library, no third-party OAuth/OIDC SDK, no provider daemons. The protocol surface and the RFC behavior already live in our tree — the port is Beego→zip, not a rewrite.
4. **One admin UI**: `@hanzo/gui` admin app under `gui/apps/admin-iam/`. The Radix tree under `web/` is decommissioned at Phase 4.
5. **One binary**: `ghcr.io/hanzoai/iam:vX.Y.Z`. Same image runs solo (embedded SQLite) and multi‑tenant (per‑org SQLite shards). Same env contract.

---

## 3. Decision points (need owner sign‑off before Phase 1)

These are the only open questions. Each has a recommendation; explicit "approved" is required before any Phase 1 code lands.

### 3.1 Storage: `hanzoai/orm` + `hanzoai/base` (already decided — confirming)

`LLM.md` already declares Base/SQLite. v2 nails down the layering: `hanzoai/orm` for typed Go records + KV cache, `hanzoai/base` for collections + realtime + admin SPA. Both, orthogonal.

**Recommendation: `hanzoai/orm` (typed Go records, KV cache) layered with `hanzoai/base` (collections, realtime, replicate-to-S3). Approve.**

Reasoning:

- `hanzoai/orm` (`~/work/hanzo/orm`) is the canonical Hanzo ORM — generics-based, KV-cache-aware, adapter-pluggable. Every hot-path read in v2 (`/oauth/token` cert lookup, `/oauth/userinfo` user-by-sub, JWKS-by-app, refresh-token-by-jti) goes through orm so the KV cache covers it. orm wraps SQLite and Postgres uniformly; v2 uses SQLite.
- `hanzoai/base` (`~/work/hanzo/base`) brings the collection model, the realtime feed, the admin SPA mount point, and the replicate-to-S3 WAL sidecar. The 13 v2 collections (users, organizations, applications, providers, roles, permissions, certs, keys, sessions, tokens, webhooks, invitations, audit_logs) are Base collections. Base sits over the same SQLite file orm reads from — `base.App.DB()` and the orm DB handle point at the same database. The two layers are orthogonal: orm gives us type-safe Go records and KV caching; base gives us collection semantics, realtime, and admin tooling. There is no overlap to resolve.
- Per-org SQLite shard pattern (already specified in `LLM.md` §Storage) horizontally partitions write load. Even at 10k orgs the single-node IO ceiling is read-amplified through Quasar replication, not write-amplified through one table.
- The hot path at `hanzo.id` is `/oauth/token` (signature, no DB if the cert is in the orm KV cache) and `/oauth/userinfo` (one indexed orm read, cached). SQLite handles 50k QPS of indexed reads on a single VM; the workload is nowhere near that, and the KV cache shaves another order of magnitude.
- Sessions and short-lived OAuth codes live in a separate SQLite file with WAL pragma `synchronous=NORMAL`; their durability window is short enough that the WAL fsync rate is not the bottleneck.
- Postgres would be a second source of truth (Casdoor's xorm tables + our application layer) and re-introduces network hops, connection pool tuning, and a separate backup path. Not worth it.

**Trade-off:** a single very-hot IAM cell maxes at one node's IO. Mitigation: shard by org *now* (already specified), rely on the orm KV cache for read amplification, and add a Quasar read-replica tier in Phase 5 if `hanzo.id` ever exceeds 10k QPS.

### 3.2 OIDC server logic: in-tree port (already decided — confirming)

**Recommendation: port the existing in-tree OIDC server from Beego to `hanzoai/zip`. No external OIDC library. Approve.**

Reasoning:

- The IAM repo *already* contains a complete, working, deployed OIDC server. RFC 6749 (auth code, refresh, client credentials), RFC 7009 (revocation), RFC 7662 (introspection), RFC 8628 (device authorization), RFC 7591 (dynamic client registration), OIDC core, OIDC discovery, RFC 8414 (server metadata), RFC 9728 (protected resource metadata), RFC 7033 (WebFinger) — all served from the controllers + object trees enumerated in §2 above.
- We ALSO carry value that no external library has: ML-DSA-65 (FIPS 204) post-quantum JWT signing via `object/jwt_mldsa65.go`, the precomputed-bytes JWKS cache in `object/jwks_cache.go`, the multi-org token signing-method gate, and the `hanzo.id` white-label discovery doc shape. Dropping any external library in would require us to either lose those features or maintain a heavy fork — both worse than the port.
- The 35k-LOC `object/` tree we're retiring is the **xorm/CRUD/business-logic** layer, not the protocol layer. The protocol layer is ~3k LOC across `controllers/auth.go`, `controllers/wellknown_*`, `object/jwt_*`, `object/jwks_cache.go`, `object/wellknown_oidc_discovery.go`. That code is *good* — it's the Beego scaffolding around it that has to go.
- Port path: each protocol handler becomes a typed `zip.Post[In, Out](app, "/v1/iam/oauth/token", handler)` over a thin storage adapter (`internal/v2/oidc/storage.go`) that reads/writes Base collections via `hanzoai/orm`. The handler bodies move verbatim modulo Beego→zip request/response idioms. No new RFC implementations.

**Trade-off:** we own every RFC behavior ourselves. Mitigation: the protocol layer already passes the v1 e2e suite (`tests/iam-e2e.spec.ts`, `tests/iam-login.spec.ts`); Phase 2 reuses that suite as the parity gate. We are not writing new protocol code, we are moving existing protocol code from Beego routes to zip routes.

**SAML IdP:** stays in-tree the same way. The current SAML controllers (with `crewjam/saml` as the wire-format dependency, same as today) port to `internal/v2/saml/` alongside the OIDC port. No new SAML implementation.

### 3.3 Migration data path: live vs side‑by‑side

**Recommendation: side‑by‑side, read‑only first; one‑shot import at cutover. Approve.**

Reasoning:

- The v1 Casdoor data lives in xorm tables. The v2 data lives in Base collections. They are not the same schema.
- Phase 0 ships a `iam-v2 compare` CLI that opens both stores read‑only and diffs row counts per logical entity (users, orgs, applications, providers). Drift detection runs continuously in dev/test; it never touches prod.
- Cutover (Phase 5) is a single offline import: stop writes on v1, run `iam-v2 import --source=v1`, verify count parity, flip the DNS at `hanzo.id` from v1 binary to v2 binary. Maintenance window: 30 min.
- We do **not** do live dual‑write. Dual‑write is what Casdoor's `sync_v2/` tree was built for and that tree is one of the reasons this repo is 50k LOC of Go.

**Trade‑off:** 30 min planned downtime at cutover. Acceptable; OAuth tokens are pre‑minted and outlive the gap.

### 3.4 Module path

**Recommendation: stay on `github.com/hanzoai/iam` v1.x.x. No `/v2` module path.** (Mandatory per global rules.)

`cmd/iam-v2/` is a binary name. Internal v2 code lives at `internal/v2/`, not at a new module path. When Phase 5 cuts over, the v1 controllers and object trees are deleted in one commit and what was `internal/v2/` is hoisted to the right place. Versioning continues `v1.18.x → v1.19.0` at cutover; no v2 tag is ever published.

### 3.5 Admin UI port

**Recommendation: net‑new `gui/apps/admin-iam/` consuming `@hanzo/gui` `ui-admin` package. Approve.**

The existing `web/` tree under IAM (Vite + Radix + 100k LOC) is a fork of Casdoor's admin. It will not be ported — it will be replaced by a thin `@hanzo/gui` admin app that talks to the `/v1/iam/*` API. The two coexist during Phase 1–3 (v1 admin keeps working against v1 backend; v2 admin built alongside v2 backend). v1 admin is deleted at cutover.

---

## 4. Domain model mapping

Casdoor object (`object/*.go`) → Base collection. All names lowercase plural, snake_case, per Base conventions. All carry `createdAt`/`updatedAt` (Base‑native timestamp fields) and a `deleted` soft‑delete flag.

| v1 object | v2 collection | Notes |
|---|---|---|
| `user.go` | `users` | adds `password_hash` (Argon2id), `mfa_secret`, `webauthn_credentials` ref. v1's per‑provider profile columns collapse into a `linked_identities` join table. |
| `organization.go` | `organizations` | per‑org SQLite shard keyed by `slug`. |
| `application.go` | `applications` | provider list moves out to `application_providers` join; redirect URIs and scopes become typed columns. |
| `provider.go` | `providers` | one row per IdP (GitHub, Google, Microsoft, SAML, OIDC) with typed config blob. |
| `role.go` | `roles` | authz policy column is dropped — see 4.1 below. |
| `permission.go` | `permissions` | same shape; enforcement moves to `hanzoai/authz`. |
| `cert.go` | `certs` | per‑org signing cert pairs; current + previous slots for JWKS rotation. |
| `key.go` | `keys` | API keys + access tokens that never get refresh tokens (machine identity). |
| `webauthn` columns on user | `webauthn_credentials` | normalized; one row per registered key. |
| `session.go` | `sessions` | server‑side session table (browser cookies); short TTL (24h max). |
| `token.go` | `tokens` | OAuth access + refresh tokens. Refresh tokens persist; access tokens are JWTs and **not** stored (we verify via signature). |
| `record.go` | `audit_logs` | append‑only; written via Base event hook on every state‑changing handler. |
| `model.go` (authz model) | **removed** | policy model lives in `hanzoai/authz` (already a separate service). v2 stores the model name only; the engine is remote. |
| `enforcer.go` | `enforcers` | thin pointer to authz service. |
| `adapter.go` | **removed** | xorm adapter for the v1 in-process authz engine disappears with xorm. |
| `syncer*.go` (ldap, awsiam, dingtalk, …) | **deferred** | external identity sync is a Phase 3 problem; v2 ships without it and the v1 sync pipeline keeps running until then. |
| `ticket.go` | `tickets` | invitations/recovery tickets; one row, 24h TTL. |
| `invitation.go` | `invitations` | org‑to‑user join queue. |
| `webhook.go` | `webhooks` | outbound notification config. |
| `payment/plan/product/order/subscription/transaction/pricing.go` | **removed** | not IAM's job; move to commerce service (`~/work/hanzo/commerce`) before v2 cuts over. |
| `resource.go` | `resources` | uploaded file metadata. |
| `cred/`, `face/`, `captcha/`, `idv/` | external | wrappers around third‑party SDKs; treated as providers in v2. |

### 4.1 Authz separation (decomplect)

v1 has the policy engine, model, adapter, enforcer all braided into the IAM binary (descended from the fork that became `hanzoai/authz`). v2 splits cleanly:

- IAM owns the **subjects** (users, roles, role membership).
- `hanzoai/authz` owns the **policy engine** (model + decisions). Single canonical authz library, same module path everywhere.
- v2 IAM publishes role/membership changes to authz over ZAP RPC; authz answers `enforce(subject, object, action)` over ZAP RPC.

This is the single most important value of the migration: authentication (who you are) stops being braided with authorization (what you can do). Each does one thing.

---

## 5. Endpoint mapping (HIP‑0026)

Canonical surface stays at `/v1/iam/*`. Legacy v1 aliases keep working via the `pathRewrite` middleware (single rewrite table in `internal/v2/middleware/path_rewrite.go`, replacing the v1 `routers/path_rewrite_filter.go`).

### 5.1 OIDC surface (in-tree, mounted on `hanzoai/zip`)

Every handler below is the ported-to-zip form of an existing in-tree controller. Handler bodies move verbatim; the registration changes from a Beego `// @router` annotation to a typed zip mount. The post-quantum signing path (ML-DSA-65) and the precomputed-JSON JWKS cache come along untouched.

| Endpoint | Method | Notes | v1 source |
|---|---|---|---|
| `/v1/iam/oauth/authorize` | GET | PKCE supported; auth code flow only (implicit removed) | `controllers/auth.go` |
| `/v1/iam/oauth/token` | POST | grants: authorization_code, refresh_token, client_credentials, device_code | `controllers/auth.go` |
| `/v1/iam/oauth/userinfo` | GET/POST | bearer‑validated | `controllers/auth.go` |
| `/v1/iam/oauth/introspect` | POST | RFC 7662 | `controllers/auth.go` |
| `/v1/iam/oauth/revoke` | POST | RFC 7009 | `controllers/auth.go` |
| `/v1/iam/oauth/device` | POST | RFC 8628 | `controllers/auth.go` |
| `/v1/iam/oauth/register` | POST | RFC 7591 dynamic client registration | `controllers/auth.go` |
| `/v1/iam/oauth/logout` | POST | end‑session | `controllers/auth.go` |
| `/v1/iam/.well-known/openid-configuration` | GET | discovery | `controllers/wellknown_oidc_discovery.go` + `object/wellknown_oidc_discovery.go` |
| `/v1/iam/.well-known/jwks` | GET | current + previous key; ML-DSA-65 + RSA dual track; cache via `object/jwks_cache.go` (precomputed JSON bytes per app key) | `object/jwks_cache.go` |
| `/v1/iam/.well-known/oauth-authorization-server` | GET | RFC 8414 | `object/wellknown_oidc_discovery.go` |
| `/v1/iam/.well-known/oauth-protected-resource` | GET | RFC 9728 | `controllers/wellknown_oauth_prm.go` |
| `/v1/iam/.well-known/webfinger` | GET | RFC 7033 | `controllers/` (existing) |

### 5.2 Application surface (mounted on `hanzoai/zip`)

The 239 v1 routes collapse to RESTful resources under `/v1/iam/<resource>`. Each handler is a typed `zip.Get[In, Out]` / `zip.Post[In, Out]` form so OpenAPI 3.1 spec auto-generates at `/v1/iam/v2/docs`. The dash‑verb shape (`/get-user`, `/add-user`, `/update-user`, `/delete-user`) of the v1 surface is dropped; rewrites in middleware preserve it during transition.

| Resource | Verbs | v1 routes collapsed |
|---|---|---|
| `users` | GET list/one, POST, PATCH, DELETE | `/get-users`, `/get-user`, `/add-user`, `/update-user`, `/delete-user`, `/check-user-password`, `/set-password`, `/get-account` |
| `organizations` | GET list/one, POST, PATCH, DELETE | `/get-organizations`, `/get-organization`, `/add-organization`, `/update-organization`, `/delete-organization` |
| `applications` | GET list/one, POST, PATCH, DELETE | `/get-applications`, `/get-application`, `/add-application`, `/update-application`, `/delete-application`, `/get-app-login` |
| `providers` | GET list/one, POST, PATCH, DELETE | `/get-providers`, `/get-global-providers`, `/get-provider`, `/add-provider`, `/update-provider`, `/delete-provider` |
| `roles` | GET list/one, POST, PATCH, DELETE | `/get-roles`, `/get-role`, `/add-role`, `/update-role`, `/delete-role`, `/get-all-roles` |
| `permissions` | GET list/one, POST, PATCH, DELETE | `/get-permissions*`, `/get-permission`, `/add-permission`, `/update-permission`, `/delete-permission` |
| `certs` | GET list/one, POST, PATCH, DELETE | `/get-certs`, `/get-cert`, `/add-cert`, `/update-cert`, `/delete-cert`, `/update-cert-domain-expire` |
| `keys` | GET list/one, POST, PATCH, DELETE | `/get-keys`, `/get-key`, `/add-key`, `/update-key`, `/delete-key` |
| `sessions` | GET list/one, DELETE | `/get-sessions`, `/get-session`, `/add-session`, `/update-session`, `/delete-session`, `/is-session-duplicated` |
| `tokens` | GET list/one, DELETE | `/get-tokens`, `/get-token`, `/add-token`, `/update-token`, `/delete-token` |
| `webhooks` | GET list/one, POST, PATCH, DELETE | `/get-webhooks`, `/get-webhook`, `/add-webhook`, `/update-webhook`, `/delete-webhook` |
| `invitations` | GET list/one, POST, PATCH, DELETE | `/get-invitations`, `/get-invitation`, `/add-invitation`, `/update-invitation`, `/delete-invitation`, `/send-invitation`, `/verify-invitation` |
| `tickets` | GET list/one, POST | `/get-tickets`, `/add-ticket`, `/add-ticket-message`, `/delete-ticket`, `/update-ticket` |
| `audit_logs` | GET list/one | `/get-records`, `/get-record` (read‑only) |
| `mfa` | POST setup/verify, DELETE | `/mfa/setup/{initiate,enable,verify}`, `/set-preferred-mfa`, `/delete-mfa/` |
| `webauthn` | POST | `/webauthn/{signin,signup}/{begin,finish}` |
| `verification` | POST | `/send-verification-code`, `/verify-code`, `/verify-captcha`, `/verify-identity/*` |

Routes that **stay verb‑shaped** because they are RPC‑style, not REST‑style:
`/login`, `/logout`, `/signup`, `/Callback`, `/grant-consent`, `/revoke-consent`, `/impersonation-user`, `/exit-impersonation-user`, `/enforce`, `/batch-enforce` (last two proxy to authz), `/sync-init-data`, `/sync-ldap-users`, `/run-syncer`, `/sso-logout`, `/kerberos-login`, `/userinfo` (the legacy alias of `/oauth/userinfo`).

### 5.3 ZAP RPC surface — inter-service is ZAP-native, not HTTP

All in-cluster service-to-service traffic between IAM and downstream services (commerce, gateway, KMS, MPC, ATS, anything that needs to look up a user/org/role) uses native ZAP binary RPC (`github.com/luxfi/zap`), not HTTPS. ZAP binds on `:9653`, a separate listener, registered via `app.ZAPRegistry()` on the same `*zip.App` as the HTTP listener. One binary, two listeners, one source of truth.

Why: HTTP for inter-service inside a cluster pays JSON-encode, JSON-decode, TLS handshake (when used), and connection setup costs on every hop. ZAP is the binary protocol the Lux/Hanzo stack already uses for in-cluster service mesh — it's faster, smaller, and the wire is type-checked. The HTTP `/v1/iam/*` surface stays the external interface; ZAP is the internal interface.

Methods exposed on `:9653`:

- `AuthService.GetToken(req) → token` — client_credentials grant via binary RPC for in-cluster service mesh
- `AuthService.IntrospectToken(token) → claims` — validate a JWT and return claims; downstream services call this on every request (no shared secret)
- `AuthService.GetJWKS() → keys` — fan-out the JWKS for downstream JWT validators that prefer a push over a pull
- `AdminService.GetUser(id) → user` — admin read-only (e.g. commerce looking up a user record for invoice attribution)
- `AdminService.GetOrg(slug) → org` — org lookup by slug
- `AdminService.GetRoles(userId) → []role` — role membership read

Downstream services consume these via the corresponding ZAP client stubs generated from the same RPC schema. No `/v1/iam/users/{id}` HTTP calls from inside the cluster.

---

## 6. Phased rollout

Each phase ships as a separate PR. No phase merges to `main` until the previous one's tests pass on CI and Playwright e2e is green against the dev environment.

### Phase 0 — Scaffold (this PR)

- New directory tree at `cmd/iam-v2/`, `internal/v2/`, `Dockerfile.v2` — purely additive.
- `iam-v2` binary boots, mounts Base, registers the 13 collections (idempotent, safe to run against a fresh DB), serves `/v1/iam/v2/health`.
- `iam-v2 compare --legacy=<dsn>` CLI: opens v1 xorm DB read‑only, opens v2 SQLite read‑only, prints per‑entity row counts and drift.
- Not deployed. Not in any production manifest. `Dockerfile` (the v1 one) is untouched.

**Effort: 1–2 days.** This PR is that scaffold.

### Phase 1 — Read‑write CRUD on `users`, `organizations`, `applications`, `roles`, `permissions`, `keys`

- Port each resource one at a time. Resource handler is ~80 LOC of zip; collection definition is ~40 LOC of Base; together they replace ~1500 LOC of the v1 controller + xorm tree.
- All handlers use `zip.Get[In, Out](app, path, fn)` typed form so OpenAPI 3.1 spec auto‑generates at `/v1/iam/v2/docs`.
- Authz checks lift out to a `requireRole(...)` zip middleware that calls `hanzoai/authz` over ZAP.
- v2 runs alongside v1 on a separate port in dev. Side‑by‑side comparison test asserts API parity.

**Effort: 3 weeks.** Six resources × 3 days each, plus middleware extraction.

### Phase 2 — OIDC server (in-tree port from Beego to `hanzoai/zip`)

- Port `controllers/auth.go` (authorize/token/userinfo/introspect/revoke/device/register/logout) from Beego routes to typed `zip.Get[In, Out]` / `zip.Post[In, Out]` handlers under `internal/v2/oidc/`. Handler bodies are copied verbatim; only the request/response surface changes.
- Port `controllers/wellknown_oidc_discovery.go`, `controllers/wellknown_oauth_prm.go`, and `object/wellknown_oidc_discovery.go` to `internal/v2/oidc/discovery.go` + `prm.go` + `metadata.go`.
- Port `object/jwt_mldsa65.go` (ML-DSA-65 / FIPS 204 post-quantum JWT signing) to `internal/v2/oidc/jwt.go`. Classical RSA dual track stays for clients that don't yet validate PQ algorithms.
- Port `object/jwks_cache.go` (precomputed JSON bytes per app key) to `internal/v2/oidc/jwks.go`. The cache is the hot path of every JWT-validating consumer (KMS, MPC, gateway); the rewrite is byte-for-byte equivalent.
- Build the storage adapter at `internal/v2/oidc/storage.go` that reads/writes Base collections (users, tokens, sessions, codes) via `hanzoai/orm`. The adapter is the only new code in this phase; everything else is a port.
- Reuse v1 signing certs (read same KMS slot) so all outstanding JWTs continue to validate during transition.
- Test plan: every OIDC RFC scenario in the v1 e2e suite (`tests/iam-e2e.spec.ts`, `tests/iam-login.spec.ts`) must pass against v2 — same suite, new backend, same green.

**Effort: 4 weeks.** OIDC is where the protocol surface is widest; we don't rush this. But because the protocol code already exists and works, this is a port, not a rewrite — most of the time is in the parity gate, not in fresh code.

### Phase 3 — Providers and federation

- GitHub, Google, Microsoft, Apple, LinkedIn social providers (~80% of inbound logins).
- SAML IdP via `crewjam/saml` mounted under `/v1/iam/saml/*`.
- LDAP server keeps `hanzoai/ldapserver` for now; gets a thin adapter to v2 user storage.
- SCIM 2.0 server via `elimity-com/scim` (already a dep), backed by v2 user storage.
- Syncers (LDAP autosync, Azure AD, Okta, Google Workspace, AWS IAM, DingTalk, Keycloak, Lark, WeCom) deferred to Phase 3.5 if needed; in practice these are used by ≤3 tenants and can stay on v1 until tenants are migrated.

**Effort: 3 weeks** (without syncers). +2 weeks if all syncers ported.

### Phase 4 — `@hanzo/gui` admin UI

- New app at `~/work/hanzo/gui/apps/admin-iam/` consuming `@hanzo/gui` `ui-admin`.
- Each resource gets one screen; screens are generated from the OpenAPI spec where possible.
- Login screen is a thin redirect to `/v1/iam/oauth/authorize` — no embedded credential form (HIP‑0026 standard).
- v1 React admin under `web/` is *not* updated; it freezes at last v1 patch and gets deleted at Phase 5.

**Effort: 4 weeks.** Mostly translation work — designs already exist in the v1 admin.

### Phase 5 — Cutover

- v1 admin (`web/`) deleted in one commit.
- v1 controllers (`controllers/*.go`) and v1 objects (`object/*.go` except shared types) deleted.
- `cmd/iamd/` deleted; `cmd/iam-v2/` → `cmd/iamd/`.
- `internal/v2/` hoisted to canonical locations (`internal/oauth/`, `internal/storage/`, etc.).
- `Dockerfile.v2` → `Dockerfile`.
- Version bumps `v1.18.x → v1.19.0` (no v2 tag, ever).
- Maintenance window: 30 min. Pre‑flight import via `iam-v2 import --source=v1` against a snapshot of v1 prod DB taken 24h prior; differential replay during the window covers the gap.

**Effort: 1 week** (mostly waiting and verifying).

### Total

~16 weeks elapsed engineering, single owner. With one full‑time dev + CTO review, 4 months end‑to‑end.

---

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| OIDC parity drift — clients break at cutover | Phase 2 has explicit e2e parity gate. The Beego→zip port + the orm storage adapter must satisfy every existing client (KMS, gateway, all SPAs) before Phase 3 starts. Because the protocol handlers are ported verbatim, parity drift can only come from the storage adapter — narrowing the surface to test. |
| Per‑org SQLite shards don't scale | Built‑in mitigation: Quasar read‑replica + S3 WAL replicate already designed. If `hanzo.id` exceeds 10k QPS post‑cutover, enable `BASE_NETWORK=quasar` peer fan‑out. |
| Federation provider catalog is huge | Treat as feature flags. Phase 3 ships only the top 5 providers (GitHub, Google, Microsoft, Apple, LinkedIn); the long tail (DingTalk, Lark, WeCom, RADIUS, Kerberos) defers and v1 keeps serving those tenants until they request migration. |
| Cutover window collides with peak traffic | Window is 30 min, scheduled Saturday 03:00 PT. Pre‑minted JWTs (1h TTL on hanzo.id, 24h on KMS service tokens) span the gap. |
| Existing v1 has historical password hashes that aren't Argon2id | One‑shot rehash on first login: when a user authenticates with a bcrypt/md5 v1 hash, verify against the legacy hash, then immediately rewrite the column to Argon2id. After 90 days post‑cutover, force‑rotate any remaining non‑Argon2id hashes. |
| authz model migration is non‑trivial | Decision §4.1 already extracted: the engine moves to `hanzoai/authz` *now*, not at cutover. Phase 1 includes the ZAP RPC adapter; the v1 in-process authz code is deleted in Phase 5 along with everything else. |
| External brand contamination in tests/data | `tests/` and `web/` carry upstream-fork brand references in places. Scrub during Phase 4 along with UI port. |

---

## 8. What this is NOT

- Not a rewrite of `hanzoai/authz`. Authz already exists; v2 IAM just consumes it.
- Not a rewrite of `hanzoai/kms`. KMS already exists; v2 IAM continues to source signing‑key bytes from it.
- Not a rewrite of `@hanzo/gui`. v2 admin is an *application of* `@hanzo/gui`, not a new GUI library.
- Not introducing Postgres. Base/SQLite remains the only storage path.
- Not introducing Helm. Kustomize remains.
- Not introducing a `v2` module path. The Go module stays at `github.com/hanzoai/iam` v1.x.x.

---

## 9. Phase 0 deliverable (this PR)

```
cmd/iam-v2/
  main.go                  — boots base.App, mounts /v1/iam/v2/*, prints config
  go.mod                   — pins hanzoai/orm + hanzoai/zip + hanzoai/authz + hanzoai/base direct
  internal/
    stack/
      stack.go              — declared-and-pinned stack imports (orm, zip, authz)
    schema/
      schema.go              — 13 collections, idempotent register
    routes/
      health.go              — /v1/iam/v2/health
    compare/
      compare.go             — read-only drift CLI (v1 Beego/xorm DB vs Base SQLite)
Dockerfile.v2              — alpine + iam-v2 binary; not deployed
MIGRATION.md               — this file
```

Nothing in this scaffold is wired into the live IAM binary or production manifests. `iamd` (v1) is untouched. The v2 binary builds and runs locally; CI builds the v2 image alongside v1 but does not publish it.

Stack dependencies are direct deps in `cmd/iam-v2/go.mod` from Phase 0 — `hanzoai/orm v0.5.2`, `hanzoai/zip v0.2.0`, `hanzoai/authz v1.10.0`, `hanzoai/base v1.3.0` — even though Phase 0 itself only exercises `hanzoai/base`. This is intentional: the stack contract is observable in `go.mod` from the moment this PR opens, and Phase 1 work can begin without touching `require` again.

Sign‑off required before Phase 1 PR opens.
