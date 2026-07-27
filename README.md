# Hanzo IAM

**Identity & access for the Hanzo cloud — OpenID Connect / OAuth2 with PKCE, standards only.**

![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8) ![Standards](https://img.shields.io/badge/standards-OIDC%20%C2%B7%20OAuth2%20%C2%B7%20SCIM%202.0-informational) ![License](https://img.shields.io/badge/license-proprietary-lightgrey)

Hanzo IAM is the identity service behind every Hanzo sign-in: OpenID Connect
discovery, the authorize + token endpoints (authorization code + PKCE, refresh,
`client_credentials`, RFC 8693 token exchange), UserInfo, JWKS, SCIM 2.0
provisioning, MFA / WebAuthn, service accounts, and social federation
(Google, GitHub).

It is a **clean-room, native rewrite** on the Hanzo stack — `zip` over
`hanzoai/orm`, **no Casdoor, no Beego, no xorm**. The identity binary owns its
source outright and collapses to one way of doing each thing. The retired
Casdoor/Beego fork lives at
[`hanzoai/iam-v1`](https://github.com/hanzoai/iam-v1) and is out of every graph.

Clients never hand-roll OAuth. They authenticate through the **`@hanzo/iam`
SDK** against the endpoints below — one way, no legacy paths (HIP-0111).

## Stack

| Concern | Component | Notes |
|---|---|---|
| HTTP | [`zap-proto/zip`](https://github.com/zap-proto/zip) | Typed `zip.Get[In,Out]` handlers on the `zap-proto/fiber/v3` engine; specificity routing; OpenAPI 3.1 at the edge |
| Storage | [`hanzoai/orm`](https://github.com/hanzoai/orm) | Typed Go records + KV cache over one `orm.DB` abstraction. Embedded SQLite by default (`hanzoai/sqlite`, pure-Go, WAL) — never Postgres |
| OIDC / OAuth2 | in-tree | RS256 today; ML-DSA-65 hybrid JWT + real JWKS from the Cert entity. No external OIDC library |
| Password verify | `internal/cred` | Algorithm resolved from the stored row — argon2id + bcrypt, verify-only, fail-closed |
| Authorization | [`hanzoai/authz`](https://github.com/hanzoai/authz) | One canonical policy engine, called over ZAP RPC |
| Inter-service | [`zap-proto`](https://github.com/zap-proto) | Binary RPC service↔service. HTTPS is the external edge only |

## Endpoints — RFC / OIDC standard (no `/api/`, no vendor verbs)

The HTTP contract is RFC/OpenID-standard only. There are no Casdoor verb aliases
(`get-users`, `add-user`, `issue-user-token`, …) and no `/api/` prefix — `/v1/`
throughout. Paths are relative to the brand `serverUrl`.

| Capability | Standard | Endpoint |
|---|---|---|
| Discovery / AS metadata | RFC 8414 · OIDC Discovery | `/.well-known/openid-configuration` |
| JWKS | RFC 7517 | `/v1/iam/.well-known/jwks` |
| Authorize | RFC 6749 (code + PKCE `S256`) | `/v1/iam/oauth/authorize` |
| Token | RFC 6749 (code, refresh, `client_credentials`, password) | `/v1/iam/oauth/token` |
| Token exchange / on-behalf-of | RFC 8693 | `/v1/iam/oauth/token` (`grant_type=…token-exchange`) |
| Introspection / revocation | RFC 7662 / RFC 7009 | `/v1/iam/oauth/{introspect,revoke}` |
| UserInfo (account claims) | OIDC UserInfo | `/v1/iam/oauth/userinfo` |
| Logout | OIDC RP-initiated logout | `/v1/iam/oauth/logout` |
| Identity provisioning | SCIM 2.0 (RFC 7644 / 7643) | `/v1/iam/scim/v2/Users` |
| Social sign-in / federation | OIDC/OAuth2 Relying Party | `/v1/iam/oauth/authorize?provider=<name>` → `/v1/iam/oauth/callback` |

PKCE `S256` always; `client_secret_basic`; scopes `openid profile email`.
`client_id` is `<org>-<app>` (globally unique); `redirectUris` must be the
framework's exact callback.

**Brands** (set `serverUrl`): hanzo → `iam.hanzo.ai` · lux → `lux.id` ·
zoo → `zoo.id` · bootnode → `id.bootno.de` · pars → `pars.id`. Shared infra
white-labels by domain — never the Hanzo mark on a Lux or Zoo surface.

## Storage — one `orm.DB`, backend-pluggable

Every handler and the drift tool are written once against `orm.DB`, never a
driver. Pick the backend at boot with `--store`:

- `sqlite` (default) — embedded, pure-Go, WAL. No Postgres.
- `sql` — `hanzoai/sql` over ZAP.
- `datastore` — `hanzoai/datastore` over ZAP (ZAP-native persistence +
  snapshots, zero code change).

## Build & run

```sh
go build ./...

# Seed real config + serve OIDC / login (SQLite by default)
go run . serve --init-data init_data.json

# ZAP-native persistence instead of embedded SQLite
go run . serve --store datastore --init-data init_data.json

# Read-only v1 → v2 drift report (needs a `-tags migration` build)
go run . compare --legacy postgres://…/iam

go run . version
```

`serve` flags: `--store` (`sqlite|sql|datastore`), `--db` (SQLite path),
`--zap` (ZAP listen), `--http` (HTTP edge), `--init-data` (new-only seed;
`${VAR}` expands from env). Deploy env: `IAM_ISSUER=https://<brand-id>`,
`IAM_KEY_MINT_ALLOWED_APPS`, `IAM_ADMIN_MINT_ALLOWED_APPS` (matched by the
globally-unique `client_id`).

The service is embeddable via `server.Route` and builds on Hanzo CI
(`ghcr.io/hanzoai/iam`).

## Client auth (HIP-0111)

Authenticate **only** through `@hanzo/iam` against the canonical OIDC endpoints —
no hand-rolled OAuth, no `genericOAuth({discoveryUrl})`, no per-app path strings,
no legacy paths. SDK subpaths cover every runtime: `@hanzo/iam/server`
(`validateToken` / `getServerSession`), `@hanzo/iam/betterauth`,
`@hanzo/iam/nextauth`, `@hanzo/iam/react` + `@hanzo/iam/browser` (SPA PKCE),
`@hanzo/iam/passport`. Keep `originFrontend` empty in prod so discovery is
host-relative.

## Status

OIDC/OAuth2 core is live and tested end to end (login → PKCE code → token → JWT):
discovery + JWKS, credential login (argon2id / bcrypt), the token endpoint,
introspection / revocation, UserInfo, RFC 8693 token exchange, SCIM 2.0
provisioning, and Google / GitHub federation. Current release line: `v1.33.x`.
See [MIGRATION.md](./MIGRATION.md) for the phased plan and the full RFC surface
table.

## License

Proprietary — see [LICENSE](./LICENSE). Confidential to Hanzo AI, Inc.

## Hanzo — the Open AI Cloud

Open source · every language · on-chain settlement. [hanzo.ai](https://hanzo.ai) · [docs.hanzo.ai](https://docs.hanzo.ai)

**SDKs in every language** — [Python](https://github.com/hanzoai/python-sdk) (flagship) · [TypeScript](https://github.com/hanzo-js/sdk) · [Go](https://github.com/hanzo-go/sdk) · [Rust](https://github.com/hanzo-rs/sdk) · [C++](https://github.com/hanzo-cpp/sdk) · [Swift](https://github.com/hanzo-swift/sdk) · [Kotlin](https://github.com/hanzo-kt/sdk) · [umbrella](https://github.com/hanzoai/sdk)
