# Hanzo IAM v2

Proprietary identity service for the Hanzo platform. A clean-room rewrite of the
identity layer on the native Hanzo stack — **no Casdoor, no Beego, no xorm**.

The predecessor (`hanzoai/iam`) is a fork of Casdoor (Apache-2.0). `iam2` owns
its source outright: original expression on our own framework and ORM, so the
identity binary carries no upstream copyright or license obligations.

## Stack

| Concern        | Component | Notes |
|----------------|-----------|-------|
| HTTP           | [`zap-proto/zip`](https://github.com/zap-proto/zip) | Typed handlers (`zip.Get[In,Out]`) on the `zap-proto/fiber/v3` engine; specificity routing; OpenAPI 3.1 |
| Storage        | [`hanzoai/orm`](https://github.com/hanzoai/orm) (embedded SQLite via hanzoai/sqlite) | Typed Go records + KV cache; typed Go records + KV cache; embedded SQLite (no Postgres), ZAP backends pluggable |
| Authorization  | [`hanzoai/authz`](https://github.com/hanzoai/authz) | One canonical policy engine, called over ZAP RPC |
| OIDC / OAuth2  | in-tree | ML-DSA-65 hybrid JWT; no external OIDC library |
| Inter-service  | `zap-proto` | Binary RPC. HTTPS is the external surface only |

## Status

OAuth2/OIDC core is live and tested (login → PKCE code → token → JWT): OIDC
discovery + JWKS, get-app-login + auth/methods, credential login (bcrypt,
email/username), the token endpoint (RS256 JWT), and init_data bootstrap that
seeds the real config (79 apps / 9 orgs). Embeddable via `server.Mount`. Builds
on Hanzo CI (`ghcr.io/hanzoai/iam2`).

See [MIGRATION.md](./MIGRATION.md) for the phased plan.

## Build & run

```sh
go build ./...
go run . serve --init-data init_data.json   # seed config + serve OIDC/login
go run . compare --legacy postgres://…/iam  # read-only v1 ↔ v2 drift report
```

## License

Proprietary — see [LICENSE](./LICENSE). Confidential to Hanzo AI, Inc.
