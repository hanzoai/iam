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
| Storage        | [`hanzoai/orm`](https://github.com/hanzoai/orm) over [`hanzoai/base`](https://github.com/hanzoai/base) | Typed Go records + KV cache; collections + realtime + replicate-to-S3; SQLite (no Postgres) |
| Authorization  | [`hanzoai/authz`](https://github.com/hanzoai/authz) | One canonical policy engine, called over ZAP RPC |
| OIDC / OAuth2  | in-tree | ML-DSA-65 hybrid JWT; no external OIDC library |
| Inter-service  | `luxfi/zap` | Binary RPC. HTTPS is the external surface only |

## Status

Phase 0. The binary boots Base, registers the v2 collection schema, serves
`/v1/iam/v2/health`, and ships a read-only drift CLI. Cutover off `hanzoai/iam`
is gated on `iam2 compare` reading **drift = 0** against a v1 replica.

See [MIGRATION.md](./MIGRATION.md) for the full phased plan.

## Build & run

```sh
go build ./...
go run . serve                              # Base + v2 schema + /v1/iam/v2/health
go run . compare --legacy postgres://…/iam  # read-only v1 ↔ v2 drift report
```

## License

Proprietary — see [LICENSE](./LICENSE). Confidential to Hanzo AI, Inc.
