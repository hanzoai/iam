# IAM v2 Migration

Casdoor fork (`hanzoai/iam`: Beego + xorm, Apache-2.0) → `hanzoai/iam2`:
clean-room, proprietary, on the native Hanzo stack. Phased and drift-gated —
the identity binary is never rewritten in one shot.

## §1 Why

`hanzoai/iam` is a fork of Casdoor. Every file carries `Portions Copyright The
Casdoor Authors` under Apache-2.0. It couples us to xorm's fluent API, Beego's
router, and an upstream we do not control. `iam2` is original expression on our
own framework — we own it, and it collapses to one way of doing each thing.

## §2 Stack contract

- **HTTP** — `github.com/zap-proto/zip` (typed `zip.Get[In,Out]` handlers on the
  `zap-proto/fiber/v3` engine, specificity routing, OpenAPI 3.1 at the edge).
- **Storage** — `github.com/hanzoai/orm` (typed Go records + KV cache) over
  `github.com/hanzoai/base` (collections, realtime, replicate-to-S3). SQLite —
  never Postgres for the local/default path.
- **Authz** — `github.com/hanzoai/authz`, one canonical policy engine, called
  over ZAP RPC. No in-process copy.
- **OIDC/OAuth2** — in-tree port (no external OIDC library). ML-DSA-65 hybrid
  JWT signing; JWKS cache.
- **Inter-service** — `github.com/luxfi/zap` binary RPC. HTTPS is the external
  edge only; all service↔service is ZAP (platform law).

## §3 Phases

| Phase | Scope | Gate to exit |
|------:|-------|--------------|
| 0 | Scaffold: Base boots, v2 collection namespace claimed, `/v1/iam/health`, `compare` CLI. | Binary builds and boots. |
| 1 | Entity schemas (fields + indexes) + CRUD handlers on `zip` + `orm`, per resource. | Per-entity field parity vs v1; handlers pass tests. |
| 2 | In-tree OIDC/OAuth2 server: `/v1/iam/oauth/*`, `/v1/iam/.well-known/*`, JWT (ML-DSA-65), JWKS. | Token/userinfo/authorize parity vs v1. |
| 3 | Authz via `hanzoai/authz` over ZAP RPC; retire in-process authz. | Policy decisions match v1. |
| 4 | Parity: run `iam2 compare` continuously against a v1 read replica. | **drift = 0** (or a known v1-only residual v2 does not model). |
| 5 | Cutover: import v1 data, promote `iam2` to the `iam` mount, archive the fork. | Green in prod; rollback path proven. |

Phases 0–4 are additive and non-destructive — v1 stays live and authoritative
until Phase 5. Routes carry a `/v1/iam/*` prefix through the transition so
they are orthogonal to the live `/v1/iam/*` mount; the prefix collapses at §6.

## §4 Domain model (v1 xorm table → v2 Base collection)

Thirteen identity entities. Field-completeness is mandatory — a dropped column
is lost auth data.

| v1 table (xorm)       | v2 collection (Base)   | Base kind |
|-----------------------|------------------------|-----------|
| `user`                | `users`                | auth      |
| `organization`        | `organizations`        | base      |
| `application`         | `applications`         | base      |
| `provider`            | `providers`            | base      |
| `role`                | `roles`                | base      |
| `permission`          | `permissions`          | base      |
| `cert`                | `certs`                | base      |
| `key`                 | `keys`                 | base      |
| `webauthn_credential` | `webauthn_credentials` | base      |
| `session`             | `sessions`             | base      |
| `token`               | `tokens`               | base      |
| `record`              | `audit_logs`           | base      |
| `invitation`          | `invitations`          | base      |

**Deliberately not modeled by iam2** (they belong to commerce/other services,
not identity): `payment`, `plan`, `product`, `subscription`, `pricing`,
`model`, `adapter`, `enforcer`, `syncer_*`.

## §5 Drift gate

`iam2 compare --legacy <v1-dsn>` opens the v1 database **read-only** (only
`SELECT COUNT(*)`), opens the v2 Base store read-only, and prints per-entity
row counts plus absolute drift. This is the gate that keeps cutover honest:
drift must be 0 before Phase 5 import goes live. No writes, no DDL, ever.

## §6 Cutover

At Phase 5, with drift proven 0: import v1 rows into v2 collections, repoint the `iam` image /
operator CR / DNS to `iam2`, and archive `hanzoai/iam`. One identity binary,
one way, no Casdoor.
