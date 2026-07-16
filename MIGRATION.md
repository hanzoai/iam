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
| 0 | Scaffold: Base boots, v2 collection namespace claimed, `/healthz`, `compare` CLI. | Binary builds and boots. |
| 1 | Entity schemas (fields + indexes) + CRUD handlers on `zip` + `orm`, per resource. | Per-entity field parity vs v1; handlers pass tests. |
| 2 | In-tree OIDC/OAuth2 server: `/v1/iam/oauth/*`, `/v1/iam/.well-known/*`, JWT (ML-DSA-65), JWKS. | Token/userinfo/authorize parity vs v1. |
| 3 | Authz via `hanzoai/authz` over ZAP RPC; retire in-process authz. | Policy decisions match v1. |
| 4 | Parity: run `iam2 compare` continuously against a v1 read replica. | **drift = 0** (or a known v1-only residual v2 does not model). |
| 5 | Cutover: import v1 data, promote `iam2` to the `iam` mount, archive the fork. | Green in prod; rollback path proven. |

Phases 0–4 are additive and non-destructive — v1 stays live and authoritative
until Phase 5. Routes carry a `/v1/iam/*` prefix through the transition so
they are orthogonal to the live `/v1/iam/*` mount; the prefix collapses at §6.

**Phase 1 blocker — login verifies with bcrypt only; live rows are BOTH argon2id and bcrypt.**
`users.VerifyPassword` (`internal/users/users.go`) calls `bcrypt.CompareHashAndPassword`
unconditionally, and it is the only path credential login takes (`internal/oidc/login.go`).
Handed an argon2id PHC string bcrypt returns `ErrHashTooShort`, so every argon2id
user fails login. v1 resolves the algorithm per row: `object/check.go` reads
`user.PasswordType`, falling back to `organization.PasswordType`, then dispatches
through `cred.GetCredManager`. The hash algorithm is a property of the stored row,
never a constant.

*Measured against the live prod store (2026-07-16), not inferred.* The earlier
claim here — "every live v1 row is argon2id, so bcrypt can be deleted" — is
**false**, and deleting the bcrypt path would have broken more logins than it
fixed. Read via the product's own read-only codec (`iam orgdb query`, HKDF KEK →
AES-GCM DEK unwrap → SQLCipher) across all 114 per-org DBs in `hanzo/iam`
(`v1.31.27`), classifying by the hash bytes themselves:

| stored hash | users | note |
|---|---:|---|
| `argon2id` (`m=65536,t=1,p=2`) | 85 | `alexedwards/argon2id` `DefaultParams` |
| *(empty)* | 63 | federated/OAuth — no credential login |
| `bcrypt` (`$2a$10$`×24, `$2b$10$`×15, `$2b$12$`×1) | 40 | **still live** |

Why bcrypt survives: `sanitizeOrgPasswordType` rewrites the **organization**'s
type, and `UpdateUserPassword` only re-stamps a **user**'s row when that user's
password is next written. A user whose password has not changed keeps its bcrypt
digest indefinitely — 3 orgs are still `bcrypt` outright. So both algorithms must
verify, and bcrypt rows only ever migrate if login rehashes them.

Consequences for iam2, all load-bearing:
1. **Verify must dispatch on the hash bytes, not a type column.** The digest is
   self-describing (`$argon2id$…` / `$2a$|$2b$|$2y$…`). `PasswordType` is a second
   source of truth that can disagree with the bytes it describes — it is not read
   on the verify path.
2. **Params come from the stored hash, never from a constant.** Live rows are
   `m=65536,t=1,p=2`; the current OWASP recommendation is different. Hardcoding
   today's params on the verify path would fail all 85 argon2id rows.
3. **Rehash-on-login is required, not optional** — it is the only thing that
   retires the 40 bcrypt rows. (This supersedes the earlier "verify-only" note:
   that was written believing no bcrypt rows existed.)

This is the sharpest reason parity is proven by `compare` against real rows, not
by tests over rows iam2 wrote itself — a round-trip test of our own hasher passes
happily while every live login is broken.

**Phase 2 residual — the front door (blocks Phase 5).** The OIDC/OAuth2 protocol
surface is complete, but HIP-0111 §6's *native front-door* surface — what the
hosted portal at `hanzo.id` itself calls, as distinct from the OIDC surface
client apps use — is not. Present: `get-app-login`, `login`. Missing: `signup`,
`send-verification-code`, `get-account`, `userinfo` (native), `logout` (native).
A backend swap without these takes the portal's signup, email verification,
account page, and sign-out with it, so cutover is gated on them regardless of
drift. Serve them under `/v1/iam/*` per HIP-0111 §6 — no `/api/`, no new prefix.

Three facts the port must honour, each verified against live v1:
- `get-account` is not just the portal's session read — the gateway's admin-guard
  derives the **SuperAdmin predicate** from it (`gateway/cmd/admin-guard/main.go`)
  and waitlist-guard derives **approval** from it. Its response shape is a
  security contract, not a convenience.
- `send-verification-code` takes **multipart/form-data**, not JSON.
- Native `userinfo` and `logout` are **aliases** of the `oauth/*` handlers
  (`routers/router.go` + `authz_filter.go` collapse them onto one handler each) —
  register the alias, never fork a second implementation.

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
