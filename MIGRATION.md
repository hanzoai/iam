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

**Phase 1 blocker — RESOLVED (`internal/password`).** Login verified with bcrypt
only; live rows are BOTH argon2id and bcrypt.

`users.VerifyPassword` called `bcrypt.CompareHashAndPassword` unconditionally, and
it is the only path credential login takes (`internal/oidc/login.go`), so every
argon2id user failed login. (Handed an argon2id PHC string bcrypt does *not*
return `ErrHashTooShort` as first recorded — it reads the `a` of `$argon2id$` as
a version and returns `HashVersionTooNewError`. Same outage; the correct password
is rejected either way.) v1 resolves the algorithm per row: `object/check.go`
reads `user.PasswordType`, falling back to `organization.PasswordType`, then
dispatches through `cred.GetCredManager`. The hash algorithm is a property of the
stored row, never a constant.

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

The fix, in `internal/password` — the one place that mints a digest and the one
place that checks one. Nothing else in the tree imports a hash function:

1. **Verify dispatches on the hash bytes, not a type column.** The digest is
   self-describing (`$argon2id$…` / `$2a$|$2b$|$2y$…`). `PasswordType` is a second
   source of truth that can disagree with the bytes it describes, so it is not read
   on the verify path — and it is now *derived* from the digest (`password.Scheme`)
   wherever it is written, so it cannot contradict it.
2. **Params come from the stored hash, never from a constant.** Live rows are
   `m=65536,t=1,p=2`; our mint policy is the OWASP baseline `m=19456,t=2,p=1`.
   Parameters pinned into verify would fail all 85 argon2id rows.
3. **Rehash-on-login**, in `users.VerifyPassword` — the only thing that retires
   the 40 bcrypt rows, since a successful login is the only moment the plaintext
   exists to re-hash from. Best-effort: the password is already proven correct, so
   a storage failure must not fail the login. (This supersedes the earlier
   "verify-only" note, written believing no bcrypt rows existed.)
4. **Staleness is judged against an acceptance floor, not against mint policy.**
   The floor is the weakest of OWASP's five equivalent sets (`m=7168,t=5` → 35840
   KiB-passes, on the memory-time product). Comparing against mint policy instead
   would flag three of OWASP's own equivalent sets as stale *and* "upgrade" the
   live `m=65536,t=1` rows by halving their memory hardness — a downgrade wearing
   the word upgrade.

**Parameters, and why.** OWASP's baseline `m=19456 (19 MiB), t=2, p=1`, 16-byte
`crypto/rand` salt, 32-byte key. Measured at `GOMAXPROCS=2` — the iam pod's real
budget (2 CPU, 2 GiB, `GOMEMLIMIT=1750MiB`):

| operation | latency | memory/op |
|---|---:|---:|
| Hash (`m=19456,t=2,p=1`) | 13.5 ms | 19.9 MB |
| Verify live v1 (`m=65536,t=1,p=2`) | 16.6 ms | 67.1 MB |
| Verify bcrypt (cost 10) | 39.3 ms | 5.3 KB |

Argon2id at the baseline is ~3x **faster** than the bcrypt it replaces, so
retiring bcrypt costs no login latency. Memory is the exposed axis: of OWASP's
equivalent sets we take the cheap end of the memory range (`m=47104` is 2.4x the
footprint for the same work; `m=7168,t=5` is 2.5x the CPU on a 2-core box).
Because every in-flight argon2id hash holds its full `m`, and login is
unauthenticated, argon2id runs under a `GOMAXPROCS`-wide gate — without it ~26
concurrent logins against live-parameter rows reach `GOMEMLIMIT` and OOM the pod,
which is the one failure that logs everybody out at once. With `p=1` only
`GOMAXPROCS` hashes progress anyway, so the bound costs no throughput.

**Proven** (`go test -race ./...`): a digest minted by v1's exact pinned library
(`alexedwards/argon2id v0.0.0-20211130144151`, `DefaultParams` = the live
`m=65536,t=1,p=2`) verifies; both live shapes sign in through the real
`POST /v1/iam/login`; a fresh bootstrap signs in with no manual step; a bcrypt row
is re-minted in place and the same password still works. Testing only our own
hasher's round-trip would have passed while every live login was broken.

**Login is a writer now, and that is the sharp edge of rehash-on-login.** Before
`internal/password`, the login path only ever read. Point 3 above makes a
successful login write, and a write from the login path has the whole user row in
its blast radius: `orm`'s `Update` is a blind whole-entity `Put` — no dirty-field
tracking, no version, no CAS. Written naively, the sequence is *read → verify
(bcrypt ~39ms) → mint (~14ms) → write back the row you read 53ms ago*, which
silently reverts anything that landed in between. The scenario that matters is an
incident response: a responder forbids a compromised account, strips its admin
and rotates the password, while the attacker — who knows the password, which is
*why* it is being rotated — has a login in flight against a pre-revocation
snapshot. The revert restores admin, clears the forbid, and puts the leaked
password back, with no error and no audit signal. `login.go` does not gate on
`IsForbidden` (only `authz.go` does), so the reverted row is fully live.

`upgrade` therefore re-reads inside a transaction and writes only the three
fields it owns, with the digest it verified against as the precondition: if that
digest changed underneath, the other write is newer and wins. The mint stays
*outside* the transaction — the SQLite store serializes every writer in the
process for the life of a transaction, so minting inside would put password
hashing on the critical path of every unrelated write. This also collapses the
redundant writes when several logins race the same stale row: the first lands,
the rest decline. Only stale rows are ever written, so the exposure was exactly
the 40 bcrypt rows, and it self-heals as they migrate.

**The login must not answer whether an account exists.** Verifying is expensive
and *not* verifying is not, so a handler that short-circuits `user == nil` around
the hash tells the caller the account is absent by answering sooner. Measured
through the real router: 18.5ms for a real user with a wrong password against
92us for an absent one — 201x, no statistics needed. So an absent user is not a
special case: "there is no digest that matches this plaintext" is one question
with one answer, whether the row is missing, federated with no password, or
holding a different digest. `VerifyPassword` hands the absent user to `Verify` as
the empty digest, and `Verify` pays for a decoy rather than returning cheaply.
Ratio through the router afterwards: **0.95x**, and a federated row is 1.06x
against one holding a password.

The decoy runs through the same gate as every real hash — a decoy that allocated
around the bound would be a hole in it — and it does not raise the DoS ceiling:
anyone holding a single valid username could already make the pod hash on demand,
and the gate bounds that work regardless of which branch asked for it. What the
decoy removes is the need to know a username. Bounding arrival *volume* is the
edge's job; it can see the client, this package can only see a plaintext.

Residual, and it self-heals: the decoy costs one mint (13.5ms), so a live bcrypt
row (39.3ms) still answers ~3x slower — the tell is the row's **scheme**, not its
existence, and it disappears as the 40 rows migrate. Closing it fully would mean
a fixed time budget for the whole login, which no single decoy cost can imitate
across a fleet holding three different costs.

> **bcrypt truncates at 72 bytes.** Live rows longer than 72 bytes are not locked
> out — bcrypt verifies the 72-byte prefix, so those logins keep working. But the
> re-mint changes the effective secret from that prefix to the **full string**:
> argon2id has no such truncation. A user who has been signing in with a known
> *prefix* of their password (rather than the whole thing) would be locked out
> the moment their row migrates. Exotic, but it is a one-way door — the plaintext
> only exists during that one login.

> **`redact` + `Update` destroys MFA enrolment — pre-existing, and `feat/mfa`
> lands on top of it.** `redact` zeroes `TotpSecret`, `RecoveryCodes` and
> `AccessSecretHash` on the way out, and `Update` restores only the password
> triple (`PasswordHash`/`PasswordType`/`PasswordSalt`) from the stored row. So a
> read-modify-write round-trip through the API — **an ordinary rename** — writes
> those secrets back as empty and silently un-enrolls the user's second factor.
> `main` is identical here; what this branch made safe is the password triple
> only, and the same reasoning was never applied to the other redacted fields.
> Whoever implements MFA must preserve every redacted field on `Update` the way
> the password triple is preserved, or enrolment evaporates on the first profile
> edit. The general fix is that `Update` must not be able to write a field it
> never showed the caller.

> **`init_data.json` seeds no users.** It declares organizations, applications,
> providers and certs — v1's own file declares **zero** users, and `internal/seed`
> models none. "Bootstrap" cannot mean "seed a login": the first credential comes
> from the users API. The `passwordType: argon2id` in that file is the
> *organization*'s, which iam2 does not read (the digest decides).

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
