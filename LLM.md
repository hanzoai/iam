# Hanzo IAM

## Overview

Identity & Access Management for the Hanzo ecosystem and any product that consumes it as a white-label engine. OAuth 2.0 / OIDC / SAML / LDAP / SCIM / WebAuthn / MFA — all served behind a single canonical surface at `/v1/iam/*`.

Data lives in Base (`hanzoai/base`) — embedded SQLite with auto-migrations and replicate-to-S3 (no PostgreSQL, no Redis). Inter-service traffic uses native ZAP binary protocol.

## API surface

**Public:** `/v1/iam/*` only. Internal services and SDKs target this.

```
/v1/iam/login                       — username/password + MFA
/v1/iam/oauth/authorize             — OAuth2 authorization endpoint
/v1/iam/oauth/access_token          — OAuth2 token endpoint (incl. client_credentials)
/v1/iam/oauth/refresh_token
/v1/iam/oauth/introspect
/v1/iam/oauth/revoke
/v1/iam/oauth/userinfo
/v1/iam/oauth/device
/v1/iam/oauth/logout
/v1/iam/oauth/register              — Dynamic Client Registration (RFC 7591)
/v1/iam/.well-known/openid-configuration
/v1/iam/.well-known/jwks
/v1/iam/users/...
/v1/iam/applications/...
/v1/iam/organizations/...
/v1/iam/...
```

One shape per endpoint. There is no rewrite layer, no `/api/*` alias, no `/login/oauth/*` back-compat. Anything off `/v1/iam/*` is 404.

ZAP RPC runs on a separate port for service-to-service auth (`AuthService.GetToken`, `AuthService.IntrospectToken`).

## Storage — Base/SQLite ONLY, per-org + per-user files. NO Postgres. NO Redis. Ever.

IAM persists to embedded SQLite (modernc, pure-Go, CGO-free) under the canonical
Hanzo Base model. **One SQLite file per tenant boundary** — so any org or user can
be dropped/recreated independently, deterministically, again and again:

- **Global rows** (certs, providers, admin org/app/user) → `${IAM_DATA_DIR}/iam.db`.
- **Per-org**: each org → its own file `${IAM_DATA_DIR}/orgs/{orgSlug}.db`, HKDF-derived
  per-org DEK (`object/orgdb.go`).
- **Per-user**: each user → its own file `${IAM_DATA_DIR}/orgs/{orgSlug}/users/{userId}.db`,
  DEK derived per-user from the per-org key. User-scoped data never shares a table.

Directory isolation = deterministic recreation: delete a file → that tenant is gone;
re-seed from `init_data.json` → it's back. No shared multi-tenant table, no leader
election, no external DB. Migrations via Base (Goose-style, `migrations/`), applied on
boot; WAL streamed to S3 (age-encrypted) via replicate.

> ⚠️ **CURRENT STOPGAP (2026-06) — Postgres, to be removed.** Prod IAM in hanzo-k8s
> is temporarily on Postgres (`driverName=postgres`, `sql-0.sql.hanzo.svc`, db `iam`)
> because the `CGO_ENABLED=0` build's `modernc.org/sqlite` v1.48 **panics at open** in
> this cluster — `unable to open database file: out of memory (14)` at
> `object/ormer.go` `createTable`/`Sync2` — across file / emptyDir / in-memory /
> PVC+fsGroup / 4Gi+GOMEMLIMIT. This is NOT the policy; it's a fallback that kept auth
> up after a restart surfaced the never-validated sqlite switch. **The fix is to make
> the embedded driver open reliably** (root-cause the modernc arena/RLIMIT failure, or
> build with CGO + `mattn/go-sqlite3`), then return to per-org/per-user SQLite above.
> See memory `hanzo_iam_db_postgres_landmine` + `feedback_no_postgres_anywhere.md`.

### Cutover runbook — Postgres → encrypted SQLite (per env, NEVER in place on a live writer)

The exit from the Postgres stopgap is the `cmd/pg2sqlite` migrator, which writes
the **enveloped per-org layout** the runtime opens (global `iam.db` + per-org
`orgs/<slug>/iam.db`, each with its own wrapped-DEK `.dek` sidecar). Run it
**once per environment**, lowest-risk env first (devnet → testnet → mainnet),
and only flip `driverName=sqlite` after row-count parity is proven. Encryption is
mandatory: the migrator and the runtime both FAIL CLOSED without
`IAM_KMS_MASTER_KEY`, and a CGO+libsqlcipher build refuses to start with the key
set but no codec linked (`CodecLinked()=false`) rather than writing plaintext.

Hard preconditions (all required, no shortcuts):

- **Image** = the CGO + SQLCipher build (`-tags "libsqlite3 sqlite_fts5"`,
  `CGO_LDFLAGS=-lsqlcipher`). The Dockerfile gates this with
  `TestEncryptionProof` + `TestOrgDBEncryptionPosture` under CGO — no image is
  produced if the codec isn't linked. A pure-Go (`CGO_ENABLED=0`) image CANNOT
  encrypt and MUST NOT be used for any env holding real data.
- **`IAM_KMS_MASTER_KEY`** = 64 hex chars (32 bytes), KMS-sourced via a KMSSecret
  CR. Never in git, never logged, never `kubectl apply`-ed as raw bytes.
- **Single-writer** during and after cutover: `replicas: 1` + `strategy: Recreate`
  + an RWO PVC for `IAM_DATA_DIR`, and **no HPA**. Two pods on one volume corrupt
  the SQLite files. (The operator CR `crs/iam-v1.yaml` already pins this; the
  universe kustomize has no HPA.)

Steps:

1. **Quiesce the writer.** Scale IAM to 0 (`kubectl -n <ns> scale deploy/iam
   --replicas=0`) so nothing writes Postgres or the data dir mid-copy. (Reads stop
   too — schedule a short window.)
2. **Verify source row counts first** — no writes, just a census of the live
   Postgres so you have a parity baseline:
   ```bash
   IAM_KMS_MASTER_KEY=<64hex> \
     pg2sqlite -verify \
       -src "user=iam host=sql-0.sql.<ns>.svc dbname=iam sslmode=disable password=<pw>"
   # prints per-table source row counts to stderr
   ```
3. **Migrate** into the enveloped layout on the RWO PVC (mount it, e.g. via a Job
   or an exec into a paused pod that has the volume):
   ```bash
   IAM_KMS_MASTER_KEY=<64hex> \
     pg2sqlite \
       -src "user=iam host=sql-0.sql.<ns>.svc dbname=iam sslmode=disable password=<pw>" \
       -dst /data/iam            # DATA DIR, not a file
   # writes /data/iam/iam.db + /data/iam/orgs/<slug>/iam.db (+ .dek each)
   ```
   Use `-overwrite` only on a known-empty/seed destination (it deletes
   `dst/iam.db*` and `dst/orgs`). The migrator mints a DEK and writes the `.dek`
   per file via the SAME `openEncrypted`/`OrgDBManager` the runtime uses, routing
   User rows per-org and everything else to the encrypted global db.
4. **Prove parity** BEFORE flipping the driver: confirm the migrator's destination
   per-table counts equal the step-2 source counts (the run reports both; any
   mismatch = stop and investigate, do not flip). Spot-check that
   `/data/iam/iam.db` and each `orgs/<slug>/iam.db` are **ciphertext** (no
   `SQLite format 3` magic in `hexdump -C ... | head`) and that every `.dek`
   sidecar exists.
5. **Flip `driverName=sqlite`** (+ `orgIsolation=sqlite`) in the env's IAM config
   and bring the single writer back up (`--replicas=1`, `strategy: Recreate`).
   Keep `IAM_KMS_MASTER_KEY` injected. Do NOT keep a Postgres fallback wired — the
   destination is now source of truth.
6. **Validate live**: `POST /v1/iam/login` (env superuser) → 200; OIDC discovery +
   `/v1/iam/.well-known/jwks` → 200; a real browser login completes. Confirm the
   pod is `replicas: 1` / `Recreate`. Keep the Postgres db read-only as a rollback
   safety net for one cycle, then decommission.

Rollback: if validation fails, scale to 0, flip `driverName` back to `postgres`,
scale to 1. Postgres was untouched (the migrator only reads it), so rollback is
immediate. Never run the migrator against the data dir of a running writer.

### Cutover runbook — PLAINTEXT SQLite → enveloped encrypted (the PROD path, `cmd/sqlite2enveloped`)

PROD IAM at-rest is **plaintext SQLite** (not Postgres — the live image
`1.19.7-projfix` is a pure-Go `CGO_ENABLED=0` build that gates on the *deprecated*
`ENCRYPTION_MASTER_KEY` and physically cannot encrypt). The keystone that closes
the gap is **`cmd/sqlite2enveloped`**, which migrates the live plaintext `iam.db`
into the SAME enveloped layout the runtime opens (global `iam.db` + per-org
`orgs/<slug>/iam.db`, each with a wrapped-DEK `.dek`), preserving every SQL NULL.

Why a separate tool from `pg2sqlite`: `pg2sqlite` is Postgres-only and reads via
`xorm.QueryInterface`, which coerces SQL NULL → `""`/`0`/`false` at the READ step.
Proven on the real 112-user prod snapshot: it turns the 12 NULL JSON-TEXT `roles`
into `""` (boot-killer: "unexpected end of JSON input") and the NULL
`mfa_*`/`balance` into `0`. **Count parity cannot detect this.** `sqlite2enveloped`
instead reads with a per-column `database/sql` `*any` scan (SQL NULL → Go `nil`),
routes via the shared `object.InsertRows`/`object.CopyUsersPerOrg` write path
(`database/sql` honours `nil` as NULL), drops the bogus `enforcer.enforcer`
column, and gates on **CONTENT/hash parity** (per-table row-hash multisets with a
NULL sentinel + storage-class tag), not counts. It even preserves the legacy
BLOB-in-REAL-affinity `balance` values byte-identically.

Hard preconditions (identical to the pg2sqlite runbook, PLUS):

- **Image** = the CGO + SQLCipher build that gates on `IAM_KMS_MASTER_KEY`:
  `ghcr.io/hanzoai/iam:sha-5b62a0e` (built from the exact commit, Dockerfile
  `target=standard`, gated by `TestEncryptionProof` + `TestOrgDBEncryptionPosture`
  + the DT_NEEDED `readelf` proof — a plaintext build cannot be produced). The
  live `1.19.7-projfix` MUST be replaced; it is pure-Go and gates on the wrong var.
- **`IAM_KMS_MASTER_KEY`** = 32 bytes (64 hex), KMS-sourced via a KMSSecret
  (`secrets.lux.network/v1alpha1`, kind `KMSSecret`, hostAPI `http://kms.hanzo.svc`)
  that produces Secret `iam-master-key` with key `IAM_KMS_MASTER_KEY` — which the
  operator CR already references. Provision:
  `openssl rand -hex 32 | kms put /iam-secrets/IAM_KMS_MASTER_KEY --stdin --org hanzo --env prod`
  (never in git/logs/argv; versioned + recoverable in KMS; `creationPolicy: Orphan`
  so deleting the CR never GCs the key). **Key loss = permanent lockout of all 42
  orgs incl JWT-signing Certs** — confirm KMS itself is backed up first.
- **Single-writer**: `replicas: 1` + `strategy: Recreate` + RWO PVC for the data
  dir, **no HPA**. The live CR + universe kustomize already pin this.
- **`DATA_DIR`** is the authoritative env the binary reads (`resolveDataDir()` reads
  `DATA_DIR` first, then conf `dataDir`; `IAM_DATA_DIR` alone is NOT honoured) —
  set `DATA_DIR=/data/iam`.

Red sign-off (against the real 112-user snapshot): **SAFE — full data fidelity, 0
critical/high/medium.** Red proved the content-parity gate is not vacuous
(injected a NULL→"" coercion on a non-censused column → parity correctly FAILED),
and that the mixed REAL/BLOB `balance` values, the 4 true-BLOB MFA/WebAuthn
columns, the 3-column-PK `session`, and `record` (222k rows) all round-trip
byte-identically with 0 drops / 0 slug collisions / 0 orphans. One LOW
follow-up, NOT a cutover blocker (zero data impact): the migrator's bogus
`enforcer.enforcer` column drop is undone at the next daemon boot because
`ormer.go` `Sync2(new(Enforcer))` re-adds the all-NULL column — fix by dropping
it on the boot path or tagging the upstream embed `xorm:"-"` (a daemon-image
follow-up, the column carries no data).

Exact gated cutover sequence (run ONLY after this is Red-approved; lowest-risk env
first). The migrator runs against a **COPY** of the live db on the PVC, never the
live writer's open file:

```bash
CTX=do-sfo3-hanzo-k8s; NS=hanzo
# 0. Prereqs already in place: KMSSecret → Secret iam-master-key synced; the
#    reconciled CR (services.hanzo.ai/iam, image sha-5b62a0e, DATA_DIR=/data/iam,
#    orgIsolation=sqlite, driverName=sqlite, IAM_KMS_MASTER_KEY env) staged but
#    NOT yet applied; a fresh rollback snapshot of /data/iam taken.
# 1. Quiesce the writer (short window — reads stop too).
kubectl --context $CTX -n $NS scale deploy/iam --replicas=0
kubectl --context $CTX -n $NS rollout status deploy/iam --timeout=120s  # wait for 0
# 2. In a maintenance pod mounting the SAME PVC (the iam image, sleep), with the
#    master key injected, COPY the live plaintext db and migrate the copy:
#    cp /data/iam/iam.db /data/iam/_plain.db   (copy; never migrate the live file)
#    IAM_KMS_MASTER_KEY=$KEY sqlite2enveloped -src /data/iam/_plain.db -dst /data/iam/enc
# 3. CONTENT-PARITY gate: the tool exits non-zero on ANY parity miss. Also verify
#    counts (112u/42o/213a/9p/10c) and ciphertext (no "SQLite format 3" header)
#    on /data/iam/enc/iam.db and each orgs/<slug>/iam.db; confirm every .dek exists.
#    If anything is off → STOP (do not swap), scale back to 1 on the old image.
# 4. Swap the enveloped layout into place atomically (still scaled to 0):
#    mv /data/iam/iam.db{,.preenc.bak}; rm -rf /data/iam/orgs
#    mv /data/iam/enc/iam.db /data/iam/iam.db; mv /data/iam/enc/iam.db.dek /data/iam/
#    mv /data/iam/enc/orgs /data/iam/orgs; rm -rf /data/iam/enc /data/iam/_plain.db
# 5. Apply the reconciled CR (image sha-5b62a0e + DATA_DIR + orgIsolation=sqlite +
#    IAM_KMS_MASTER_KEY) and bring the single writer up:
kubectl --context $CTX -n $NS apply -f <reconciled-iam-Service-CR>.yaml
kubectl --context $CTX -n $NS scale deploy/iam --replicas=1
kubectl --context $CTX -n $NS rollout status deploy/iam --timeout=180s
# 6. Validate live: login + OIDC + JWKS 200, ciphertext at rest, browser e2e:
#    curl -sf https://hanzo.id/v1/iam/.well-known/openid-configuration → 200
#    curl -sf https://hanzo.id/v1/iam/.well-known/jwks → 200
#    POST /v1/iam/login (z@hanzo.ai) → 200; Playwright real-browser login completes.
#    Confirm replicas:1 / Recreate; confirm /data/iam/iam.db has no plaintext header.
```

INSTANT ROLLBACK (the auth authority stays plaintext+healthy until this flip, so
rollback is immediate and total): scale to 0, restore `/data/iam` from the
rollback snapshot (`iam.db.rollback-snapshot-…`), re-apply the OLD CR
(`1.19.7-projfix`, no encryption env), scale to 1. The off-cluster copy at
`/Users/a/work/hanzo/.iam-rollback/iam.db.prod-plaintext-rollback-…` is the last
resort. The plaintext source is only ever read (migration runs on a copy), so no
forward step is destructive until step 4's swap — and step 4 keeps
`iam.db.preenc.bak` on the PVC too.

Run/test the migrator (CGO + SQLCipher; the shared `CGO_ENABLED=0` job skips the
encryption assertions, the Dockerfile build is the hard gate):

```bash
SC=/opt/homebrew/opt/sqlcipher   # or the alpine sqlcipher-dev in the image
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I$SC/include/sqlcipher" \
  CGO_LDFLAGS="-L$SC/lib -lsqlcipher" \
  go test -count=1 -tags "libsqlite3 sqlite_fts5" ./cmd/sqlite2enveloped/
```

### CUTOVER EXECUTED — prod hanzo-k8s is now ENCRYPTED at rest (DONE)

The plaintext→enveloped cutover ran on `do-sfo3-hanzo-k8s` ns `hanzo` and is
**live + verified**. End state: IAM serves from per-org SQLCipher-encrypted
SQLite; auth is healthy (login/OIDC/JWKS 200 on `hanzo.id` + `iam.hanzo.ai`).

- **Image**: `ghcr.io/hanzoai/iam:sha-a298046` — the Red-approved server commit
  `5b62a0e` (iamd byte-identical: the only delta is the ADDITIVE
  `cmd/sqlite2enveloped` migrator + `object/migration_copy.go`, referenced ONLY
  by the migrator, never by the boot path) PLUS a one-line Dockerfile COPY that
  ships the migrator binary at `/sqlite2enveloped`. Built via **platform/arcd
  in-cluster buildkit** (`POST arcd-control.hanzo.svc:3000/v1/arcd/enqueue`,
  target=standard, linux/amd64) — NO GitHub Actions. ONE image runs both the
  migration Job and the server.
- **Key**: `IAM_KMS_MASTER_KEY` (32B/64-hex) minted via KMS canonical write
  (`POST /v1/kms/orgs/hanzo/secrets` with `{path:"iam",name:"IAM_KMS_MASTER_KEY",
  value,env:"prod"}` after `POST /v1/kms/auth/login` with `hanzo-platform`
  creds — the IAM-direct token 401s, the KMS login-proxy token writes). Value
  never logged. Synced down via KMSSecret `iam-master-key-kms-sync`
  (`secretsPath:/iam`, `envSlug:prod`, `creationPolicy:Orphan`) →
  Secret `iam-master-key`. **GOTCHA: the KMS POST is env-scoped by the body
  `env` field; a POST with no `env` lands env-less and is invisible to the
  operator's `envSlug:prod` read.**
- **Config**: the cutover REQUIRES `orgIsolation=sqlite` in the `iam-conf`
  ConfigMap (ormer.go InitAdapter gates the enveloped global-db open on
  `orgIsolation=="sqlite" && driverName=="sqlite"` + a resolvable master key;
  otherwise it opens the plaintext DSN on a now-ciphertext file → panic). The CR
  alone is NOT sufficient — apply BOTH the ConfigMap (orgIsolation=sqlite,
  dataDir=/data/iam) AND the operator CR (image + DATA_DIR + master-key
  secretRef). Both live in `universe/infra/k8s/iam/`.
- **Sequence run**: scale CR `replicas:0` (operator drains, RWO PVC freed) →
  Job `iam-encryption-cutover` (cp live db → `_plain.db`; `sqlite2enveloped`
  → `enc/`; content-parity gate PASS; ciphertext+`.dek` verify; atomic swap
  keeping `iam.db.preenc.bak`) → apply ConfigMap + CR (`replicas:1`).
- **Evidence**: parity OK every table incl. user 112/112 → 7 org files,
  record 222752/222752; counts intact 112u/42o/213a/9p/10c (API-verified);
  global + 8 per-org dbs are ciphertext (no `SQLite format 3` magic) with `.dek`
  sidecars; pod Running 1/1 0 restarts; Playwright real login z@hanzo.ai →
  `/onboarding`.
- **Rollback nets retained**: `/data/iam/iam.db.preenc.bak` +
  `iam.db.rollback-snapshot-20260623T165417Z` (on-PVC) + off-cluster
  `~/work/hanzo/.iam-rollback/iam.db.prod-plaintext-rollback-…`; CR + ConfigMap
  pre-enc backups in `~/work/hanzo/.iam-rollback/*.PREENC.*.yaml`. Rollback =
  scale 0, restore preenc.bak→iam.db (+rm orgs), re-apply OLD CR
  (`1.19.7-projfix`, no master-key env) + OLD ConfigMap (no orgIsolation),
  scale 1.

## Auth flows

### User login

1. Browser hits `https://iam.{env}.{deployment-domain}/v1/iam/login`
2. Form submit → Base verifies password + MFA
3. Sets session, redirects to OAuth `authorize` endpoint
4. Returns code → SPA exchanges via `/v1/iam/oauth/access_token`

### Service-to-service (client_credentials)

For machine identity (e.g. KMS pulling from IAM, or a CI job calling internal APIs):

```bash
curl -X POST https://iam.dev.{deployment-domain}/v1/iam/oauth/access_token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>"
```

Returns `{"access_token": "...", "expires_in": 86400, "token_type": "Bearer"}`.

### JWKS for downstream JWT validation

`GET /v1/iam/.well-known/jwks` — RSA public keys for verifying issued JWTs. Downstream services (gateways, ATS, etc.) validate tokens using JWKS — no shared secret.

## Deployment

| Env | URL | Image | Storage |
|---|---|---|---|
| devnet | `https://iam.dev.{domain}` | `ghcr.io/hanzoai/iam:dev` | Base/SQLite (PVC) |
| testnet | `https://iam.test.{domain}` | `ghcr.io/hanzoai/iam:test` | Base/SQLite (PVC) |
| mainnet | `https://iam.main.{domain}` | `ghcr.io/hanzoai/iam:main` | Base/SQLite (PVC) |
| local | `http://localhost:8000` | `ghcr.io/hanzoai/iam:dev` | SQLite (volume) |

Deployed via the IAM operator CRD. Per-deployment configuration is supplied by the consuming product.

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
| `IAM_ADMIN_ORG` | Admin organization name | `admin` (panics if unset in production) |
| `IAM_ADMIN_APP` | IAM application name inside the admin org | `iam` (panics if unset in production) |
| `IAM_ADMIN_USER` | Bootstrap admin user name | `root` (panics if unset in production) |

The three admin slots are orthogonal: `admin/admin` is the org row, `admin/iam`
is the application row, `admin/root` is the bootstrap user row. Each is read
once at package init via `requiredEnvOrDefault`, which **panics in production**
when the corresponding env var is unset. Use the `object.NewAdminOrg/App/User()`
constructors when seeding — never spell the values inline.

There are no upstream-brand env vars, aliases, or fallbacks — `IAM_*`
everywhere, period.

## Build

```bash
cd ~/work/hanzo/iam
go build -o iam ./cmd/iam     # backend
cd web && pnpm build           # frontend (Vite)
```

CI builds multi-arch Docker image (`hanzo-build-linux-amd64` + `hanzo-build-linux-arm64` runners) and pushes to:
- `ghcr.io/hanzoai/iam:{tag}` (canonical)

## Repository layout

```
iam/
├── *.go                     — canonical Go SDK (package iam): Client, Claims,
│                              User, Application, Cert, jwt parsing, …
│                              import "github.com/hanzoai/iam"
├── errors.go                — typed error vars (ErrTokenMissing, ErrTokenInvalid …)
├── cmd/iam/                 — admin CLI binary
├── cmd/iamd/                — server daemon (canonical entrypoint)
├── controllers/             — HTTP handlers
├── routers/
│   └── router.go            — route table (canonical /v1/iam/* only)
├── object/                  — domain logic (users, apps, orgs, sessions)
├── service/                 — auth flows (oauth, oidc, saml, ldap)
├── pkg/iam/                 — separate Go module: Embed() + Mount() entry
│                              points for HIP-0106 fused cloud binary.
│                              Carries cloud + zip deps; root SDK does not.
│                              import "github.com/hanzoai/iam/pkg/iam"
├── migrations/              — Base schema migrations
├── notification/            — email/SMS/webhook fan-out adapters
├── storage/                 — pluggable file backends (S3, GCS, Azure, ...)
├── web/                     — React SPA
├── compose.yml              — local dev stack
├── deployment/              — K8s manifests (operator-managed in prod)
├── conf/                    — sample app.conf templates
└── NOTICE                   — third-party license attributions
```

### Canonical Go SDK (HIP-0117)

The Go SDK lives at the module root — one canonical path, no drift:

```go
import iam "github.com/hanzoai/iam"

c := iam.NewClient(endpoint, clientId, clientSecret, certPEM, org, app)
claims, err := c.ParseJwtToken(token)
```

There is no `iam/sdk/`, no `iam/client/`, no `iam/v2`. The legacy
`github.com/hanzoai/iamsdk/v2/iamsdk` upstream-fork module is retired —
its consumers (ai, vm, visor, …) have been swept to the root path.

Non-Go SDKs (TypeScript, Python, Rust) live in `github.com/hanzoiam/sdk`.
That repo is the polyglot umbrella; Go stays in this repo.

## Integration points (across the stack)

- **Gateway**: validates inbound JWTs against IAM JWKS
- **KMS**: authenticates clients via `/v1/iam/oauth/access_token` (client_credentials), then mints short-lived bearer for KMS sessions
- **Downstream services**: extract `sub` (user) and `owner` (org) from JWT claims
- **Web consoles / SPA clients**: standard authorization_code + PKCE OAuth flow
- **MPC**: WebAuthn challenges issued via IAM, completed in browser, then user shard authorized via JWT bound to NodeID

## Security posture

- All secrets land in KMS first, synced to k8s `Secret` via `KMSSecret` CR — never push raw key bytes through `kubectl apply`
- Argon2id password hashing (NEVER plaintext, NEVER bcrypt)
- TLS termination at the deployment ingress; IAM serves plain HTTP internally
- JWKS rotation: keys are dual-published (current + previous) for graceful rollover

### Encryption at rest — envelope model (`object/orgdb.go`, `github.com/hanzoai/sqlite` ≥ v0.1.3)

The master key is sourced from ONE env var: **`IAM_KMS_MASTER_KEY`** (64 hex =
32 bytes), KMS-sourced via a KMSSecret CR. The earlier `ENCRYPTION_MASTER_KEY`
name was a bug (it existed nowhere else, so the key was always nil → silent
plaintext). **The operator/universe Deployment MUST inject `IAM_KMS_MASTER_KEY`
from KMS** for any env storing real data — encryption is OFF until it is set, and
a CGO+libsqlcipher build refuses to start with the var set but no codec rather
than writing plaintext.

- **Envelope, not page-key-from-master.** Each db (global + per-org) has its own
  random DEK (SQLCipher page key), wrapped (AES-256-GCM) under a KEK =
  `HKDF(master, lp(principal)||lp(id))` and stored in a `<db>.dek` sidecar (0600).
  The raw DEK is never written. The wrap also binds the principal as GCM AAD
  (`sqlitedrv.PrincipalAAD`), so a sidecar moved to another principal fails the
  tag — defense-in-depth atop the per-principal KEK.
- **Master-key rotation = rewrap the sidecars** (`OrgDBManager.Rewrap`) — pages
  are never rewritten, so rotation is O(1) and cannot brick a file. (The old
  HKDF-direct page key made rotation = data loss.) Rotation is **idempotent /
  crash-resumable**: `rewrapSidecar` tries the new KEK first and skips an
  already-rotated sidecar, so a rotation that dies after `k` of `N` files
  converges on a clean re-run instead of aborting on the first done one.
- **Global db encrypted too.** `{dataDir}/iam.db` holds the JWT signing private
  keys (`Cert`) and `Application.ClientSecret` — the forge-any-token material.
  Under `orgIsolation=sqlite` + master key it is opened enveloped (principal
  `global`), not via the plaintext conf DSN.
- **Per-org isolation, fail-closed.** Every org owner is canonicalized to a
  safe, injective slug (`orgSlug`: lowercase + illegal→`-`, disambiguated by a
  16-hex (64-bit) SHA-256 suffix when changed) so EVERY org maps to its own
  encrypted file — never rejected, never falling back to the shared engine.
  `orgEngine` fails CLOSED under isolation (a genuine open failure 500s; it never
  silently routes org data to the global engine).
- **SCOPE OF PER-ORG ENCRYPTION — read this, don't overclaim.** Only the **User**
  table is per-org (`orgEngine` is called only from `user.go`). Tokens, sessions,
  certs, applications, providers, roles, permissions, groups, keys, etc. all live
  on the **global** engine (`{dataDir}/iam.db`), co-mingled across orgs. The
  global db IS encrypted at rest (principal `global`), which protects the JWT
  signing keys / ClientSecrets against disk theft — but the "one org's file can't
  be read with another org's key" guarantee applies to **usernames/profiles
  only**. Compromise of the global DEK or the live process exposes every org's
  tokens, secrets, and authz. Routing tokens/sessions per-org is future work; do
  not describe the current state as full per-tenant cryptographic isolation.
- **Single-writer by design (concurrency).** Embedded SQLite on an RWO PVC means
  exactly ONE pod writes the data dir — the operator CR pins `replicas: 1` +
  `strategy: Recreate`, and the universe kustomize has **no HPA** (an HPA would
  scale to multiple writers on one volume → corruption). HA = fast Recreate
  restart + replicate-to-S3, NOT horizontal write scaling. As a backstop against
  an accidental re-scale, `openEncrypted` takes an exclusive cross-process file
  lock (flock on `<db>.create.lock`) around the DEK-mint + db-create critical
  section and re-checks the sidecar under the lock, so two processes
  first-touching a fresh org can never mint divergent DEKs and brick the file.
- **HKDF info is length-prefixed** → injective (`(org,"a:b") ≠ ("org:a","b")`).
- **Key hygiene.** DEKs are zeroized after open; `RLIMIT_CORE=0` is set on Linux
  (`object/coredump_linux.go`) so a core dump can't leak keys; the SQLCipher key
  rides the driver open call (never a DSN xorm logs); DSN paths are percent-
  escaped so `?`/`#` can't strip `key=`; `cache=shared` is never set on an
  encrypted db (shared cache leaks decrypted pages across keys).
- **Postgres → SQLite migration** (`cmd/pg2sqlite`) emits the enveloped layout
  the runtime opens: `-dst` is a DATA DIR; it requires `IAM_KMS_MASTER_KEY`,
  mints a DEK + writes the `.dek` per file (reusing `object.NewMigrationTarget` →
  the runtime's `openEncrypted` + `OrgDBManager`), and routes User rows per-org +
  everything else to the encrypted global db. It FAILS CLOSED without the key
  (never writes a plaintext destination).
- **Per-USER files are DEFERRED.** The canonical layout reserves
  `orgs/{slug}/users/{userId}.db` with a DEK derived per-user FROM the per-org
  KEK (hierarchy primitive `sqlitedrv.DeriveChildKey` is implemented). No code
  routes to a user-level engine yet (`ProvisionOrg` is unused; org DBs are lazy),
  so there is no plaintext-user exposure today — wiring user files is future work.

## Testing

```bash
go test ./...                       # backend unit tests
cd web && pnpm test                 # frontend
pnpm e2e                            # Playwright (hits live dev IAM)
```

E2E tests live at `tests/iam-e2e.spec.ts` and `tests/iam-login.spec.ts`. They run against a dev or staging IAM with a known seed user (`satoshi.nakamoto` per memory `feedback_seed_credentials.md`).

## Things this is NOT

- ❌ A PostgreSQL service (no postgres anywhere — Base/SQLite only)
- ❌ A Redis user (no Redis — sessions live in Base)
- ❌ Branded — IAM is the white-label engine; brand surfaces live in the consuming product, not here.

## Related

- `~/work/hanzo/iam/NOTICE` — upstream library attributions (legal)
- Memory notes (these are policy):
  - IAM is uniquely ours — no upstream brand in source, env, or docs
  - `feedback_no_postgres_anywhere.md` — Base/SQLite only
  - `feedback_keys_from_mnemonic.md` — keys derive from mnemonic + KMS
  - `feedback_seed_credentials.md` — fixed dev seed users
