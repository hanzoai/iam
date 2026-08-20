# IAM v2 Migration

Casdoor fork (`hanzoai/iam`: Beego + xorm, Apache-2.0) → `hanzoai/iam2`:
clean-room, proprietary, on the native Hanzo stack. Phased and additive — the
identity binary is never rewritten in one shot, and v1 stays live and
authoritative until the supervised cutover. Parity is proven by tests + golden
vectors captured from v1's own code + a route-level parity audit, and by a
shadow deployment against real traffic — not by a swap on faith.

## §1 Why

`hanzoai/iam` is a fork of Casdoor. Every file carries `Portions Copyright The
Casdoor Authors` under Apache-2.0. It couples us to xorm's fluent API, Beego's
router, and an upstream we do not control. `iam2` is original expression on our
own framework — we own it, and it collapses to one way of doing each thing.

## §2 Stack contract

- **HTTP** — `github.com/zap-proto/zip` (typed `zip.Get[In,Out]` handlers on the
  `zap-proto/fiber/v3` engine, specificity routing, OpenAPI 3.1 at the edge).
- **Storage** — `github.com/hanzoai/orm` (typed Go records + KV cache). Default
  is embedded SQLite (`hanzoai/sqlite`, pure-Go, WAL) — never Postgres. The same
  `orm.DB` abstraction pluggably targets `hanzoai/sql` / `hanzoai/datastore` over
  ZAP (`--store sql|datastore`), so iam2 gains ZAP-native persistence + snapshots
  with zero code change once orm's ZAP backend is enabled.
- **OIDC/OAuth2** — in-tree (no external OIDC library). RS256 today; ML-DSA-65
  hybrid JWT signing + real JWKS from the Cert entity.
- **Password verify** — algorithm resolved from the stored row (`internal/cred`):
  argon2id (every live v1 row) + bcrypt (new iam2 rows), verify-only, fail-closed.
- **Inter-service** — `zap-proto` binary RPC. HTTPS is the external edge only; all
  service↔service is ZAP (platform law).
- **Authz** — `github.com/hanzoai/authz` policy engine (`internal/authz` gate).

## §2.1 RFC/IETF-standard surface — no Casdoor verbs (HIP-0111)

The wire contract is RFC/OpenID-standard only; there are no Casdoor verb aliases
(`get-users`, `add-user`, `get-account`, `issue-user-token`, …) and no `access_token`
duplicate of the token endpoint. Each capability is served by its standard, all
shipped (iam2 tags):

| Capability | Standard | Endpoint | Tag |
|-----------|----------|----------|-----|
| Authorize / token | RFC 6749 (code+PKCE, refresh, client_credentials, **password**) | `/v1/iam/oauth/{authorize,token}` | v0.5.0 |
| Delegation / on-behalf-of | **RFC 8693 Token Exchange** (replaces `issue-user-token`) | `grant_type=…token-exchange` | v0.7.0 |
| Introspection / revocation | RFC 7662 / RFC 7009 | `/v1/iam/oauth/{introspect,revoke}` | v0.6.0 |
| AS metadata / discovery / JWKS | RFC 8414 / OIDC Discovery / RFC 7517 | `/.well-known/*` | v0.6.0 |
| Account claims | **OIDC UserInfo** (carries owner/organization/email/isAdmin/type — the get-account contract) | `/v1/iam/oauth/userinfo` | v0.9.0 |
| Identity provisioning | **SCIM 2.0** (RFC 7644/7643; replaces get-/add-/update-/delete-user) | `/v1/iam/scim/v2/Users` | v0.8.0 (v0.8.1 authz fix) |
| Resource indicators / issuer pin | RFC 8707 + `IAM_ISSUER` | token `aud`/`iss` | v0.5.0 |
| Social sign-in / federation | **OIDC/OAuth2 Relying Party** (Authorization-Code + PKCE; Google = OIDC Discovery, GitHub = OAuth2 + userinfo) | authorize `?provider=<name>` → `/v1/iam/oauth/callback` | v0.15.0 |

Deploy env: `IAM_ISSUER=https://<brand-id>`, `IAM_KEY_MINT_ALLOWED_APPS` (token
exchange + `hk-` key mint) and `IAM_ADMIN_MINT_ALLOWED_APPS` (reserved-org targets)
— both matched by the globally-unique clientId only.

**Federation (social sign-in), v0.15.0.** iam2 completes a Google/GitHub sign-in
as a standard OIDC/OAuth2 Relying Party — no Casdoor verbs, no tokens-in-query.
The authorize endpoint, once it has validated the client and its EXACT
redirect_uri, treats a `?provider=<providerName>` request as a federation
kickoff: it stashes the app-leg request in a single-use, expiring,
browser-bound `FederationState` (state = an opaque 256-bit row key; a `hanzo_fed`
HttpOnly+Secure+SameSite=Lax cookie binds it to the initiating browser) and 302s
to the IdP with iam2's callback as the redirect_uri, an IdP-leg S256 PKCE
verifier, and (OIDC) a nonce. The fixed public callback `/v1/iam/oauth/callback`
resolves + burns the transaction (expiry + browser-binding checked), exchanges
the IdP code, and VERIFIES the response — for OIDC the id_token signature
(against the discovered JWKS, alg pinned to RS/ES), issuer, audience (= our
client id), expiry, and nonce; for GitHub the userinfo + a GitHub-verified
primary email. It then LINKS or PROVISIONS a local user (match by provider
subject, else by VERIFIED email, else provision — never `isAdmin`, federated
accounts carry no password) and mints iam2's OWN authorization code bound to the
original PKCE/redirect/nonce, so the relying party's existing PKCE code→token
exchange completes unchanged. Provider credentials/endpoints come from the
existing `providers` rows (`clientId`/`clientSecret`/`type`/`scopes`/`issuerUrl`
or the `custom*Url` overrides); the linked subject is persisted on the User's
per-connector column (`google`/`github`/…).

Remaining for cutover: migrate the clients (console `IamAdminApi`/`identity.ts`,
gateway admin-guard, portal) off the Casdoor verbs onto these standards via
`@hanzo/iam` (+ a SCIM client + token-exchange), then retire `internal/compat` and
`get-account`. iam2 already serves everything the clients need in standard form.

## §3 Phases

| Phase | Scope | Exit |
|------:|-------|------|
| 1 | Entity schemas (full fields) + owner-scoped CRUD on `zip`+`orm`, 13 identity entities. | ✅ Field-complete vs v1; handlers tested. |
| 2 | In-tree OIDC/OAuth2: discovery, JWKS, authorize, token (PKCE S256 + JWT), refresh, userinfo, logout; front-door login/get-app-login/auth-methods. | ✅ Core flow (login→code→token→JWT) tested; front-door residual in progress (below). |
| 3 | Authz via `hanzoai/authz` gate over the entity CRUD. | ✅ In `internal/authz`. |
| — | ~~Drift gate~~ **DROPPED.** Parity is proven by tests + golden vectors (a real v1 argon2id digest verifies) + a route-level parity audit + a shadow deployment — not a row-count diff. The read-only `compare` CLI remains as a diagnostic, not a gate. | — |
| 4 | **Bootstrap + embed.** Seed the real config (orgs/apps/providers/certs) from the same `init_data.json` v1 uses (`internal/seed` — 79 apps / 9 orgs). Embed in `hanzoai/cloud` via `server.Mount`, SHADOW-FIRST (own prefix, alongside live Casdoor, non-destructive). | Shadow serves real `get-app-login`/login against seeded config. |
| 5 | **Cutover.** Import the user rows (password hashes verify as-is — see §5), flip iam2 onto the canonical `/v1/iam/*`, archive the fork. | Green in prod; rollback proven. |

## §4 Front-door residual (gates cutover)

The OIDC/OAuth2 protocol surface is complete. HIP-0111 §6's *native front-door* —
what the hosted `hanzo.id` portal itself calls, distinct from the OIDC surface
client apps use — is now complete: `get-app-login`, `login`, `auth/methods`,
`userinfo`, `logout`, `refresh`, `authorize`, `get-account`,
`send-verification-code`, `signup`. A backend swap without these takes the
portal's account page, email verification, and signup with it, so cutover was
gated on them. Serve under `/v1/iam/*` (no `/api/`, no new prefix).

The **durable session** is wired (`internal/sessions`): a bare `login`
(type=login) issues a signed, revocable session cookie (`hanzo_session`, HMAC
keyed off the platform signing cert — no new secret), and `get-account` resolves
the caller by cookie first (the portal + admin-guard path) then bearer (the API
path) — two credentials, one identity. The cookie's `sid` is registered in the
`Session` row and re-checked on every resolve, so logout/rotation revokes it.
§4 is closed; iam2 is Phase-4 shadow-embed ready.

The `signup`/`send-verification-code` pair carries two deliberate seams vs v1,
each a missing iam2 dependency, not a shortcut: (1) signup lands the user in the
app's **existing** org — v1's founder-org mint (`TenantOrgForSignup`) needs an
org-create helper + the `Org.Parent` tenant model iam2 has not modeled yet;
(2) `send-verification-code` persists a verifiable OTP (the `verifications`
entity) but the email/SMS **delivery** is owned by `hanzoai/notify`, not wired
into iam2 — the endpoint reports `ok` honestly and never fakes a "sent" claim.

Three facts the port must honour, each verified against live v1:
- **`get-account` is a security contract, not a convenience.** The gateway's
  admin-guard derives the **SuperAdmin predicate** from it
  (`gateway/cmd/admin-guard/main.go`); waitlist-guard derives **approval**. Its
  response shape (owner/isAdmin/… + no secret material) must match exactly.
- **`send-verification-code` takes `multipart/form-data`, not JSON.**
- Native **`userinfo`/`logout` are aliases** of the `oauth/*` handlers
  (`routers/router.go` + `authz_filter.go` collapse them) — register the alias,
  never fork a second implementation.

## §5 Credential parity (the cutover landmine, RESOLVED)

Every live v1 row is **argon2id** (`object/organization.go sanitizeOrgPasswordType`
rewrites `""`/`bcrypt`/`plain` → `argon2id`; `UpdateUserPassword` stamps it per
user). A bcrypt-only verifier handed an argon2id PHC digest returns
`ErrHashTooShort` → **100% of logins fail at cutover.** Fixed: `internal/cred`
resolves the algorithm **from the row** (`user.PasswordType` → fallback
`organization.PasswordType`), matching v1's `object/check.go`, and verifies
argon2id + bcrypt, verify-only, fail-closed on any unknown scheme. Proven by a
**golden vector** — a digest produced by v1's *own* `Argon2idCredManager`
verifies under iam2 (`internal/cred/golden_v1_test.go`), across the v0→v1.0.0
library-version gap. So existing users' hashes verify unchanged at import — no
password reset, no re-hash on read.

## §6 Domain model (v1 xorm table → v2 orm kind)

Fourteen identity entities. Field-completeness is mandatory — a dropped column is
lost auth data.

| v1 table (xorm)       | v2 orm kind            |
|-----------------------|------------------------|
| `user`                | `users` (auth)         |
| `organization`        | `organizations`        |
| `application`         | `applications`         |
| `provider`            | `providers`            |
| `role`                | `roles`                |
| `permission`          | `permissions`          |
| `cert`                | `certs`                |
| `key`                 | `keys`                 |
| `webauthn_credential` | `webauthn_credentials` |
| `session`             | `sessions`             |
| `token`               | `tokens`               |
| `record`              | `audit_logs`           |
| `invitation`          | `invitations`          |
| `verification`        | `verifications`        |

**Deliberately NOT modeled by iam2** (they belong to other services or are
replaced by `hanzoai/authz`): `payment`, `plan`, `product`, `subscription`,
`pricing`, `model`, `adapter`, `enforcer`, `syncer_*`, LDAP.

## §7 Build & deploy

Builds CGO-free (`hanzoai/sqlite` is pure-Go), pinned to published `hanzoai/orm`
+ `zap-proto/zip` (no local replaces). Native CI at `.gitea/workflows/build.yaml`
(git.hanzo.ai act_runner) + a mirror `.github/workflows/build.yml`, both
self-contained (no reusable-workflow dependency). Canonical pipeline is
**git.hanzo.ai + Hanzo GitOps**; GitHub is a downstream mirror.
