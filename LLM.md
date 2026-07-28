# LLM.md — hanzoai/iam

Canonical **Hanzo IAM** service: identity & access for the Hanzo cloud —
OpenID Connect / OAuth2 with PKCE, JWKS, UserInfo, SCIM 2.0, MFA/WebAuthn,
social federation. The server behind the `@hanzo/iam` SDK. Proprietary,
clean-room rewrite on the Hanzo stack (`zip` over `hanzoai/orm`) — no Casdoor,
Beego, or xorm. Retired Casdoor fork = `hanzoai/iam-v1` (do not use).

## Role in the model
This is a `hanzoai/<product>` service (impl lives here, DRY — one place). It is
NOT a language SDK. Clients authenticate via the `@hanzo/iam` SDK, never by
hand-rolling OAuth. Full SDK model: `~/work/hanzo/SDK-ARCHITECTURE.md`.

## Build & run
- `go build ./...`
- `go run . serve --init-data init_data.json`  (SQLite default; `--store sqlite|sql|datastore`)
- `go run . compare --legacy postgres://…/iam` (needs `-tags migration`)
- Image: `ghcr.io/hanzoai/iam`. Embed via `server.Route`. Go 1.26.

## Endpoints (HIP-0111 — /v1 only, no /api, no vendor verbs)
`/.well-known/openid-configuration` · `/v1/iam/.well-known/jwks` ·
`/v1/iam/oauth/{authorize,token,introspect,revoke,userinfo,logout,callback}` ·
`/v1/iam/scim/v2/Users`. PKCE `S256` always; `client_id` = `<org>-<app>`.
Brands set `serverUrl`: hanzo→iam.hanzo.ai, lux→lux.id, zoo→zoo.id,
bootnode→id.bootno.de, pars→pars.id (white-label by domain).

## Key entry points
- `main.go` — cobra root (`serve` / `compare` / `version`); `server/server.go` route registration.
- `internal/{oidc,routes}` — OAuth2/OIDC surface; `internal/{scim,mfa,webauthn,providers,sessions,tokens,cred,authz,certs,keys}`.
- `internal/{users,organizations,applications,roles,permission,memberships}` — entities; `pkg/model`, `pkg/store`; `MIGRATION.md` (RFC surface + phases).

## OPEN P0 — self-service signup enrolls strangers in the staff tenant

`hanzo-console` / `hanzo-cloud` / `hanzo-gitea` / `hanzo-bot` carry
`enableSignUp: true` with `organization: hanzo` (universe
`infra/k8s/iam/init_data.json`). `signupHandler` files the new user under
`f.Organization`, and `store.MemberOrgRefs` emits `user.Owner` as the HOME entry
of the `orgs` claim — so **anyone on the internet who signs up at hanzo.id is a
signed `member` of the `hanzo` tenant** until they onboard. Cloud reads that
claim as tenancy (correctly — it is the signed membership set), so a
60-second-old anonymous account gets, verified against production 2026-07-28:

- `/v1/projects`, `/v1/sites` — read **and** write **and** DELETE (a probe
  project was created and deleted inside org `hanzo`);
- `/v1/git/repos` — **121 private repos** listed (`cloud`, `universe`, `ci`,
  `console`…), and `/v1/git/repos/<name>/tree` returns their file entries;
- `/v1/crm/contacts` — read + write (PII).

Refused: KMS, `/v1/admin/authors` (SuperAdmin), `/v1/iam/keys`; the billing
ledger is per-account so no money crosses.

The asymmetry is the whole bug, and this repo already states the rule that
closes it — `provision` (onboard.go) refuses an existing org the caller did not
found ("an existing one is refused by the create-conflict check"), while
`signup` happily joins one. Two doors to the same end state, one locked.

NOT fixed unilaterally: every candidate fix trades off badly without an owner
decision. Turning `enableSignUp` off on those apps closes it instantly but stops
customer signup; note also that `server.Seed` is **new-only**, so editing
`init_data.json` does NOT change a live app row — remediation must go through
`update-application`, which then needs a GitOps record. The durable fix is to
stop reading storage `Owner` as membership (`MemberOrgRefs`), with
`BackfillMemberships` already writing the explicit rows that would replace it.
Decide, then do it in ONE place.

## Brand rules (hard)
- Never call Hanzo an "LLM gateway"; never position vs LiteLLM. Full AI cloud, not a proxy.
- `/v1/` only, never `/api/`. Zen models are our own family — never name upstream models.
- White-label by domain; never the Hanzo mark on a Lux/Zoo surface.
