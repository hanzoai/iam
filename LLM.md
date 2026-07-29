# LLM.md — hanzoai/iam

Canonical **Hanzo IAM** service: identity & access for the Hanzo cloud —
OpenID Connect / OAuth2 with PKCE, JWKS, UserInfo, SCIM 2.0, MFA/WebAuthn,
social federation. The server behind the `@hanzo/iam` SDK. Proprietary,
clean-room rewrite on the Hanzo stack (`zip` over `hanzoai/orm`) — no the legacy surface,
Beego, or xorm. Retired the legacy surface fork = `hanzoai/iam-v1` (do not use).

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

## Org scope — HONOURED or REFUSED, never silently reinterpreted

**The rule.** A request that NAMES an organization gets that organization's data
or an error. It never gets a different organization's data. `authz.Scope` is the
one place it lives; all 17 org-scoped call sites resolve their owner there.

| principal | `?owner=` | result |
|---|---|---|
| SuperAdmin (org `admin`) | anything | honoured; empty = every tenant |
| anyone else | absent | own org (unstated ≠ reinterpreted) |
| anyone else | its own org | honoured |
| anyone else | **any other org** | **403, no rows** |
| anyone else, `p.Org == ""` | anything | **403** (no org ⇒ no scope; `""` used to mean *no filter* = every tenant) |

**Why.** `Scope` used to `return p.Org` for ANY owner. Measured in production
2026-07-28 with the `hanzo-console` credential (home org `hanzo`): `?owner=lux`,
`?owner=zoo` and `?owner=nonexistent-org-xyz` each answered `200 {"status":"ok"}`
with 262 **`hanzo`** accounts. Nothing in the code, the `status` field, the `msg`
or the count said the filter had been dropped, so a fabricated org was
indistinguishable from a real one *and* from your own. No rows escaped IAM, so it
was not a confidentiality breach here — it was **misattribution**, which is worse
in one specific way: you believe you hold tenant B while holding tenant A. It
nearly caused a production purge of the wrong tenant. Downstream it *was* a leak:
cloud's IAM edge (`cloud/iam_edge.go`) validates `?owner=` against the calling
tenant and then forwards it under ONE confidential client, so every tenant's team
page asked for its own org and was served the edge credential's org.

**Not an existence oracle — by construction, not by care.** The refusal is decided
from the verified principal alone and never touches the store, so `lux` (real),
`built-in` (reserved) and `nonexistent-org-xyz` (invented) are the same comparison
and the same bytes; the message names the CREDENTIAL's org, never the requested
one. Same collapse cloud's per-org KMS store makes: every spelling you may not
have routes to ONE existence-independent answer. It differs only in *which*
answer — KMS reads the org from the token, so absence is its only observable and
it answers 404; here the org is a stated parameter, so there is a decision to
report and reporting it is the point.

**Cross-tenant reach exists only where a grant says so**, and a grant HONOURS the
org it names (returning that org's real data, correctly attributed) — it never
substitutes:
- **SuperAdmin** — every entity. The only unrestricted cross-tenant scope.
- **`CapOrgAdmin`** — the organization REGISTRY only. Brand consoles create
  customer orgs during onboarding and read `Organization.Founder` to resume a
  partial one, so registry-wide reach is load-bearing, not incidental.

So `get-users` and `get-organization` now **agree on the only question carrying a
secret**: for every principal without a cross-tenant grant both refuse a foreign
org existence-independently, so neither is an oracle. For a `CapOrgAdmin` holder
org existence is *not* a secret — it can create orgs and read `Founder`, so hiding
reads from it would be theatre. What can no longer happen anywhere: **being handed
org A's rows in answer to a request that named org B.**

**A rewrite is not a safe answer, only an unsampled one.** The old SCIM guard
(`scim/read_scope_test.go`) proved foreign-exists and foreign-missing were both
404 and called the oracle closed. It was: the re-pin turned `/Users/orgb/bob` into
a lookup of `hanzo/bob`, absent. Seed a `hanzo/bob` — a name every tenant has —
and the same request returns **200 carrying hanzo's bob under orgb's URL**, and
`PATCH active:false` then deactivates a hanzo employee. Pinned by
`TestRed_scimGet_foreignIdNeverResolvesToASameNamedLocalUser`.

**Divergence still open (needs a decision, do not "fix" by widening).** The legacy
verb lister goes through `Scope`; the native noun lister (`organizations.List`)
filters `in.Owner` under the Guard's authorization. For a `CapOrgAdmin` app,
`get-organizations?owner=admin` is now a 403 while `/v1/iam/organizations?owner=admin`
returns every org row (masked). Before this change it was 403-vs-a-silently-EMPTY
list, so nothing regressed — but one policy still answers two ways on two
spellings. Unifying it changes a documented capability's blast radius: decide it
deliberately, in `authorize()`, not by opening the legacy lister.

## API keys — one entity, one plural noun, and the SCOPE is what differs

`internal/keys`, entity `keys`, routes `/v1/iam/keys{,/get,/update,/delete}`.
**Plural on every op** (like `users`): `authz.entityOf` reads the FIRST path segment
as the entity, so serving the list at `keys` and the writes at `key` made two entity
strings for one entity — and any capability keyed on it was dead on whichever half
you did not name. Same defect `entityNoun` fixes for the legacy verb spellings.

`Scope` is the ACCESS CLASS, fixed at create (an update that could flip it would
blank a secret and open the ingest door):

| scope | halves | resolves to | door |
|---|---|---|---|
| `""` (secret) | `pk-` + `sk-` | the USER | `get-user?accessKey=` (`CapKeyResolve`) |
| `publish` | `pk-` only, NO secret | just the ORG | `resolve-key` (`CapPublishableResolve`) |

**The publishable key had no producer until 2026-07-28.** The model, the resolver
(`store.PublishableKeyByAccessKey`) and the ingest door all existed and nothing
minted one. It is now a FIELD on the one mint:
`POST /v1/iam/mint-user-keys?id=<owner>/<name>&type=publishable|secret` (default
secret; unknown type → 400), same for `revoke-user-keys`. `keys.NameFor(scope)` maps
scope → row name (`cloud-api` / `publishable`), so the two are separate rows and
rotating a browser key does not revoke the API key.

**Every read is masked.** `schema.Key.Mask()` blanks `AccessSecret` and keeps
`AccessKey` (a `pk-` is public and its holder needs it). Before it, the key list
handed every reader every secret in the org, which made read AUTHORIZATION stand in
for redaction. The secret is revealed ONCE, by `create`. `capFor("keys")` =
`CapKeyMint`: the authority that already mints a credential may read the set it
manages.

`MintUserKey` writes a `schema.Key` ROW because that is the only thing the resolvers
read. Stamping it on `schema.User.AccessKey` authenticated nobody AND overwrote the
holder's working legacy `hk-`, locking them out with no path back through the UI.

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
