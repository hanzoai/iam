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
- Image: `ghcr.io/hanzoai/iam`. Go 1.26.

## Embedding — a host GRAFTS the app, it does not adapt a handler

Two entry points, and they are different verbs for different situations:

| call | what it does | when |
|---|---|---|
| `server.NewApp(db) *zip.App` | the whole IAM surface as a self-contained app | a host composing IAM in process: `app.Graft(iamserver.NewApp(db))` |
| `server.Route(app, db)` | registers IAM's routes ONTO the host's app | only when the host genuinely wants IAM's routes co-mingled with its own. It also brings IAM's root-level routes onto the host, which is what shadowed a host console once |

`server.Handler(db) http.Handler` is **deleted** (was: `adaptor.FiberApp(NewApp(db).Fiber())`).
It existed so a host could hang the whole surface on one wildcard —
`app.All("/v1/iam/*", zip.AdaptNetHTTP(iamserver.Handler(db)))` — and that
adapter is where IAM's knowledge died. `AdaptNetHTTP` takes an `http.Handler`
and returns a closure, so the App went in and a bare function came out, and
IAM's **94 typed ops** went with it. hanzoai/cloud published five wildcard path
keys and 35 placeholder operations where 78 real paths and 94 typed operations
were — no schema, no MCP tool, no CLI command, no SDK method for any of them.

`zip.Graft` (zip v1.18.16) is the composition that keeps them: the host's router
learns IAM's route patterns AND its op registry, while IAM's own router keeps
IAM's behaviour — its `Use(authz.Guard)` seam, its error handler, its config.
Serving is unchanged and strictly cheaper (no net/http round trip). IAM's
`Authorizer` still runs on IAM's ops; the host never re-authorizes them under
its own rules. Named types are published as `iam.<Type>`, because a composed
document carries more than one app's `Application`.

**Liveness is not IAM's.** `/healthz`, `/readyz` and `/metrics` are zip's ops
surface (HIP-0119 §1) — a SECOND listener the DEPLOYMENT brings up when it names
`OPS_PORT`, never the public one. IAM used to register `/healthz` on its public
group; that was hand-rolling a path the framework owns, on the wrong listener,
and it is also what made IAM un-composable: a host registers `/healthz` as the
HOST's, because it must answer while every subsystem is still cold. Two
claimants on one liveness address is what once served `{"binary":"iam2"}` out of
a shared binary.

## Endpoints (HIP-0111 — /v1 only, no /api, no vendor verbs)
`/.well-known/openid-configuration` · `/v1/iam/.well-known/jwks` ·
`/v1/iam/oauth/{authorize,token,introspect,revoke,userinfo,logout,callback}` ·
`/v1/iam/scim/v2/Users`. PKCE `S256` always; `client_id` = `<org>-<app>`.
Brands set `serverUrl`: hanzo→iam.hanzo.ai, lux→lux.id, zoo→zoo.id,
bootnode→id.bootno.de, pars→pars.id (white-label by domain).

## A principal is `owner`/`name` — org and USERNAME, on every surface

**The rule.** `owner` is the org. `name` is the USERNAME (`<name>` of
`<owner>/<name>`). A display name never appears in `name`, in a token or in
UserInfo; it has its own claim, `displayName`. `preferred_username` is the
OIDC-standard spelling of the same username and is sourced from the same field,
so the two cannot drift.

**Why.** `hanzo auth login` files its credential under the token's own
`owner`/`name`, so those claims ARE the principal downstream believes it holds.
`userClaims` computed `name = DisplayName, else Name` — OIDC's display reading of
`name`, inherited from the v1 `Userinfo` struct and present since the in-tree
server was written (`73b7ef63e`). Measured on iam.hanzo.ai 2026-07-30: a login as
account `z` minted `name: "Zach Kelling"` and the CLI filed `hanzo/Zach Kelling`,
an account that does not exist. cloud's money path had already paid for the same
reading — it addresses a wallet `<org>/<username>`, addressed `hanzo/Zach Kelling`
and 402'd every completion while the balance sat in `hanzo/z`. `5c0ea823f`
answered that by ADDING `preferred_username` and deliberately leaving `name`
display-sourced, which gave the username a home without evicting the display name
from the claim consumers actually read; the CLI then hit the wall from the other
side. One address for a principal beats two spellings that disagree, so `name` is
the username and OIDC's display reading of it is the thing we diverge from.

**One resolution, one claim builder.** Three mint paths — the code/refresh/password
grant, the console's issue-user-token, and the RFC 8693 exchange — had each
SEPARATELY written the `DisplayName, else Name` fallback, so fixing one would have
left two. `identityOf` is now the only user→claims resolution and `Signer.claims`
the only place an `Identity` becomes a claim set. The values also stopped
travelling as six adjacent positional strings: two of them are human-readable and
were therefore swappable at the call site, they WERE swapped on all three paths,
and it type-checked (the wallet harness had lost a scope into the username slot
the same way). UserInfo answers identically — it and the token describe one
principal, and a client holding either must not get two names for it.

## Usernames — one rule, at the write

`schema.Username`: trim, lowercase, `^[a-z0-9][a-z0-9._-]{0,62}$`. Normalization
settles case and padding; everything else is REFUSED rather than rewritten,
because quietly turning what someone typed into a different principal is the
failure being avoided. One character is legal (the account this was written over
is `z`); a leading digit is legal (nothing resolves a principal numerically).

Ten entry points reach a user row and exactly ONE used to validate the name it
wrote. The rule now lives at `users.Create` — the choke point six of them share —
plus the three that write through orm directly (bootstrap's first-admin seed, the
wallet identity, the onboarding credential). `CreateInput.AuthzTarget` normalizes
too, so the pair AUTHORIZED is the pair STORED. Service accounts keep only what is
theirs: `<org>-` binding and segmentation.

**Social signup derives from the ADDRESS, never the profile.** `schema.Handle`
takes the email local part and refuses a string with no `@` or a local part with
whitespace — without both, "Zach Kelling" is a local part whose space gets dropped
and the profile name silently becomes the username `zachkelling`. Dedupe is a
numeric suffix (`z`, `z2`, `z3`), replacing a random 8-hex suffix on every name
that made collisions impossible by making every username unrecognisable.

**Case does not make a second person, and stored names are NOT rewritten** —
renaming moves real principals. `store.GetUserByName` resolves exact, then folded,
then over the org for a legacy mixed-case row, and FAILS CLOSED on an ambiguous
fold (the rule `GetUserById` already applies to a duplicated subject), so whoever
registered "ALICE" alongside "Alice" is never resolved as the other. `users.lookup`
goes through it rather than repeating the query — restating it is how Create's
uniqueness check stayed case-SENSITIVE while the rule it guards is not.

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

## Refresh — confidential is a property of the GRANT, and a lifetime must be SAID

Two independent defects made `refresh_token` unusable for every client that signs
in through a browser, so a session died at the access token's expiry and the user
logged in again. Measured on `hanzo-cli` 2026-07-31: a live refresh answered
`401 invalid_client`, and the refresh token was already expired anyway.

**Client auth.** `authorizationCodeGrant` has a documented relaxation — a
registration that HOLDS a secret still serves a public PKCE surface (`hanzo-cli`,
and every `@hanzo/iam` SPA whose secret exists for a backend path), so a code
exchange that presents no secret is authenticated by PKCE instead.
`refreshTokenGrant` did not have it and demanded the secret unconditionally: the
client completed the exchange without one, cannot acquire one, and is refused the
moment it tries to renew. The fact is now recorded where it belongs — on the
GRANT, `schema.Token.PublicGrant`, set at establishment and carried across
rotation (drop it and only the FIRST refresh works). It never widens: a grant
established WITH the secret still needs it, and a presented secret is always
verified.

**Lifetime.** `refreshTTL` falls back to `appTTL` when `RefreshExpireInHours` is
unset — v1 parity, and dead on arrival: the refresh token expires at the same
instant as the token it renews. Nothing could say otherwise, because the upsert
body carried no lifetime field at all. `expireInHours` / `refreshExpireInHours`
now travel document → `provision.App` → upsert → model under ONE name, as
POINTERS on the wire so an omitted lifetime PRESERVES (a plain float would reset
every app on every converge). `provision.checkLifetimes` REFUSES a refresh
lifetime that does not outlive the access lifetime, measured against
`schema.DefaultExpireInHours` when the access lifetime is unstated — so the state
`hanzo-cli` shipped in cannot be declared again.

**Which half bit whom** (measured over all 286 live applications on hanzo.id).
Most first-party clients already carried `expireInHours: 168` +
`refreshExpireInHours: 720` from the v1 era, so for `hanzo-cloud`, `hanzo-chat`,
`hanzo-platform`, `hanzo-world` the LIFETIME was fine and only the CLIENT-AUTH
half was broken — they held a 30-day refresh token they could not spend. One fix
unblocks all of them: driven live after the change, each does code→token 200 then
refresh 200 with a new access token, presenting no secret at either step.
`hanzo-cli` was the rare client with BOTH lifetimes at 0, which is why it was the
one that hurt. Still at 0, and therefore still dead on arrival: `hanzo-mcp` (now
declared, same as the CLI), `hanzo-git`, `hanzo-zrok`, `hanzo-admin`, and every
auto-created per-signup `app-<email>` client. The fix is one line per app in that
org's provision document; it is deliberately NOT a changed global default,
because session lifetime is POLICY and this mechanism ships no policy.

## Device grant — a CLI holds NO secret, and ROPC must then refuse it

`hanzo auth login` died on `invalid_client: client authentication failed`
straight out of `POST /v1/iam/oauth/device`, for every client, so nobody could
sign in from a terminal.

**Cause.** `deviceHandler` requires the stored secret from any registration that
HAS one (RFC 8628 §3.1 → 6749 §3.2.1), and every Hanzo client was declared
`type: confidential` in the provision document — deliberately, because
`client_credentials` and the password grant authenticate with that secret and a
public upsert DELETES it (`bootstrap.resolveSecret`). So all 12 held one, and a
CLI can never present one. The code exchange survived the same registration
shape only because `authorizationCodeGrant` skips client auth when a PKCE
challenge is present; the device grant carries no challenge to skip on, so it
had no such escape. `invalid_client` distinguishes the two cases — `client_id is
invalid` means unknown, `client authentication failed` means known-and-holds-a-
secret — which is how the cause was read straight off the wire.

**Fix.** `hanzo-cli` is `type: cli` in the universe provision document: PUBLIC,
no stored secret, loopback redirects per RFC 8252 §7.3, with the device grant
declared through the additive `grants:` field rather than added to
`grantsByType[cli]` — same reason `redirects` is additive, a type default would
silently hand RFC 8628 to every future CLI client in every org. No image was
needed; `make iam-provision` converged it.

**The rule this forced.** Going public silently opened ROPC. `passwordGrant`
gates on the `enablePassword` FLAG, not on `grantTypes`, so removing `password`
from the document changed nothing — and the grant had a legacy-parity relaxation
that let a public client through, carried so console/chat would not 401 during
the cutover. With no stored secret and no PKCE challenge and no human approval
step, "public" there means anyone who knows the client_id can post a username and
password. `passwordGrant` now REFUSES a client with no stored secret. The
relaxation was dormant (every live registration is confidential and takes the
secret path), so nothing that worked broke. The rule lives on the GRANT, not in a
document, because registration shape must not be able to open a credential
surface — the same lesson as `Token.PublicGrant` above, in the other direction.

**One client id.** `hanzo-cli` is the id BOTH CLIs authenticate as — Rust
`hanzoai/cli` (`src/iam/oauth.rs` `CLIENT_ID`) and the Go control CLI
(`hanzoai/cloud` `cli/cli.go` `defaultClientID`). The Go one had been borrowing a
different first-party client per flow (`hanzo-app` for device, `hanzo-console`
for password and refresh); besides being unregistrable, that guaranteed renewal
could never work, because a device_code is redeemable only by the client it was
issued to and a refresh token was being presented under a different id.

## Key entry points
- `main.go` — cobra root (`serve` / `compare` / `version`); `server/server.go` route registration.
- `internal/{oidc,routes}` — OAuth2/OIDC surface; `internal/{scim,mfa,webauthn,providers,sessions,tokens,cred,authz,certs,keys}`.
- `internal/{users,organizations,applications,roles,permission,memberships}` — entities; `pkg/model`, `pkg/store`; `MIGRATION.md` (RFC surface + phases).

## Sign-up is risk-gated (`internal/risk`, `internal/oidc/signup_gate.go`)

`POST /v1/iam/signup` asks the platform scoring plane — `POST /v1/risk/decide`,
stage `signup` — before it writes anything. IAM does **not** score: velocity,
address/ASN reputation, disposable-mailbox lists and multi-account linkage live
in the risk plane over a per-org feature surface IAM cannot see, and a second
scorer would be a second answer to one question.

**Order is the design.** Every deterministic check (app policy, reserved org,
tenant gate, username, uniqueness, email, password floor) runs FIRST, then the
gate, then every write. So a typo costs no screen, and a refused sign-up leaves
nothing behind — including the organization, which self-serve creation used to
mint *before* the user was validated.

**Outcomes.** `allow`/`review` → the account is created. `challenge` → answered
with the protocol string `RequiredVerify` (beside `RequiredMfa`/`NextMfa`); the
client calls `send-verification-code` and re-posts the sign-up with `code`.
Presenting a code SPENDS it (`SpendVerificationCode`, was `CheckVerificationCode`):
a code that survived being presented would let one proven address open account
after account for the rest of its ten-minute window, which is exactly the
multi-account abuse the challenge exists to stop. Burned before the answer
returns, mirroring authorization-code redemption; a burn that cannot be written
fails closed. `block`/`restrict` → one opaque
refusal carrying a decision reference and nothing else.

**Fail policy — one function, `risk.unavailable`.** An ordinary sign-up ALLOWS
when the scorer is unreachable (never break login). A sign-up that would MINT A
TENANT is a grant of standing authority and REFUSES — but only on an ARMED
deployment. `RISK_URL` unset means no risk plane was ever wired here, and
refusing to onboard because a component does not exist is an outage, not a
defense; that case allows and is recorded as `scorer-absent`. Same semantic as
the cloud edge, whose arming signal is the per-org `mode=live`.

**Records.** Durable first: every decision is a `schema.AuditLog` row
(`signup.risk.<action>`) written before the client is answered, carrying the
decision id, action, score, cause, refusal and `scored` — never the request body,
because the sign-up form carries a password. The analytics COPY goes to
`/v1/event` afterwards, best-effort, on its own background context.

Config: `RISK_URL` (scorer origin), `EVENT_URL` (analytics door), credential =
the unified service token (`httpx.ServiceToken`). All three unset = inert gate.

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
