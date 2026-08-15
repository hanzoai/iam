# LLM.md — hanzoai/iam

Canonical **Hanzo IAM** service: identity & access for the Hanzo cloud —
OpenID Connect / OAuth2 with PKCE, JWKS, UserInfo, SCIM 2.0, MFA/WebAuthn,
social federation. The server behind the `@hanzo/iam` SDK. A clean-room
rewrite on the Hanzo stack (`zip` over `hanzoai/orm`) — no Casdoor,
Beego, or xorm. The retired Casdoor fork is `hanzoai/iam-v1` (archived, do not use);
its versions are retracted here — see `TestCasdoorLineageRetracted`.

## License — `MIT OR Apache-2.0`
Dual-licensed at the user's option: `LICENSE-MIT` + `LICENSE-APACHE` (canonical
texts, never edited), `LICENSE` declares the pair. HIP-0130 puts `iam` in the OSS
core tier, so the previous "confidential and proprietary / All rights reserved"
LICENSE contradicted both the HIP and the repo's own public visibility. Every Go
file carries `// SPDX-License-Identifier: MIT OR Apache-2.0` instead of the old
`All rights reserved` header; `go.mod` has no license field, and this repo ships
no Cargo/npm/PyPI manifest, so the SPDX headers plus the three files are the
whole declaration.

Relicensing was Hanzo's alone to do: the tree is original work, not a fork
(`fork: false`, its root commit is its own, and no `v1.*` Casdoor tag is an
ancestor of `main`). Note the Casdoor-lineage tags `v1.0.0`–`v1.31.37` are still
present on this remote even though `go.mod` says they "now live at
`hanzoai/iam-v1`" — anyone checking out one of those tags gets Apache-2.0
Casdoor code under this repo's name. The retraction covers module resolution,
not `git checkout`.

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
`/v1/iam/oauth/device` + `/v1/iam/oauth/device/info` (RFC 8628; `info` names the
client a pending `user_code` belongs to, session-gated, code in the BODY because
a request line reaches access logs) · `/v1/iam/scim/v2/Users`. PKCE `S256` always; `client_id` = `<org>-<app>`.
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

## A mark is how a SUBJECT appears, and a subject is a person OR an org

`schema.Mark` is the pair every subject carries — `avatar`, an image, and
`emoji`, one glyph — with `schema.MarkOf` the one writer. A person already had
`User.Avatar` (published as the OIDC `picture` claim and the SCIM `photos`
value); `Organization` now carries the same two fields under the same names, so
a screen draws a subject without asking which kind of subject it holds.

**Two fields, one answer.** They are two fields because they are two TYPES:
`picture` and `photos` are URL-typed by their specs, so an emoji in `avatar` is
not a smaller answer, it is an invalid one. At most one is ever stored — an image
wins at the WRITE and the emoji does not reach the row — so no reader ranks them
and nothing downstream can rank them differently. Both empty means the subject is
drawn as its initial, which is the only part that is the client's.

**Both halves live on the ROW.** A mark appears everywhere the org does, so it
cannot be kept per device. `Logo`/`LogoDark` are a different thing: the wordmark
a login screen draws. `DefaultAvatar` is a third — the avatar new MEMBERS start
with, not the org's own.

**An image is a REFERENCE.** `https://…`, or the bytes inline as
`data:image/{png,jpeg,gif,webp};base64,…` — which is what a crop performed in a
browser produces, and what `User.Avatar` already holds. IAM stores no blobs and
needs no bucket for this. `schema.AvatarRef` refuses everything else: `http` is a
downgrade on a page served over TLS, and SVG renders in an `<img>` while being a
document that executes. `AvatarLimit` (96 KiB) lives here because the row lives
here — a bound enforced only by the client that writes it binds that client alone.

**`POST /v1/iam/organizations/avatar`** (`setOrganizationAvatar`), body
`{owner, name, avatar, emoji}`, answering the masked org row. Reads need no route:
the pair rides on `organizations`/`organizations/get` like any other column, so a
picker listing orgs gets every mark in the response it already makes.

It is its own op rather than a field on `update` because `update` REPLACES the
record and every read is masked — a client that read an org, changed one field and
posted it back would persist `"***"` over `masterPassword`, `passwordSalt`,
`passwordObfuscatorKey` and `kerberosKeytab`. This one applies two fields to the
row as it stands, so nothing else can be carried in or out on the request.

**Authorization is the one that already existed.** The path's first segment is
`organizations`, so `authorize` reaches the reserved-owner clause and a write
resolves to `p.adminOf(name)` — an org admin manages the org they administer, by
their own `IsAdmin` or an owner/admin membership. Self-service, NOT SuperAdmin:
nothing here consults the reserved `admin` org, and a plain member and a foreign
org's admin are both refused. Pinned by `TestSetAvatar_*`, which drive the real
router with a real bearer.

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
read. Stamping it on `schema.User.AccessKey` authenticated nobody — nothing resolves
that field, and it is not a credential.

**Two key shapes, estate-wide.** `pk-` is publishable and `sk-` is secret; there is no
third. `store.UserByAccessKey` resolves a live `sk-` (pinned to the key row's own
tenant), refuses a `pk-` as `key_wrong_door` — a real credential at the wrong door —
and answers `key_unknown` for everything else, which is what renders the actionable
"mint a new one at cloud.hanzo.ai/keys". A value carrying any other prefix is not a
key, so it takes that same unknown path rather than a branch of its own.

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

## A login descriptor states BOTH halves, or it is a lie

Every sign-in method on `/v1/iam/auth/methods` and `get-app-login` is the AND of
two independent facts, and publishing only the first is how a screen ends up
drawing a button that cannot finish:

    the application switch   the org WANTS this method
    the capability           this BUILD can perform it

    password   app.EnablePassword
    code       app.EnableCodeSignin  && otp.DeliveryConfigured() (a bound Sender)
    webauthn   app.EnableWebAuthn                     (the ceremony is compiled in)
    web3       schema.WalletChains()                           (what verify accepts)
    oauth      offerable(provider)   (real credential AND a driveable dialect)

`loginView` masks the same switches on the legacy descriptor, so the two cannot
disagree — the browser reads whichever one still lies. The org's stored setting is
never edited; only what a screen is told.

Passkeys are the one row where the second half is now a constant true, so it is
not written: `internal/oidc/webauthn.go` carries the assertion ceremony in every
build, so a server that can serve this descriptor can always challenge a passkey.
The predicate that used to stand there (`schema.PasskeySignin`) is gone rather
than pinned to true — a switch nobody can turn off is not a switch.

## The two WebAuthn ceremonies

`internal/oidc/webauthn.go` holds both halves of the standard, on
`github.com/go-webauthn/webauthn`: registration enrolls a passkey, assertion signs
in with one. Four addresses, already called by the hosted login and account pages:

    GET  /v1/iam/webauthn/signup/begin    POST /v1/iam/webauthn/signup/finish
    GET  /v1/iam/webauthn/signin/begin    POST /v1/iam/webauthn/signin/finish

It lives in `internal/oidc` because it is a LOGIN FRONT DOOR, and the three rules a
front door must not forget are unexported here: `callerOf` (cookie-or-bearer, which
is how the portal enrolls with no bearer), `Gate` (the org's second factor), and
`loginGrant` (the one mint path and the session it opens). The passkey ROWS stay in
`internal/webauthn` — one table, written by the ceremony, listed and revoked there,
keyed by the same `schema.CredentialName`.

Half-finished ceremonies ride the existing `LoginChallenge` primitive under two new
kinds, `KindRegister` and `KindAssert`; the go-webauthn session is the row's
`Payload`, the subject is the row's `Subject`, and `TakeChallenge` burns it
atomically. So a replayed assertion loses, and a finish learns whose ceremony it is
from the burned row rather than from the request.

**RP ID is the issuer's host** — `resolveIssuer(host)` parsed, nothing new to
configure. A passkey is bound to ONE relying party for life and the front door
already relocates every request onto its brand's pinned issuer, so the passkey works
at exactly the origin that brand's tokens are issued from. `hanzo.id` and
`hanzo.ai` are separate registrable domains, so ONE passkey cannot serve both:
`admin.hanzo.ai` never runs a ceremony, it federates to `hanzo.id` and the passkey
is challenged there.

**User verification is enforced twice, deliberately.** The relying-party config asks
the browser for it (that is what makes the phone demand Face ID), and the finish
reads the UV bit off the signed authenticator data. The library's own check derives
from `session.UserVerification`, which makes a JSON round trip through the challenge
row; the direct read depends on the assertion alone, so a field lost in transit
cannot silently downgrade a passkey to possession. Each half has a test that fails
when only that half is reverted.

Sign-in is username-first: `signin/begin` takes `?owner=&name=`, and the challenge
is bound to that person. Credentials are enrolled as resident keys, so they ARE
discoverable passkeys on the device — but usernameless (discoverable) sign-in is not
wired, and the login form's username field is required for this method.

## A verification code has ONE receiver key

`otp.Receiver` (internal/otp) is the single canonical form a code's destination is
stored under, matched by, and delivered to. A phone number is
`store.NormalizePhone`d; anything else is verbatim, because NormalizePhone keeps only
digits and would leave an email with nothing to match on. Which one it IS is
`store.LooksLikePhone`, beside NormalizePhone, because "is this a number" and "what
is its canonical form" are one question and sign-in's identifier resolution asks it
too.

EVERY site routes through it, because they all live in the one package: the send that
writes the record, both readers (`otp.Consume`, `otp.Check`), and the second-factor
challenge's own send. Deciding the shape once is what makes the write and the read
unable to disagree: the record used an exact `Receiver=` compare while the ACCOUNT on
the same request resolves through `GetUserByPhone`, which normalizes first, so
"+1 415 555 0134" at send and "+14155550134" at login found the right user and then
answered "the code is incorrect or has expired".

## internal/otp is the one-time code; internal/mfa/factor is the second factor

Two words that are easy to braid and must not be. `otp` is a secret SENT to an
address to prove somebody holds it — mint, word, file, deliver, spend — and it is a
LEAF (store + schema + cred). `factor` is what a second factor IS: `app` (TOTP, whose
secret never travels), `sms`, `email`; whether a passcode verifies; which factors an
account HOLDS (`factor.Has`/`Held`); where a delivered one goes (`factor.Destination`,
the address on the ACCOUNT and never one from a request); and the ONE writer of each
column (`Add`/`Remove`/`Prefer`/`Save`).

`Prefer` holds the invariant the login gate depends on: `PreferredMfaType` names a
factor the account HOLDS. `factor.Enabled` is that column, so a preferred type nobody
enrolled reported "MFA is on" and then left the gate nothing to ask for.

The enrolment surface (internal/mfa) and the login gate
(internal/oidc/mfa_gate.go) are the two callers, and neither owns a second copy of
any of it: one `proveFactor` verifies a challenge answer for both the password and the
federated resume, and the challenge row carries the factors it was minted OFFERING so
an answer is checked against that offer rather than recomputed.

## Key entry points
- `main.go` — cobra root (`serve` / `compare` / `version`); `server/server.go` route registration.
- `internal/{oidc,routes}` — OAuth2/OIDC surface; `internal/{scim,mfa,webauthn,providers,sessions,tokens,cred,authz,certs,keys}`.
- `internal/{users,organizations,applications,roles,permission,memberships}` — entities; `pkg/model`, `pkg/store`; `MIGRATION.md` (RFC surface + phases).

## CORS — two questions, and the edge answers a third

`internal/cors` decides two things about an `Origin`, and conflating them is a
privilege escalation:

1. **May it read?** The DERIVED allowlist — any origin some application already
   registered a `redirect_uri` on. A tenant admin can write into this set, so it
   only ever grants reads of answers that carry no ambient authority.
2. **May it send the SSO cookie and read the answer?** `IAM_SESSION_ORIGINS`, a
   comma-separated list of **exact** origins. Never a suffix, never derived from
   (1). A malformed entry **panics at route registration**, which is the one
   place both `iam serve` and the cloud binary that embeds IAM pass through.

The `[cookie]` paths are exactly the five sites `hanzoai/js-iam`
`src/browser.ts` sends `credentials: "include"` to — `POST /v1/iam/login`,
`GET /v1/iam/web3/nonce`, `POST /v1/iam/web3/verify`, `POST /v1/iam/oauth/revoke`,
`POST /v1/iam/oauth/logout`. A browser DISCARDS a credentialed response that
lacks `Access-Control-Allow-Credentials`, so withholding it on one of them
withholds no privilege — it breaks the call. Only `POST /v1/iam/login` actually
spends the cookie (the single-sign-on branch mints an authorization code from
it); revoke, logout and both wallet legs never read or clear it, so the SDK's
`credentials: "include"` there is inert and the SDK is where that gets fixed.
**`logout` not ending the portal session is a real open defect**, not a CORS one.

`IAM_TRUSTED_ORIGIN_SUFFIXES` is a DIFFERENT list, read nowhere in this repo.
Never wire it to question 2: the fleet serves `<slug>.hanzo.app` as
customer-published sites, so a suffix read of it would name every customer page
a first-party console.

**A proxy can override all of this.** Measured 2026-08-01: hitting the cluster
ingress directly with `Host: iam.hanzo.ai` returns `server: zip`, `Vary: Origin`
and no ACAO; the same request through Cloudflare returns
`Access-Control-Allow-Credentials: true` plus the reflected origin. The
`hanzo.ai` zone reflects a suffix set (`hanzo.ai`, `hanzo.app`, `hanzo.bot`,
`lux.network`, `zoo.ngo`, `zoo.network`, `pars.ai`, `bootno.de`, `ad.nexus`) and
the `hanzo.id` zone reflects **any** origin. `*.hanzo.ai` is SAME-SITE with
`iam.hanzo.ai`, so `SameSite=Lax` does not withhold `hanzo_session` — that is the
reachable path. No Go change closes it; the edge rule has to be narrowed, and
this package must answer correctly FIRST or the narrowing breaks every login.

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

## Onboarding an ORGANISATION — what works, and the three places it stops

Founding the org works and is the good part. `POST /v1/iam/onboard` (session) and
`POST /v1/iam/admin/provision` (service token) both drive one converge: org row +
founder moved in as its admin + one `<slug>-default` metered credential + the
founder's owner membership. Driven live 2026-08-13 against hanzo.id: org created,
`pk-live-…`/`sk-live-…` returned once, roster correct.

Adding the SECOND person is where it stops, in three independent places, and only
the first of them is fixed here.

**1. The invite could not resolve anybody — fixed.** cloud's `sendInvite`
(`apps/team/invite.go`) resolves the invitee with
`GET /v1/iam/users/get?owner=<org>&email=<addr>`. `users/get` took `{owner, name}`
with BOTH required and **no email field at all**, so every invite — of a member,
of a stranger, of anyone — answered `400 field "name" is required` and the RPC
reported "no Hanzo account for <addr> in this org". A schema error wearing the
message of a business rule, which is why it read as working-as-intended and
survived. The read now takes `Lookup{Owner, Name|Email}` and both arms go through
store, so this surface and the login that authenticates the same address cannot
disagree about who it names. Ambiguity is REPORTED (409), never flattened to
not-found: two rows in one org can carry one address, and answering with an
arbitrary one of them is how a person joins a team under a colleague's identity.
Authorization is unchanged by construction — a REST read's target rides in the
query and `authz.ReadTarget` reads `owner`/`name`, so an address read authorizes
exactly like `?owner=<org>` already did and discloses strictly less than the org
listing the same caller may already fetch. `Ref` (both halves required) still
addresses the WRITES: an address is a mutable attribute, and resolving one to
decide who gets written puts a rename between the authorization and the write.

**2. The invitee has no account IN the org, and nothing can give them one.**
Signup files everyone under the APP's org and refuses any other, so a teammate
who signs up at hanzo.id is `hanzo/<name>`, never `acme/<name>` — and an invite
scoped to `?owner=acme` will not find them however it is spelled. `add-membership`
IS the working grant (measured: the invitee's next token carried
`orgs:[{hanzo,member},{zzb2b1,member}]` and `/v1/projects` with `X-Org-Id` then
answered 200), but it takes an identity that already exists. The `invitations`
entity — `/v1/iam/invitations` CRUD over `schema.Invitation`, carrying Email,
Code, Quota, UsedCount, State — is **redeemed by nothing**: no signup hook, no
accept endpoint, no reference outside its own package and the route table. So
there is no invite for a person who does not yet have an account, which is the
ordinary B2B case. The console's onboarding step says "Pick an organization you
belong to, or create a new one" above a form that only creates one
(`id` `pkgs/onboarding` OrgStep states this deliberately: "Joining an existing org
happens by invitation, handled outside this flow" — there is no outside).

**3. Founding an org locks the founder out of the front door.** The move re-keys
the identity, and sign-in resolves the account inside the org the FORM states —
`resolveLoginUser(ctx, db, f.Organization, identifier)`. The portal always states
the APP's org (`id` `pkgs/auth/src/ui/LoginForm.tsx`: `app?.organization`), which
for `hanzo-console` is `hanzo`. Measured 2026-08-13 in a real browser: a founder
moved into their new org typed the correct password at hanzo.id and got "the
username or password is incorrect"; the control — the same password, the same
screen, a probe still sitting in `hanzo` — signed in and landed on `/onboarding`.
The server already supports the right answer (`organization=<slug>` posted to
`/v1/iam/login` returns 200 for the same account); nothing tells the screen which
org to name. Orgs that were hand-given an application of their own are unaffected
— `karma-style`→`karma`, `sdm-cloud`→`sdm` — which is why this has not been
reported: every org with a live customer has an app, and every self-service org
does not.

NOT fixed here, deliberately. Every candidate touches an authentication boundary:
a cross-org fallback by address is the F-2 collision this repo removed on purpose
(it resolved `z@hanzo.ai` onto `admin/*` and coupled lockout counters across
rows), a domain→org map is a new tenant primitive the Organization schema has no
field for, and an org picker on the login screen is policy about what a stranger
may learn. Decide it, then do it in ONE place — and note the same 2026-08-13
census that measured it: 82 orgs, 354 human accounts, **279 of them (79%) sitting
in org `hanzo`**, which is the P0 above and the reason the second person has
nowhere to be.

## Brand rules (hard)
- Never call Hanzo an "LLM gateway"; never position vs LiteLLM. Full AI cloud, not a proxy.
- `/v1/` only, never `/api/`. Zen models are our own family — never name upstream models.
- White-label by domain; never the Hanzo mark on a Lux/Zoo surface.
