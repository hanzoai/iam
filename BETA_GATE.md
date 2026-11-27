# IAM-only beta gate — `hanzo.bot` and `hanzo.team`

Two production sites are beta-gated at identity issuance, not at the edge and
not by org confinement:

| Redirect host (exact, case-insensitive, port dropped) | Platform switch |
|---|---|
| `hanzo.bot`, `bot.hanzo.ai` | `beta.bot` |
| `hanzo.team`, `www.hanzo.team` | `beta.team` |

Staff pass without a flag read: SuperAdmins (`schema.User.SuperAdmin`, an
account **in** the `admin` org) and human org admins of a platform-registered
application's own brand org (`app.Owner == "admin" && user.Owner ==
app.Organization && user.IsAdmin && !user.Machine()`). Both are required
because `MintFor` confines `admin/*` accounts to `admin`-org apps, so platform
owners sign in to `hanzo.bot` and `hanzo.team` with their `hanzo` org admin
account. Everyone else — including customer-founded personal orgs (where
`user.Owner != app.Organization`) and non-admin brand-org members — needs the
matching switch on for their OIDC `sub` in the cloud flags app. A lookalike
host is not in a group.

## Why the host, not the client id

`hanzo-app` serves many hosts; `team`, `team2` and `team-native` all serve
`hanzo.team`. A client-id gate would either open every host a shared client
serves or close the right ones. The gate therefore reads the **redirect host**,
which IAM has already matched against the application's registered URI list
(`internal/oidc/authorize.go` step 2, re-checked by `MintFor`) before any code
is minted. A client cannot choose this value.

## Where enforcement lives (IAM)

- `internal/oidc/beta.go` — `betaKeyForRedirect`, `BetaGate`, `BindBetaGate`,
  `betaAdmit`, `errBetaDenied`.
- `internal/oidc/mint.go` — `MintFor` is the **one** code-mint path. After the
  redirect/PKCE/tenant checks and before `MintCode`/`PersistToken`, a gated
  redirect asks `betaAdmit`. A refusal returns `errBetaDenied`; no code exists.
- `internal/oidc/prompt.go` — `silentGrant` mints through `MintFor`, so
  `prompt=none` cannot leak a code. A refusal is mapped to OIDC
  `access_denied` on the registered redirect. An unauthenticated `prompt=none`
  is still `login_required`, decided before any principal exists.
- `internal/oidc/login.go` — interactive `POST /v1/iam/login` also mints
  through `MintFor`; `errBetaDenied` returns a structured JSON error
  (`code: "access_denied"`) so the login UI's `fetch()` never chases a
  cross-origin 302 into CSP/CORS failures.
- `server/server.go` — re-exports `BetaGate`, `BindBetaGate`,
  `BetaGateBound` so a composing host can install the source.

With **no source bound**, the gate fails closed: non-staff get no code for a
gated host; staff still pass. An unreadable flag is off.

## The cross-repo contract (what cloud must supply)

IAM cannot import the cloud flags app: cloud imports IAM (69 Go files), so the
reverse import is a cycle. IAM also has no flag-bearing header and no plane
client of its own. The least invasive existing mechanism is the **host-bound
seam** already used for delivery (`iamserver.BindSender` ← `apps/iam/sender.go`):
the host that owns both the router and the flags app binds what IAM can only
ask for.

Cloud side (implemented in this change set):

- `apps/flags/betas.go` registers `bot` and `team`; `BetaKey("bot")` and
  `BetaKey("team")` are the keys. Staff already get every `beta.*` through
  `apps/flags/access.go` `staffed()` — **do not duplicate that in IAM or here**.
- `apps/iam/beta_gate.go` implements `iamserver.BetaGate` with
  `flagplane.FlagsOn` over the internal plane. The org and OIDC `sub` ride the
  caller (`zip.WithCaller`), not a request field; the answer is bounded
  (`betaGateWait`), and an error/no-peer is returned so IAM fails closed.
- `apps/iam/iam.go` calls `bindBetaGate()` at Mount beside `bindDelivery`.

### Still needed by Zach / another repo (integration, not configuration)

1. **Dependency bump.** `apps/iam/beta_gate.go` calls `iamserver.BindBetaGate`,
   which only exists in the IAM worktree change set. Cloud's `go.mod` pins the
   released `github.com/hanzoai/iam`; that module must be released with this
   gate and cloud's `go.mod` bumped before cloud compiles with the binding.
   Until then cloud's `apps/iam` does not build against the released module —
   this is the one blocking cross-repo step. It was verified locally with a
   temporary `replace` to the IAM worktree (see the test evidence in the
   parent session); that `replace` is machine-specific and was not left in the
   worktree.
2. **Deploy/wiring confirmation (no live change made here).** Confirm the
   flags app is deployed wherever IAM serves these sites so `flags_on` answers.
   With no flags app, the gate denies non-staff — by design. No live config,
   flag grants, DNS, or edge rule was touched by this change.
3. **Grant the beta users** through the existing cockpit flow
   (`POST /v1/admin/flags/beta.bot|beta.team/grant`). Who gets in is unchanged:
   SuperAdmin-targeted, per person/org, never self-serviceable.

## Tests

- IAM: `go test ./internal/oidc -run TestBetaGate -count=1 -v` — host mapping;
  staff allowed (with no source and with the flag off); non-beta denied with no
  code; beta-granted allowed; unreadable flag off; no source fails closed; other
  hosts unaffected; `prompt=none` denied for non-beta, `login_required` when
  unauthenticated; interactive login with valid credentials denied with
  `access_denied` and no code, allowed once the switch is granted.
- Cloud: `go test ./apps/flags -run TestBetas -count=1 -v` — both switches
  registered, principal bool, staff-covered; `go test ./apps/iam -run
  TestBetaGate -count=1 -v` — binding installed, empty principal refused.
