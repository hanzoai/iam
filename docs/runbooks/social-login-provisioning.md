# Social-Login Provisioning (Phase 1)

Owner action required. This runbook provisions the six OAuth applications
(GitHub × 3 envs, Google × 3 envs) and produces 12 environment-variable
assignments that feed into Phase 2 (KMS provisioning).

## Why six apps

IAM serves three environments — mainnet (`iam.hanzo.ai`), testnet
(`iam.test.hanzo.ai`), devnet (`iam.dev.hanzo.ai`) — and OAuth providers
require an exact callback URL match per app registration. Sharing one
GitHub OAuth app across all three envs would force one callback URL,
collapsing the env separation.

## Naming convention

```
hanzo-iam-<env>    (where <env> ∈ { mainnet | testnet | devnet })
```

Used identically on GitHub and Google for inventory consistency.

## GitHub (3 apps)

Account: `hanzoai` org. Required role: org **owner** (only owners can
register OAuth apps under an org account).

Per app:

1. https://github.com/organizations/hanzoai/settings/applications/new
2. **Application name**: `hanzo-iam-<env>`
3. **Homepage URL**:
    - mainnet: `https://hanzo.ai`
    - testnet: `https://test.hanzo.ai`
    - devnet:  `https://dev.hanzo.ai`
4. **Authorization callback URL**:
    - mainnet: `https://iam.hanzo.ai/v1/iam/callback`
    - testnet: `https://iam.test.hanzo.ai/v1/iam/callback`
    - devnet:  `https://iam.dev.hanzo.ai/v1/iam/callback`
5. **Enable Device Flow**: off (we use OAuth web flow only).
6. **Application description**: `Hanzo IAM — <env> — social login`.
7. Click **Register application**.
8. Record the **Client ID** (visible immediately).
9. Click **Generate a new client secret**. Record the **Client secret**
    (visible exactly once).

> Note: the callback path is `/v1/iam/callback`. This is the canonical
> path served by IAM's `routers.Callback` handler. Legacy
> `/api/callback` (and `/callback`) are still rewritten to the same
> handler by `path_rewrite_filter.go`, so registering either form works
> — but new apps should use the canonical path so the audit log is
> consistent.

## Google (3 OAuth client IDs)

Project: `hanzo-ai` GCP project. Required role: project **Editor**
or higher on the OAuth consent screen.

OAuth consent screen (one-time, project-wide):

- **User Type**: External
- **App name**: Hanzo
- **User support email**: ops@hanzo.ai
- **Authorized domains**: `hanzo.ai`
- **Developer contact information**: ops@hanzo.ai
- **Scopes**: `openid`, `profile`, `email`
- **Test users** (during pre-publish): add the seed accounts you use
  during phase-2 verification.
- Publish state: **Production** (so all hanzo.ai users can sign in).

Per env:

1. https://console.cloud.google.com/apis/credentials → **Create
    Credentials → OAuth client ID**.
2. **Application type**: Web application.
3. **Name**: `hanzo-iam-<env>`.
4. **Authorized JavaScript origins**:
    - mainnet: `https://iam.hanzo.ai`
    - testnet: `https://iam.test.hanzo.ai`
    - devnet:  `https://iam.dev.hanzo.ai`
5. **Authorized redirect URIs**:
    - mainnet: `https://iam.hanzo.ai/v1/iam/callback`
    - testnet: `https://iam.test.hanzo.ai/v1/iam/callback`
    - devnet:  `https://iam.dev.hanzo.ai/v1/iam/callback`
6. Click **Create**. Record the **Client ID** and **Client secret** from
    the dialog (the JSON download is also fine — secret is the
    `client_secret` field).

## Output: 12 env-var assignments

Drop the recorded values into the templates below — these go straight
into Phase 2 (KMS provisioning):

```text
# --- MAINNET ---
GITHUB_CLIENT_ID_MAINNET=<github-mainnet-client-id>
GITHUB_CLIENT_SECRET_MAINNET=<github-mainnet-client-secret>
GOOGLE_CLIENT_ID_MAINNET=<google-mainnet-client-id>
GOOGLE_CLIENT_SECRET_MAINNET=<google-mainnet-client-secret>

# --- TESTNET ---
GITHUB_CLIENT_ID_TESTNET=<github-testnet-client-id>
GITHUB_CLIENT_SECRET_TESTNET=<github-testnet-client-secret>
GOOGLE_CLIENT_ID_TESTNET=<google-testnet-client-id>
GOOGLE_CLIENT_SECRET_TESTNET=<google-testnet-client-secret>

# --- DEVNET ---
GITHUB_CLIENT_ID_DEVNET=<github-devnet-client-id>
GITHUB_CLIENT_SECRET_DEVNET=<github-devnet-client-secret>
GOOGLE_CLIENT_ID_DEVNET=<google-devnet-client-id>
GOOGLE_CLIENT_SECRET_DEVNET=<google-devnet-client-secret>
```

> Store these in a temporary, encrypted scratch file (e.g. age + delete
> after Phase 2). Never paste into Slack, email, or git.

## Verification

After provisioning, sanity-check each registration by visiting the
authorize URL directly:

```bash
# GitHub (replace <client-id> per env)
open "https://github.com/login/oauth/authorize?client_id=<client-id>&redirect_uri=https://iam.hanzo.ai/v1/iam/callback&scope=read:user"

# Google
open "https://accounts.google.com/o/oauth2/v2/auth?client_id=<client-id>&redirect_uri=https://iam.hanzo.ai/v1/iam/callback&scope=openid+profile+email&response_type=code"
```

A correctly-configured app shows the OAuth consent screen; a misconfigured
one shows "redirect_uri_mismatch" or "client not found". Fix mismatches
in the registration before moving to Phase 2.

## Rotation

Recommended cadence: every 12 months, or immediately on suspicion of
secret exposure.

1. Issue a new client secret in the provider console.
2. PATCH the KMS secret (see Phase 2 runbook).
3. Restart the IAM deployment (`kubectl rollout restart deploy/iam`) to
    pull the new value into the init-providers Job's env.
4. Revoke the old secret only after `iam init-providers -v` reports
    `[upd ] provider-github` (or google) cleanly.

## Troubleshooting — "password or code is incorrect" on GitHub/Google

This one message covers several distinct causes. Diagnose by the IAM pod log
(`kubectl -n hanzo logs deploy/iam`), NOT the browser text — the browser wraps
every provider failure in the same generic string.

| IAM log line | Real cause | Fix |
|---|---|---|
| GitHub token endpoint returns `incorrect_client_credentials` | The provider row's `clientSecret` is wrong/stale | Re-provision the secret (Rotation, above). Confirm with a direct probe (below). |
| `GithubIdProvider.GetUserInfo: GET /user/emails returned 403` | **GitHub App** (client id starts with `Iv…`) lacks the "Email addresses" permission | Login is now **seamless anyway** — IAM falls back to `<id>+<login>@users.noreply.github.com` (see `idp/github.go`). Grant the read-only "Email addresses" account permission on the App only if you want the user's *real* address. |
| `GitHub rejected GET /user (status 403)` | The GitHub App lacks the **user profile** account permission (can't identify the user at all) | Grant the App read-only account permissions for the user profile (App settings → Permissions → Account permissions), then sign in again. This one is fatal — there is no identity to fall back to. |
| `redirect_uri_mismatch` at authorize | The app's registered callback ≠ what IAM sends | Register `https://iam.hanzo.ai/callback` on the provider app (see Verification). |

**GitHub App vs OAuth App.** A GitHub *App* client id starts with `Iv…`; a
classic *OAuth App* is 20 hex chars. OAuth Apps get broad scopes
(`read:user`, `user:email`) automatically, so `/user` and `/user/emails` just
work. GitHub *Apps* expose only the endpoints their granular permissions
allow — so they need the account-level **user profile** (fatal if missing) and
**Email addresses** (now non-fatal, noreply fallback) permissions.

**Direct credential probe** — distinguishes a bad secret from a permission
issue without touching the browser flow:

```bash
# valid creds ⇒ "bad_verification_code" (the dummy code is what's rejected)
# wrong secret ⇒ "incorrect_client_credentials"
curl -s -H 'Accept: application/json' https://github.com/login/oauth/access_token \
  -d client_id=<client-id> -d client_secret=<client-secret> -d code=dummy
```

**Provider secret write path.** `provider-github` / `provider-google` are
admin-org rows; updating them requires a **global-admin** session
(`isGlobalAdmin: true`), not an org-admin. The canonical writer is
`iam init-providers` (run by the `iam-init-brand-apps` Job with the
`iam-kms-auth` admin machine identity). IAM caches provider rows in memory, so
`kubectl rollout restart deploy/iam` after any out-of-band write.
