# Hanzo IAM — Local Dev in 5 lines

```bash
cd ~/work/hanzo/iam
cp .env.example .env
docker compose up -d
open http://localhost:8000
# sign in: admin/root · password: root · OTP if prompted: 999999
```

Done. You have a working IAM at `http://localhost:8000` with `/v1/iam/*` canonical surface.

## What "out of the box" gives you

| Concept           | Value                                | Where it comes from         |
| ----------------- | ------------------------------------ | --------------------------- |
| Admin org         | `admin`                              | `IAM_ADMIN_ORG`             |
| Engine app        | `admin/iam`  (owner/name)            | `IAM_ADMIN_APP`             |
| Bootstrap user    | `admin/root`                         | `IAM_ADMIN_USER`            |
| Bootstrap pass    | `root` (Argon2id-hashed at boot)     | `IAM_ADMIN_PASSWORD`        |
| Sandbox OTP       | `999999` (any phone/email)           | `SANDBOX_GLOBAL_OTP`        |
| Origin            | `http://localhost:8000`              | `ORIGIN`                    |
| Runtime           | dev (relaxes prod panics)            | `ENV`                       |
| Storage           | SQLite at `/data/iam` in container   | `IAM_DATA_DIR`              |

The sandbox-OTP bypass is **only active when ORIGIN is on the sandbox
allowlist** (loopback, `.local`, anything you add via
`SANDBOX_ORIGIN_ALLOWLIST`). Boot panics if `SANDBOX_GLOBAL_OTP` is set on
any other origin — so you can't accidentally ship the dev defaults to prod.

## Registering your app

The convention for consumer-app names is `<consumer-org>-<appname>`. So
when you register, say, a Hanzo Brain login flow:

```bash
# org: hanzo
# app name: hanzo-brain
# redirect URI: http://localhost:5173/auth/callback
curl -X POST http://localhost:8000/v1/iam/applications \
  -H "Authorization: Bearer $JWT" \
  -d '{"owner":"hanzo","name":"hanzo-brain","redirectUris":["http://localhost:5173/auth/callback"], ...}'
```

Then your SPA logs in via:

```ts
import { signIn } from '@hanzo/iam/browser'

await signIn({
  iamUrl: 'http://localhost:8000',
  clientId: 'hanzo-brain',
  redirectUri: 'http://localhost:5173/auth/callback',
})
```

For OTP/MFA testing in your e2e suite, send any code — `999999` accepts.

## Production checklist

Before any deployment reachable from the public net, change in your `.env`
or operator manifest:

- [ ] `IAM_ADMIN_PASSWORD` → strong, KMS-sourced
- [ ] `IAM_KMS_MASTER_KEY` → KMS-sourced (never plaintext in manifests)
- [ ] `SANDBOX_GLOBAL_OTP` → **empty string** (origin guard refuses to boot otherwise)
- [ ] `ENV` → `production` (panics on any unset admin var, locks down OTP)
- [ ] `ORIGIN` → real hostname (`https://iam.your-domain.com`)

## Resetting state

Wipe the SQLite volume and re-bootstrap:

```bash
docker compose down -v && docker compose up -d
```

The admin org/app/user/cert/permission/model/adapter/enforcer rows are
seeded idempotently — re-running the container against an existing DB is
a no-op.

## Troubleshooting

| Symptom                                         | Fix                                                                                            |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Login form returns 401                          | The admin user was seeded with the password from `IAM_ADMIN_PASSWORD` at FIRST boot. If you changed the env after first boot, wipe the volume (`docker compose down -v`) and bring it back up. |
| OTP `999999` rejected                           | Check `SANDBOX_GLOBAL_OTP` is set and `ORIGIN` matches the allowlist. Look for `[sandbox-guard]` line in IAM logs. |
| Boot panics with "SANDBOX_GLOBAL_OTP is set but ORIGIN..." | You set the dev OTP on a non-sandbox origin. Either unset it, or extend `SANDBOX_ORIGIN_ALLOWLIST`. |
| Boot panics with "IAM_ADMIN_* must be set in production" | `ENV=production` (or `prod`/`main`/`mainnet`) but you didn't supply explicit values for `IAM_ADMIN_ORG/APP/USER`. Set them. |
