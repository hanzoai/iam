# Hanzo IAM — SDK Reference

The canonical client library for Hanzo IAM is
[`@hanzo/sdk/iam`](https://github.com/hanzo-js/sdk) — the TypeScript
sub-client inside the unified Hanzo SDK. Every IAM operation supported
by the CLI ([CLI.md](CLI.md)) is also available programmatically here.

## Install

```bash
npm install @hanzo/sdk
```

## Quick start

```ts
import { IAMClient } from '@hanzo/sdk/iam'

const iam = new IAMClient({
  baseUrl: 'https://iam.dev.example.com',
  token: process.env.IAM_SERVICE_TOKEN,
})

// List
const apps = await iam.applications.list({ owner: 'vcc' })

// Add redirect URIs (the most-asked-for op)
await iam.applications.redirectURIs.add('acme-app-client-id', [
  'http://vcc.localhost:3000/auth/callback',
  'http://vcc.localhost:3000/callback',
])

// Upsert any field
await iam.applications.upsert({
  organization: 'vcc',
  name: 'acme-app',
  clientId: 'acme-app-client-id',
  displayName: 'VCC Exchange',
  redirectUris: [
    'https://app.dev.example.com/callback',
    'https://app.dev.example.com/auth/callback',
  ],
})
```

## API surface

| TS surface                                              | REST endpoint                                  | CLI equivalent                              |
|---------------------------------------------------------|------------------------------------------------|---------------------------------------------|
| `iam.applications.list({ owner })`                      | `GET /v1/iam/get-applications`                 | `iam app list --owner=…`                    |
| `iam.applications.fetch({ clientId })`                  | `GET /v1/iam/get-application`                  | `iam app get <client-id>`                   |
| `iam.applications.upsert(app)`                          | `POST /v1/iam/admin/applications/upsert`       | `iam app upsert <file.json>`                |
| `iam.applications.remove({ clientId })`                 | `POST /v1/iam/delete-application`              | (no CLI command yet)                        |
| `iam.applications.redirectURIs.list(clientId)`          | (RMW on `redirectUris`)                        | `iam app redirect list <client-id>`         |
| `iam.applications.redirectURIs.add(clientId, urls)`     | (RMW on `redirectUris`)                        | `iam app redirect add <client-id> <url>…`   |
| `iam.applications.redirectURIs.remove(clientId, url)`   | (RMW on `redirectUris`)                        | `iam app redirect remove <client-id> <url>` |
| `iam.users.list({ owner })`                             | `GET /v1/iam/get-users`                        | `iam user list --owner=…`                   |
| `iam.users.fetch({ owner, name })`                      | `GET /v1/iam/get-user`                         | `iam user get <owner> <name>`               |
| `iam.users.create(user)`                                | `POST /v1/iam/add-user`                        | `iam user create <file.json>`               |
| `iam.organizations.list()`                              | `GET /v1/iam/get-organizations`                | `iam org list`                              |
| `iam.organizations.create(org)`                         | `POST /v1/iam/add-organization`                | `iam org create <file.json>`                |
| `iam.organizations.remove(name)`                        | `POST /v1/iam/delete-organization`             | `iam org delete <name>`                     |

The TS SDK is the recommended path from any Node service, frontend
build pipeline, or back-end automation. The CLI is the right path for
interactive operator work and shell scripts. Both call the same REST
endpoints; the on-the-wire behavior is identical.

## Error handling

Every non-2xx response throws `HanzoAPIError` with `status`, `statusText`,
and the parsed body:

```ts
import { HanzoAPIError } from '@hanzo/sdk'

try {
  await iam.applications.fetch({ clientId: 'does-not-exist' })
} catch (err) {
  if (err instanceof HanzoAPIError && err.status === 404) {
    // expected
  } else {
    throw err
  }
}
```

## See also

- [`CLI.md`](CLI.md) — equivalent `iam` CLI binary
- [`@hanzo/sdk` README](https://github.com/hanzo-js/sdk) — umbrella SDK covering KMS, Commerce, Billing, MPC, PaaS, Team
- Downstream tenant CLIs wrap `iam …` with env-aware resolution
