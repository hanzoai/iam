# Hanzo IAM — CLI Reference

The `iam` binary is the canonical administrative CLI for Hanzo IAM. One
source of truth: every operator tooling layer (the Hanzo umbrella `hanzo`
CLI, downstream wrapper CLIs, etc.) is a thin proxy that adds env-aware
base-URL resolution and delegates to the same underlying REST surface
that this CLI calls.

Wherever you see `iam <command>` here, downstream tooling typically wraps
it with `<wrapper> iam <command>` and an env flag that resolves the
appropriate `iam.<env>.<your-domain>` and fetches the service token from
the cluster.

## Install

```bash
# From source (Go 1.26+)
git clone https://github.com/hanzoai/iam ~/work/hanzo/iam
cd ~/work/hanzo/iam
go install ./cmd/iam
```

The binary lands at `$(go env GOPATH)/bin/iam`. Container builds use
`Dockerfile` at the repo root and ship under `ghcr.io/hanzoai/iam`.

## Authentication

Every command requires a service-bound bearer token. Discover the token
once and export it for the session:

```bash
# In a Hanzo cluster (e.g. running against id.hanzo.ai)
export IAM_ADDR=https://id.hanzo.ai
export IAM_TOKEN=<bearer from any iam pod env>

# In a downstream tenant's dev env (replace context/ns with your tenant's values)
export IAM_ADDR=https://iam.dev.<your-domain>
export IAM_TOKEN=$(kubectl --context=<your-cluster> \
                   -n <your-ns> exec deploy/iam -- printenv IAM_SERVICE_TOKEN)
```

## Commands

### `iam status`

Check IAM server health.

```bash
$ iam status
status: 200
{"status":"ok","version":"v1.14.29","uptime":"3d12h"}
```

### `iam app list [--owner=<slug>]`

List every application (OIDC client). Filter by owner (organization slug).

```bash
$ iam app list --owner=exampleorg
exampleorg-app1         exampleorg-app1-client-id           admin
exampleorg-app2         exampleorg-app2                     admin
exampleorg-app3         exampleorg-app3                     admin
acme-app            acme-app-client-id              admin
acme-portal            acme-portal-client-id              admin
```

### `iam app get <client-id>`

Fetch one application by client ID.

```bash
$ iam app get acme-app-client-id
{
  "organization": "vcc",
  "name": "acme-app",
  "clientId": "acme-app-client-id",
  "redirectUris": [
    "https://app.dev.example.com/callback",
    "https://app.dev.example.com/auth/callback"
  ],
  ...
}
```

### `iam app upsert <file.json>`

Idempotent upsert from a JSON file. Server merges with existing row;
fields omitted from the JSON are not cleared. For destructive
overwrites, fetch the current state, modify, then upsert.

```bash
$ cat > /tmp/app.json << 'EOF'
{
  "organization": "vcc",
  "name": "acme-app",
  "clientId": "acme-app-client-id",
  "redirectUris": [
    "https://app.dev.example.com/callback",
    "https://app.dev.example.com/auth/callback",
    "http://vcc.localhost:3000/callback",
    "http://vcc.localhost:3000/auth/callback"
  ]
}
EOF
$ iam app upsert /tmp/app.json
ok
```

### `iam app redirect add <client-id> <url> [<url> ...]`

Most-asked-for operation: add one or more redirect URIs to an OIDC
client's allow-list. Idempotent — re-adding the same URI is a no-op.

```bash
$ iam app redirect add acme-app-client-id \
    http://vcc.localhost:3000/auth/callback \
    http://vcc.localhost:3000/callback
added 2 redirect URI(s) to acme-app-client-id:
  + http://vcc.localhost:3000/auth/callback
  + http://vcc.localhost:3000/callback
```

### `iam app redirect list <client-id>`

Print the current redirect-URI allow-list.

```bash
$ iam app redirect list acme-app-client-id
https://app.dev.example.com/callback
https://app.dev.example.com/auth/callback
http://vcc.localhost:3000/callback
http://vcc.localhost:3000/auth/callback
```

### `iam app redirect remove <client-id> <url>`

Remove a single redirect URI. No-op if not present.

```bash
$ iam app redirect remove acme-app-client-id http://vcc.localhost:3000/callback
removed redirect URI from acme-app-client-id:
  - http://vcc.localhost:3000/callback
```

### `iam user list [--owner=<slug>]`

List users. Filter by owner organization.

### `iam user get <owner> <name>`

Fetch one user.

### `iam user create <file.json>`

Create a user from a JSON file.

### `iam org list / create / delete`

Organization management.

### `iam token mint --owner=<slug> --user=<name>`

Mint a JWT for a user.

### `iam token verify <jwt>`

Validate a JWT signature against the IAM JWKS.

### `iam version`

Print the binary version and exit.

## Environment variables

| Variable     | Default                  | Purpose                                    |
|--------------|--------------------------|--------------------------------------------|
| `IAM_ADDR`   | `http://localhost:8000`  | IAM server URL                             |
| `IAM_TOKEN`  | (none)                   | Bearer used on every authenticated request |

CLI flags `--addr` and `--token` override the environment.

## Related

- **REST surface**: [`routers/router.go`](../routers/router.go) — every endpoint the CLI calls is mapped there.
- **TypeScript SDK**: [`@hanzo/sdk/iam`](https://github.com/hanzo-js/sdk/tree/main/src/iam) — identical operations, programmatic. `IAMClient.applications.redirectURIs.add()` is the API equivalent of `iam app redirect add`.
- **Downstream tenant CLI**: Tenants typically ship a wrapper (e.g., `tenantctl iam redirect add ...`) that resolves `--env=dev|test|main` against their domain.
- **Server docs**: [`LOCAL_DEV.md`](LOCAL_DEV.md), [`CONVENTION.md`](CONVENTION.md), [`sdk/`](sdk/) — running IAM locally + on-the-wire conventions.

## Forbidden patterns

- ❌ `UPDATE application SET redirect_uris = json_insert(...)` straight against the SQLite DB. Bypasses validation + audit; do not do this. Use `iam app upsert` or `iam app redirect add`.
- ❌ Curl-and-pray against `/v1/iam/admin/applications/upsert` with hand-written JSON. The CLI does the read-modify-write atomically; raw curl will clobber unrelated fields.
- ❌ Hand-rolled secret tokens. The bearer always comes from a deployed `iam` pod or the IAM admin login. Don't paste tokens into chat.
