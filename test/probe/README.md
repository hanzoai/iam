# In-cluster authz probes

**Required gate for any authz change touching the app principal.** A green test
suite is not sufficient evidence and has now failed to be, four times in one day:

| shipped | passed tests | production |
|---|---|---|
| v1.33.17 | yes | 403 — grant matched `applications`; the caller sends `get-application` |
| v1.33.18 | yes | 200 with `"the entity does not exist"` — `Scope` rewrote the owner |
| v1.33.20 | yes | cert 403 — verified the bare id; the binary sends `<org>/<name>` |

Every one exercised a contract no real client uses. `app-selfread.yaml` issues the
requests the real caller issues, as the real principal, with the real secret —
read from the `hanzo-cloud-iam-creds` Secret inside the cluster, so it is never
handled outside it.

    kubectl -n hanzo apply -f test/probe/app-selfread.yaml
    kubectl -n hanzo logs iam-selfread-probe
    kubectl -n hanzo delete pod iam-selfread-probe

## Deriving the id a test should use

Read the CLIENT and copy the string it builds. Do not write the spelling that
reads naturally:

- `ai/internal/iam/cert.go:35` → `fmt.Sprintf("%s/%s", c.OrganizationName, name)` → `hanzo/cert-hanzo`
- `GetApplication` hardcodes the `admin/` owner half → `admin/hanzo-cloud`

The two differ, and the difference is exactly what the last three fixes missed.
