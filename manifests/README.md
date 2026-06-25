# IAM provisioning manifests

One-shot Kubernetes Jobs + KMS syncs that reconcile IAM's admin-org provider
configuration. They run the `iam` CLI (shipped in `ghcr.io/hanzoai/iam`) and
read every credential from k8s Secrets / KMS at runtime — **zero hardcoded
credentials**.

These are the IAM-repo canonical source for the provider live-fix. The
universe deploy can vendor/reference them; nothing here is applied by CI.

## Files

| File | What it is |
|------|------------|
| `iam-provision-providers-job.yaml` | Job: `iam init-providers && iam wire-providers`. Upserts the five admin-org providers (GitHub, Google, SMS, Email, Web3) and attaches them to every real-org app. |
| `iam-twilio-smtp-kms-secrets.yaml` | KMSSecret CRs syncing the Twilio + SMTP credentials from KMS into the `iam-twilio` / `iam-smtp` Secrets the Job consumes. |

## Apply order (operator, after review)

```sh
# 1. Sync the SMS/email creds from KMS (if not already present).
kubectl apply -f manifests/iam-twilio-smtp-kms-secrets.yaml
kubectl -n hanzo get secret iam-twilio iam-smtp   # confirm they materialized

# 2. Run the provisioning Job.
kubectl apply -f manifests/iam-provision-providers-job.yaml
kubectl -n hanzo wait --for=condition=complete --timeout=5m job/iam-provision-providers
kubectl -n hanzo logs job/iam-provision-providers
```

GitHub login (the immediate prod fix) does NOT depend on step 1 — the Job reads
`github-oauth` (already KMS-synced) and is bootstrap-tolerant for the rest, so
it converges GitHub immediately and picks up SMS/email/Google once those
Secrets exist.

## Secret dependencies (verify they exist in ns `hanzo` first)

| Secret / ConfigMap | Key(s) | Source |
|--------------------|--------|--------|
| `social` (ConfigMap) | `IAM_CLIENT_ID` (=`hanzo-social`) | `infra/k8s/social/configmap.yaml` |
| `social-secrets` (Secret) | `IAM_CLIENT_SECRET` | KMSSecret `social-kms-sync` |
| `github-oauth` (Secret) | `CLIENT_ID`, `CLIENT_SECRET` | KMSSecret `github-oauth-kms-sync` |
| `google-oauth` (Secret) | `CLIENT_ID`, `CLIENT_SECRET` | optional — Job skips Google if absent |
| `iam-twilio` (Secret) | `ACCOUNT_SID`, `AUTH_TOKEN`, `SENDER` | KMSSecret `iam-twilio-kms-sync` |
| `iam-smtp` (Secret) | `HOST`, `PORT`, `USER`, `PASS`, `FROM` | KMSSecret `iam-smtp-kms-sync` |

The admin-app credential pair (`hanzo-social` clientId + secret) authenticates
the Job as a global-admin `app/` principal — that is the only privilege the
provider/app writes require.
