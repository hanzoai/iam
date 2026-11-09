# EmailVerified backfill (do not run from CI)

Safe, **idempotent** operator script to set `EmailVerified=true` on accounts that
already proved mailbox control. Postiz (and other RPs) read `email_verified` from
userinfo, which mirrors the stored `User.EmailVerified` bit.

## Criteria (mark verified)

Mark an account verified **only** when at least one of the following is true:

1. **OTP / code prove** — audit or signup history shows a successful email code
   challenge for the current primary email (`Action` related to address/code
   prove; see address + code signup paths).
2. **Verified federation link** — the account was linked or provisioned with an
   IdP that asserted a verified email for the **current** primary address
   (federation link write already sets `EmailVerified=true` going forward).
3. **Manual operator attestation** — named admin documents the mailbox owner
   out-of-band (break-glass); record reason in the audit log.

## Do not mark verified when

- The only email source was an **unverified** IdP profile email.
- The primary email has changed since the last proof (re-prove required).
- The account is deleted / hashed / soft-deleted.

## How to run (manual)

```bash
# Dry-run (default): print owner/name counts only — no writes.
go run ./scripts/email_verified_backfill -dry-run

# Apply after reviewing the dry-run list.
go run ./scripts/email_verified_backfill -dry-run=false
```

Requires the same DB DSN env the IAM process uses. The script is idempotent:
rows already `EmailVerified=true` are skipped.

## Ordering with Postiz

1. Deploy this IAM change (refuse unverified federated **provision**).
2. Run the backfill for proven team accounts.
3. Confirm userinfo returns `email_verified: true` for admins who need Postiz
   email-link after `sub` drift.
4. Then merge/deploy Postiz “require email_verified for email-link”.
