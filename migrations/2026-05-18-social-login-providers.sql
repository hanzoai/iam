-- 2026-05-18-social-login-providers.sql
--
-- Phase 3 of the social-login rollout. Upserts the admin-org provider
-- rows — GitHub, Google, SMS (Twilio), Email (SMTP) and Web3 (SIWx) —
-- with KMS-sourced credentials. These are the ONE shared default set
-- every brand app inherits.
--
-- THIS FILE IS AN AUDIT ARTIFACT. The actual upsert at runtime is done
-- by `iam init-providers` (see cmd/iam/cli/init_providers.go) against
-- the canonical /v1/iam/{get,add,update}-provider HTTP API. We do NOT
-- run raw SQL against the IAM SQLite file in production because:
--
--   1. IAM uses Base/SQLite (per CLAUDE.md: "no PostgreSQL anywhere").
--      The schema is owned by IAM's xorm migrations.
--   2. Raw SQL bypasses the cache-invalidation hooks the API does.
--   3. The API enforces validation (e.g. category must be one of
--      OAuth/SAML/SMS/Email/Web3/...; type must match a known IdP).
--
-- This file is kept under migrations/ so a security reviewer can see
-- the EXACT shape of what iam writes. The literal SQL is a faithful
-- transcription of what init-providers' upsertProvider() does, modulo
-- the masked-secret round-trip behavior.
--
-- PLACEHOLDERS — do not commit real client_ids or secrets here. They
-- are sourced at runtime from KMS. Social OAuth from project
-- `hanzo-iam` (GITHUB_*/GOOGLE_*); Twilio + SMTP from `brand/hanzo/
-- twilio/*` (account-sid, auth-token, from-phone) and the SMTP_* set:
--
--   GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
--   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
--   TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_SENDER
--   SMTP_USER / SMTP_PASS / SMTP_HOST / SMTP_PORT / SMTP_FROM
--
-- Web3 is keyless (no client_id/secret) — the SIWx challenge/verify
-- flow needs no provider credential.

-- Equivalent xorm/Casdoor-flavored SQL. Wrapped in a transaction; the
-- INSERT … ON CONFLICT clauses are idempotent.
BEGIN TRANSACTION;

-- GitHub. category=OAuth, type=GitHub.
-- NOTE: client_secret is set unconditionally — it is masked in API
-- reads so we cannot reliably skip the write.
INSERT INTO provider (
    owner, name, created_time,
    display_name, category, type,
    client_id, client_secret, scopes
) VALUES (
    'admin', 'provider-github', CURRENT_TIMESTAMP,
    'GitHub', 'OAuth', 'GitHub',
    :github_client_id, :github_client_secret, 'read:user'
)
ON CONFLICT (owner, name) DO UPDATE SET
    display_name  = excluded.display_name,
    category      = excluded.category,
    type          = excluded.type,
    client_id     = excluded.client_id,
    client_secret = excluded.client_secret,
    scopes        = excluded.scopes;

-- Google. category=OAuth, type=Google.
INSERT INTO provider (
    owner, name, created_time,
    display_name, category, type,
    client_id, client_secret, scopes
) VALUES (
    'admin', 'provider-google', CURRENT_TIMESTAMP,
    'Google', 'OAuth', 'Google',
    :google_client_id, :google_client_secret, 'profile email'
)
ON CONFLICT (owner, name) DO UPDATE SET
    display_name  = excluded.display_name,
    category      = excluded.category,
    type          = excluded.type,
    client_id     = excluded.client_id,
    client_secret = excluded.client_secret,
    scopes        = excluded.scopes;

-- SMS. category=SMS, type=Twilio SMS.
-- client_id=Account SID, client_secret=Auth Token, app_id=sender number.
-- Twilio SMS skips sign_name; the verification send itself is opaque to
-- IAM (notify owns it) — this row backs the login UI + brand inheritance.
INSERT INTO provider (
    owner, name, created_time,
    display_name, category, type,
    client_id, client_secret, app_id
) VALUES (
    'admin', 'provider-sms', CURRENT_TIMESTAMP,
    'SMS', 'SMS', 'Twilio SMS',
    :twilio_account_sid, :twilio_auth_token, :twilio_sender
)
ON CONFLICT (owner, name) DO UPDATE SET
    display_name  = excluded.display_name,
    category      = excluded.category,
    type          = excluded.type,
    client_id     = excluded.client_id,
    client_secret = excluded.client_secret,
    app_id        = excluded.app_id;

-- Email. category=Email, type=Default (SMTP).
-- client_id=SMTP user, client_secret=SMTP pass, host/port the server,
-- receiver the envelope-from.
INSERT INTO provider (
    owner, name, created_time,
    display_name, category, type,
    client_id, client_secret, host, port, receiver
) VALUES (
    'admin', 'provider-email', CURRENT_TIMESTAMP,
    'Email', 'Email', 'Default',
    :smtp_user, :smtp_pass, :smtp_host, :smtp_port, :smtp_from
)
ON CONFLICT (owner, name) DO UPDATE SET
    display_name  = excluded.display_name,
    category      = excluded.category,
    type          = excluded.type,
    client_id     = excluded.client_id,
    client_secret = excluded.client_secret,
    host          = excluded.host,
    port          = excluded.port,
    receiver      = excluded.receiver;

-- Web3. category=Web3, type=MetaMask. Keyless — the SIWx flow needs no
-- credential; this row is what makes the wallet login button render.
INSERT INTO provider (
    owner, name, created_time,
    display_name, category, type
) VALUES (
    'admin', 'provider-web3', CURRENT_TIMESTAMP,
    'Web3', 'Web3', 'MetaMask'
)
ON CONFLICT (owner, name) DO UPDATE SET
    display_name  = excluded.display_name,
    category      = excluded.category,
    type          = excluded.type;

COMMIT;
