-- 2026-05-18-social-login-providers.sql
--
-- Phase 3 of the social-login rollout. Upserts the GitHub and Google
-- provider rows in the admin org with KMS-sourced client_id and
-- client_secret values.
--
-- THIS FILE IS AN AUDIT ARTIFACT. The actual upsert at runtime is done
-- by `iamctl init-providers` (see cmd/iamctl/init_providers.go) against
-- the canonical /v1/iam/{get,add,update}-provider HTTP API. We do NOT
-- run raw SQL against the IAM SQLite file in production because:
--
--   1. IAM uses Base/SQLite (per CLAUDE.md: "no PostgreSQL anywhere").
--      The schema is owned by IAM's xorm migrations.
--   2. Raw SQL bypasses the cache-invalidation hooks the API does.
--   3. The API enforces validation (e.g. category must be one of
--      OAuth/SAML/...; type must match a known IdP).
--
-- This file is kept under migrations/ so a security reviewer can see
-- the EXACT shape of what iamctl writes. The literal SQL is a faithful
-- transcription of what iamctl's upsertProvider() does, modulo the
-- masked-secret round-trip behavior.
--
-- PLACEHOLDERS — do not commit real client_ids or secrets here. They
-- are sourced at runtime from KMS workspace `credentials` paths:
--
--   /iam/social/<env>/GITHUB_CLIENT_ID
--   /iam/social/<env>/GITHUB_CLIENT_SECRET
--   /iam/social/<env>/GOOGLE_CLIENT_ID
--   /iam/social/<env>/GOOGLE_CLIENT_SECRET
--
-- where <env> is one of: mainnet | testnet | devnet.

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

COMMIT;
