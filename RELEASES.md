# Hanzo IAM — Release Notes

## 2026-06-03 — Notify-only delivery + profile/avatar endpoints

**PR #40: Notify is the only send path — rip direct Plivo/Twilio/SES** (b75099ae)

All outbound user messaging (OTP, password resets, account alerts) now goes through Hanzo Notify exclusively. Direct Plivo, Twilio, and SES SMTP clients are deleted along with their config plumbing; `go.mod` drops roughly ten transitive dependencies as a result. IAM keeps a single thin HTTP client to Notify and inherits the multi-provider retry chain (PR #6 in notify) for free. Operators rotating sender credentials now only touch Notify's KMS-resident secrets.

**PR #41: /v1/iam/me/profile + /v1/iam/me/avatar endpoints** (5dfeeeea)

Exposes two self-service endpoints under the existing `/v1/iam/me/*` namespace. `PATCH /me/profile` accepts the editable subset of user fields (display name, locale, timezone, marketing-consent flags) and persists through the canonical user-update path; `PUT /me/avatar` accepts multipart upload and stores the image via the configured object store (Hanzos3 in production). Both endpoints respect the JWT-derived `sub` claim — there is no admin override. Consumed by the Liquidity Exchange profile page (/exchange PR #153).

**PR #42: Fix build.yml duplicate continue-on-error YAML key** (ee8284e0)

Removes a duplicate `continue-on-error` key in the CI build workflow that was silently ignored by some YAML parsers and made future linting strict-mode fail. No behavior change in CI; a future-proofing fix only.
