# Hanzo IAM — ZAP Schema
#
# Server: iam (Go) at iam.hanzo.svc.cluster.local or via the unified
# cloud binary at api.hanzo.ai/v1/iam.
#
# This schema is the minimum ZAP-typed public surface needed for the
# HIP-0106 Mount() contract. The full HTTP surface — ~150 routes
# including OAuth 2.0 / OIDC / SAML / LDAP / SCIM / WebAuthn / MFA —
# is registered in routers/router.go and remains the source of truth
# for /v1/iam/* routes. Wider ZAP-typed handlers (VerifyJWT, GetUser,
# GetOrg, …) will land as separate schema PRs alongside the in-process
# IAMClient interface from cloud/pkg/cloud/deps.go.
#
# Code generation:
#   zapc generate schema/iam.zap --lang go   --out ./gen/zap/
#   zapc generate schema/iam.zap --lang ts   --out ./gen/zap/

# ── Health ────────────────────────────────────────────────────────────────

struct HealthRequest
  # No fields. Probe is a side-effect-free GET.

struct HealthResponse
  status   Text
  service  Text

# ── Service interface ────────────────────────────────────────────────────

interface IAMService
  # Liveness probe. Always answers ok unless the process is unreachable.
  # Mounted at GET /v1/iam/health by Mount(app, deps).
  health (request HealthRequest) -> (response HealthResponse)
