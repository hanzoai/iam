# ZAP Capability Auth — Migration Plan

Status: ZAP cap path live as a peer to JWT bearer on `POST /v1/iam/whoami`
(and `/v1/iam/whoami/zap` for clean A/B). This document covers the rest of
the migration — what to do now, how to keep both paths green during the
window, and when JWT goes dark.

## What changed

- New package `github.com/hanzoai/iam/capauth` — pure-Go middleware that
  parses `Authorization: ZAP <base64>`, calls `cap.Wrap` + `Verifier.Verify`
  from `github.com/zap-proto/go/cap`, stashes the verified holder on the
  Beego context.
- New controller methods `Whoami` and `WhoamiZAP` in
  `controllers/whoami.go`. `Whoami` dispatches on Authorization scheme;
  `WhoamiZAP` accepts ZAP only.
- New routes `/v1/iam/whoami` and `/v1/iam/whoami/zap` in
  `routers/router.go`.
- New module dep `github.com/zap-proto/go` in `go.mod` (local `replace`
  to `../../zap-proto/go` while the runtime stabilizes — flip to a tag
  once `v0.1.0` is cut).

## How to issue a ZAP cap in place of a JWT

Today, `/v1/iam/login` returns a JWT to be sent back as
`Authorization: Bearer <jwt>`. The migration plan replaces that with a
signed `cap.Capability` to be sent back as
`Authorization: ZAP <base64-of-cap-bytes>`.

```go
import (
    "encoding/base64"
    "time"

    "github.com/zap-proto/go/cap"
)

// signer is the IAM service's per-org signing key (BLS or Ed25519 today,
// ML-DSA-65 once the cap package's Signer is swapped to PQ).
sess, err := cap.Issue(cap.Issuance{
    Kind:        uint32(cap.KindIAMSession),
    Target:      iamServiceIdentity, // 32B hash of IAM's service identity
    Holder:      userPubkeyHash,     // 32B hash of the user's verification key
    Permissions: 0,                  // see capabilities_kinds.md for bit assignments
    IssuedAt:    time.Now().Unix(),
    ExpiresAt:   time.Now().Add(8 * time.Hour).Unix(),
}, signer)
if err != nil {
    return err
}
authHeader := "ZAP " + base64.StdEncoding.EncodeToString(sess.Bytes())
```

## How to attenuate a cap for service-to-service calls

The single biggest reason for ZAP caps over JWTs is downstream attenuation
without re-contacting IAM. When the platform calls KMS on behalf of a user,
the platform's service holder can attenuate the user's IAM session cap to a
narrower one:

```go
attenuated, err := cap.Attenuate(
    userSessionCap,        // parent
    kmsServiceHolder,      // who can use the child
    cap.PermKMSDecrypt,    // bit-mask narrower than parent
    []cap.Caveat{{
        Kind:  cap.CaveatExpiresAt,
        Value: timestampBytes(time.Now().Add(60 * time.Second).Unix()),
    }},
    time.Now().Add(60 * time.Second).Unix(), // override expiry
    platformSigner,        // platform's own holder key
)
```

The child cap can be sent in `Authorization: ZAP <b64>` on the KMS request;
KMS verifies the chain back to IAM's issuer key without IAM being online.

## How to revoke

Two layers:

1. **In-memory (prototype, today).** Tests and dev environments call
   `capauth.Revoke(capID)` to add to the local revocation set. The verifier
   consults this map per request — O(1) lookup.
2. **IAM cap-store table (production).** Replace `capauth.isRevoked` with a
   call into the IAM DB. The shape is the same: `func([32]byte) bool`. A
   revocation row carries the cap ID, revoker signature, and timestamp; the
   PubSub gossip channel `iam.cap.revocations.v1` fans the row out to every
   IAM replica in under 100ms.

To revoke, the holder of the cap's issuer key signs a `cap.Revocation`
record (`cap.Revoke(c, now, issuerSigner)`) and posts it to
`POST /v1/iam/caps/revocations`. The endpoint validates the revoker
signature against the cap's recorded Issuer pubkey, persists, gossips.

## Timeline

The migration is gated on three signals: cap-issuance live, downstream
service support, observed traffic share.

| Phase | Calendar window | What lands | Done-when |
|-------|-----------------|------------|-----------|
| 1. ZAP cap path live as a peer | now → 2026-07 | `/v1/iam/whoami`, `/v1/iam/whoami/zap` accept ZAP. JWT still works. | This commit. |
| 2. `/v1/iam/login` mints both | 2026-07 → 2026-08 | Login returns `{access_token, zap_cap}`. Clients opt into ZAP via `Accept-Auth: zap`. | All 3 envs return both shapes. |
| 3. Downstream services accept ZAP | 2026-08 → 2026-10 | KMS, BD, ATS, TA wire the same `capauth` package. | All 6 backend services have a ZAP path with >=10% of traffic. |
| 4. ZAP becomes default | 2026-10 → 2026-12 | New SDKs emit ZAP by default. Bearer path returns `Sunset: …` header. | Bearer traffic share <1% across all envs. |
| 5. Bearer JWT removed | 2027-Q1 | Bearer path returns 410 Gone with a one-liner pointing at this doc. JWT issuance disabled. | All clients on `>=zap` SDK; no Bearer traffic for 30 days. |

The phase boundaries are signals, not dates — we don't move forward until
the previous phase has held green for at least two weeks across dev, test,
and main.

## Non-negotiables during the migration window

- Bearer JWT must continue to work for any client that doesn't opt into
  ZAP. No silent breakage.
- The cap verifier must never share state with the JWT verifier — they
  are peer paths, not branches of one path. A failure on one path must not
  fall through to the other and silently authenticate.
- Every cap kind must be enumerated in `capabilities_kinds.md` BEFORE any
  endpoint accepts it. No `0xCAFEBABE` magic constants in service code.
- Revocation must be eventually-consistent globally; never per-replica. Any
  revoke that doesn't propagate within 5 seconds is a P0.

## References

- Spec: `~/work/zap-proto/zap-spec/capabilities.zap`
- Go runtime: `~/work/zap-proto/go/cap/`
- This endpoint: `controllers/whoami.go`, `capauth/cap_auth.go`, `routers/router.go`
- Tests: `capauth/cap_auth_test.go` — twelve cases covering valid, revoked,
  expired, wrong-kind, no-header, bearer-header, bad-base64,
  unknown-issuer, tampered-sig, HasHeader, raw-base64 fallback, and the
  full valid path with context handoff to the controller.
