# Multi-chain wallet-login e2e

Drives the **real** Hanzo IAM wallet-login UI (`web/src/auth/WalletConnect.tsx`)
in a real browser against the **real** IAM server `/v1/iam/web3/{nonce,verify}`,
with a **mock wallet signer** that produces **genuine** secp256k1 / ed25519
signatures. The only thing mocked is the wallet — the server's
`walletconnect.VerifyProof` cryptographically verifies the real signature and
provisions/resolves a real user. (HIP-0111.)

```
login page (real getWalletChains picker)
   └─ click chain → authViaWallet()  ── REAL WalletConnect.tsx ──┐
        connector.connect()        ← mock window.ethereum/solana │
        GET  /v1/iam/web3/nonce    ← REAL IAM server             │
        connector.signLogin()      ← mock signs (real crypto)    │
        POST /v1/iam/web3/verify   → REAL VerifyProof → user ────┘
```

## Files

| file | role |
|------|------|
| `mock-wallet.ts` | injects `window.ethereum` (EIP-6963 + EIP-1193, viem secp256k1) and `window.solana` (ed25519 via `@noble/curves`). Real signatures, fixed throwaway test keys. |
| `harness.tsx` | renders the **real** `getWalletChains()` (all 7 chains) and runs the **real** `authViaWallet()`; transparently records nonce/verify calls. |
| `setting-shim.ts` | 2-symbol stand-in for `../Setting` (only `goToLink`/`showMessage`), aliased in via Vite so the whole admin app isn't bundled. WalletConnect.tsx itself is untouched. |
| `vite.e2e.config.ts` | serves the harness, proxies `/v1/iam` → backend, applies the Setting alias. |
| `wallet-login.spec.ts` | Playwright: picker renders (7 chains) → EVM + Solana each connect→sign→verify→logged-in. |
| `playwright.config.ts` | boots the Vite harness as its `webServer`. |
| `run.sh` | one-shot: build+boot the IAM backend (seeds `app-hanzo`, `enableSignUp`), then run Playwright. |

## Run

```bash
web/e2e/run.sh                 # boots backend + frontend, runs the spec
IAM_BACKEND=http://host web/e2e/run.sh   # against an existing IAM
```

Screenshots land in `e2e/screenshots/` (git-ignored).

## Notes

- **Backend build**: `GOWORK=off` (the shared `~/work/hanzo/go.work` carries a
  stale `luxfi/threshold` checksum) and `CGO_ENABLED=0` (pure-Go modernc sqlite,
  no SQLCipher headers). Config is passed via **env**, not `-config`: Go's `flag`
  package stops at the `serve` positional, so `-config` after it is never parsed;
  `conf.GetConfigString` checks env before the file.
- **Post-login reload**: production `authViaWallet` calls `window.location.reload()`
  on a successful non-redirect login. `location.reload` is non-configurable in
  Chromium, so the harness doesn't fight it: the wrapped `fetch` persists the
  verify outcome to `sessionStorage` synchronously the instant it returns, and
  the harness restores that state on (re)mount — the "logged in" screenshot is
  clean either way, and the reload is the genuine production logged-in signal.
- The Go server verify path itself is unit-tested in
  `object/web3_auth_test.go` (EVM + Solana through `VerifyWalletLogin`); this
  harness is the browser/UI half end-to-end.
