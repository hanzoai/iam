# Brand Audit — hanzoai/iam

Date: 2026-05-28

## Rule

Hanzo brand only. IAM is the canonical Hanzo identity service; downstream
white-label tenants (Zoo, Pars, Lux, AdNex, Bootno) override the brand via
`/etc/brand/brand.json` at deploy time. No tenant brand may appear in this
repo's source by name.

## Files surveyed

Searched `**/*.{json,ts,tsx,js,jsx,go,md,yaml,yml,html}` (excluding
`node_modules/`, `test-results.json`, `playwright-report/`, `swagger.json`,
`pnpm-lock.yaml`) for:
- `Liquid`, `Liquidity`, `liquid-`, `liquidity-`, `liquid_`, `liquidity_`
- `@liquidityio/`
- `Lux Industries`, `Zoo Labs Foundation`, `Pars Network Foundation`
- `@luxfi/brand`, `@zooai/brand`, `@parsai/brand`, `@liquidityio/brand`

## Cross-brand findings + removals

All Liquidity references removed:

| File | Change |
|------|--------|
| `cloudbuild.yaml` | `_IMAGE` default `ghcr.io/luxfi/iam:dev` → `ghcr.io/hanzoai/iam:dev`; comment updated |
| `conf/brand_test.go` | Test fixture name `Liquid`/`liquid.example` → `Acme`/`acme.example` (generic placeholder) |
| `README.md` | Removed "Liquidity's `liquid iam` wrapper" reference; generic tenant CLI mention |
| `cmd/iam/cli/cli.go` | Three doc-comment Liquidity references → generic tenant wording |
| `cmd/iam/cli/httpclient.go` | Removed "In a Liquidity cluster:" example block; kept Hanzo + local-compose blocks |
| `controllers/bootstrap.go` | Body example `liquidity`/`Liquidity KMS` → `hanzo`/`Hanzo KMS`; `liquid-operator` references → generic `deployment operator`; `LiquidIAM tenant seed` → `tenant seed` |
| `controllers/bootstrap_test.go` | Duplicate-key fixture `'liquidity-z'` → `'hanzo-z'` |
| `docs/CONVENTION.md` | `LiquidApp / BaseApp CR` → `HanzoApp / BaseApp CR`; sample env `liquidity-id` → `hanzo-console` |
| `kms/client_test.go` | All `liquidity` org-slug fixtures → `hanzo` |
| `object/application.go` | App-name example `liquidity/liquidity-exchange` → `hanzo/hanzo-console` |
| `object/ormer.go` | `Liquidity operator emits DATA_DIR` → `operators emit DATA_DIR` |
| `object/otp_provider.go` | Default `fromName = "Liquidity"` → `"Hanzo"` |
| `routers/base.go`, `routers/router.go` | `LiquidIAM.spec.users[]` / `liquid-operator` → generic `deployment operator` |

No Lux/Zoo/Pars **branding** removed — those references are federation /
multi-tenant configuration (default superadmin domain whitelist, white-
label test scenarios) and are required for IAM's role as the shared
identity gateway across the Hanzo-managed identity federation.

## Tooling deps (kept)

- `github.com/luxfi/crypto/mldsa` — ML-DSA-65 (FIPS 204) wrapper; PQ JWT signing
- `github.com/luxfi/metric` — Prometheus metric facade
- `github.com/luxfi/compliance` — IDV provider adapter (Alibaba/Stripe/etc.)
- `@codemirror/lang-liquid` (transitive via `@uiw/codemirror-extensions-langs`)
  — Shopify Liquid template-language syntax highlighting; unrelated to brand

## Federation endpoint

Added `web/public/.well-known/iam.json` with the standard Hanzo brand
profile. The Vite dev/prod build copies `web/public/**` to the output
verbatim, so the file is served at `https://iam.hanzo.ai/.well-known/iam.json`.

## Network references retained (intentional)

- White-label tests `tests/iam-login.spec.ts` exercising `id.lux.network`,
  `id.zoo.network`, `id.pars.network` flows — these are integration tests
  for IAM's federation behaviour, not branding crossover.
- `conf/brand.go` `defaultBrand.SuperadminDomains` whitelist of
  `hanzo.ai`, `zoo.ngo`, `lux.network`, `pars.network` — Hanzo's chosen
  default federated-superadmin list, overridable per tenant.
- `object/wellknown_oidc_discovery_test.go` — federation issuer test
  fixtures listing the canonical Hanzo identity providers.
