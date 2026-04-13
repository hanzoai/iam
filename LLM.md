# Hanzo IAM - LLM Context Document

## Overview

Hanzo IAM (fork of Casdoor, Apache 2.0) provides OAuth2.0/OIDC/SAML/CAS identity and access management for the Hanzo ecosystem. Serves as the unified authentication provider at **hanzo.id**.

## Rename Status (2026-04-13)

- JS globals: `window.IAMAuthCallback`, `window.IAMProviderHintRedirect` (was `Casdoor*`)
- Session keys: `__iam_callback_react`, `iam_callback_react_fallback` (was `casdoor_*`)
- Go import paths: `github.com/casbin/casbin/v2`, `github.com/casdoor/*` -- unchanged (upstream deps)
- Casbin fork: NOT started. Requires forking `github.com/casbin/casbin` to `github.com/hanzoai/authz`.
- K8s: `CASDOOR_ORIGIN` renamed to `originFrontend` in all manifests.
- Replication: sidecar removed (Beego has no plugin hook). Pending Base migration.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Hanzo IAM (hanzo.id)                   │
├─────────────────────────────────────────────────────────────┤
│  Go Backend (Beego)  │  React Frontend  │  OAuth2/OIDC     │
├─────────────────────────────────────────────────────────────┤
│  PostgreSQL/MySQL    │  Redis           │  User Balances   │
└─────────────────────────────────────────────────────────────┘
            ↑                    ↑                    ↑
    ┌───────┴───────┐    ┌───────┴───────┐    ┌──────┴──────┐
    │   hanzo.app   │    │ cloud.hanzo.ai │    │  commerce   │
    │  (hanzo.ai)   │    │  (AI/MCP)      │    │  (billing)  │
    └───────────────┘    └───────────────┘    └─────────────┘
```

## Environments

| Environment | URL | Compose File | Config |
|-------------|-----|--------------|--------|
| **Local (MySQL)** | http://localhost:8000 | `compose.mysql.yml` | `conf/app.mysql.conf` |
| **Local (PostgreSQL)** | http://localhost:8000 | `compose.dev.yml` | `conf/app.dev.conf` |
| **Staging** | https://stg.hanzo.id | `compose.staging.yml` | `conf/app.staging.conf` |
| **Production** | https://hanzo.id | K8s on hanzo-k8s (`24.199.76.156`) | `IAM_DATABASE_URL` secret |

## Quick Start

### Local Development (MySQL - Recommended)

```bash
# Start MySQL + Redis
docker compose -f compose.mysql.yml up -d

# Build Go binary
go build -o server_darwin_arm64 .

# Run server
cp conf/app.mysql.conf conf/app.conf
./server_darwin_arm64
```

### Docker Development

```bash
# Build and run everything
make dev

# Or step by step
docker compose -f compose.dev.yml build
docker compose -f compose.dev.yml up
```

### Staging/Production

```bash
# Build staging image
make build-staging

# Deploy staging
make staging

# Build production image
make build-prod

# Deploy production
make prod
```

## Configuration Notes

### MySQL Connection Format
For MySQL, the `dataSourceName` should NOT include the database name (it's appended from `dbName`):
```
dataSourceName = user:password@tcp(host:3306)/
dbName = hanzo_iam
```

### PostgreSQL Connection Format
```
dataSourceName = user=hanzo password=xxx host=postgres port=5432 sslmode=disable dbname=hanzo_iam
```

## Init Data

The `init_data.json` file configures:

### Organization
- **Name**: hanzo
- **Theme**: Dark mode, primary color #fd4444

### Applications
| App | Client ID | Redirect URIs |
|-----|-----------|---------------|
| app-hanzo | hanzo-app-client-id | hanzo.ai, hanzo.app, localhost |
| app-cloud | hanzo-cloud-client-id | cloud.hanzo.ai |
| app-commerce | hanzo-commerce-client-id | commerce.hanzo.ai |

### Default Admin
- **Email**: admin@hanzo.ai
- **Password**: admin (change in production!)
- **Balance**: 10000 USD credits

## Integration with Hanzo Ecosystem

### Authentication Flow
1. User visits hanzo.app or cloud.hanzo.ai
2. Redirected to hanzo.id for OAuth login
3. After auth, redirected back with token
4. Service validates token with IAM

### Billing Integration
IAM tracks user credit balances. The flow is:
1. **Commerce** processes payments → adds credits to IAM balance
2. **Cloud** uses AI tokens → creates transactions in IAM (debits balance)
3. **IAM** maintains the source of truth for user credits

### SDK Integration
```go
// Go - using iam-go-sdk
import "github.com/iam/iam-go-sdk/iamsdk"

iamsdk.InitConfig(
    "https://hanzo.id",
    "hanzo-app-client-id",
    "hanzo-app-client-secret",
    "cert-hanzo",
    "hanzo",
    "app-hanzo",
)
```

```javascript
// JavaScript
import { SDK } from 'iam-js-sdk'

const sdk = new SDK({
  serverUrl: 'https://hanzo.id',
  clientId: 'hanzo-app-client-id',
  appName: 'app-hanzo',
  organizationName: 'hanzo',
})
```

## Branding

### Colors
- **Primary**: #fd4444
- **Secondary**: #ff6b6b
- **Hover**: #e03e3e

### Assets
- Logo: `https://cdn.hanzo.ai/img/logo-white.svg`
- Favicon: `/img/hanzo-favicon.png` (local) or `https://cdn.hanzo.ai/img/favicon.png`
- Auth Background: `https://cdn.hanzo.ai/img/auth-bg.jpg`

## CI/CD

### Build Workflow (`.github/workflows/build.yml`)
1. **Tests**: Go tests with PostgreSQL
2. **Frontend**: Yarn build
3. **Backend**: Go build with race detection
4. **Linter**: gofumpt
5. **E2E**: Cypress tests with Chrome
6. **Release**: Semantic versioning → GitHub Release → Docker push to ghcr.io/hanzoai/iam

### Deploy Workflow (`.github/workflows/docker-deploy.yml`)
Automated deployment to Hanzo Cloud:
- **Trigger**: Push to main/master
- **Build**: Multi-arch Docker image (amd64/arm64)
- **Deploy**: SSH to production server, Docker Compose update
- **Health Check**: Waits for IAM to be healthy before completion

### Required GitHub Secrets
| Secret | Description |
|--------|-------------|
| `DEPLOY_HOST` | Production server IP (143.198.188.26) |
| `DEPLOY_USER` | SSH username (root) |
| `DEPLOY_SSH_KEY` | SSH private key for deployment |
| `DEPLOY_PORT` | SSH port (default: 22) |
| `SLACK_WEBHOOK` | Optional Slack notification webhook |

## Production Deployment

### Current Status (as of 2026-01-30)
- **URL**: https://hanzo.id
- **Server**: 143.198.188.26 (hanzo-gateway)
- **Container**: hanzo-iam
- **Network**: hanzo-network
- **Reverse Proxy**: Traefik with automatic HTTPS

### Services Deployed
| Service | URL | Status |
|---------|-----|--------|
| IAM | https://hanzo.id | ✓ Running |
| Console | https://console.hanzo.ai | ✓ Running |
| Platform | https://platform.hanzo.ai | ✓ Running |

### OAuth Applications (Production)
| App | Client ID | Redirect URIs |
|-----|-----------|---------------|
| app-hanzo | hanzo-app-client-id | hanzo.ai, hanzo.app |
| app-console | hanzo-console-client-id | console.hanzo.ai |
| app-platform | hanzo-platform-client-id | platform.hanzo.ai |

## Key Directories

```
iam/
├── conf/                    # Configuration files
│   ├── app.conf            # Active config (gitignored)
│   ├── app.dev.conf        # Docker dev (PostgreSQL)
│   ├── app.mysql.conf      # Local dev (MySQL)
│   ├── app.staging.conf    # Staging (stg.hanzo.id)
│   └── app.prod.conf       # Production (hanzo.id)
├── object/                  # Core business logic
│   ├── adapter.go          # Database adapter
│   ├── ormer.go            # ORM setup
│   └── transaction.go      # Billing transactions
├── web/                     # React frontend
│   ├── src/
│   │   ├── Setting.js      # UI configuration
│   │   └── Conf.js         # App config
│   └── public/img/         # Hanzo branding assets
├── compose.dev.yml         # Docker dev (PostgreSQL)
├── compose.mysql.yml       # Docker dev (MySQL)
├── compose.staging.yml     # Staging deployment
├── compose.production.yml  # Production deployment
├── init_data.json          # Default org/apps/users
└── Makefile                # Build commands
```

## Common Issues

### "could not open file global/pg_filenode.map"
PostgreSQL volume corruption. Fix:
```bash
docker compose -f compose.dev.yml down -v
docker volume prune
docker compose -f compose.dev.yml up -d
```

### "Access denied for user 'hanzo'@'%' to database 'hanzo_iamhanzo_iam'"
MySQL config issue - dataSourceName should end with `/` not `/dbname`:
```
dataSourceName = hanzo:pass@tcp(localhost:3306)/    # Correct
dataSourceName = hanzo:pass@tcp(localhost:3306)/db  # Wrong
```

## Related Projects

| Project | Path | Integration |
|---------|------|-------------|
| Cloud | `~/work/hanzo/cloud` | Uses IAM for auth, creates transactions |
| Commerce | `~/work/hanzo/commerce` | Processes payments, adds credits to IAM |
| Universe | `~/work/hanzo/universe` | Infrastructure deployment |
