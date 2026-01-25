# Hanzo IAM Multi-Tenant Architecture

## Overview

A unified IAM system that serves multiple organizations (Hanzo, Zoo, Lux, Pars) with:
- **iam.hanzo.ai** - Core shared backend API
- **hanzo.id, zoo.id, lux.id, pars.id** - Tenant-branded login frontends

```
                    ┌─────────────────────────────────────┐
                    │         iam.hanzo.ai               │
                    │    (Core IAM Backend API)          │
                    │  PostgreSQL + Redis + Go Backend   │
                    └─────────────────────────────────────┘
                              ↑    ↑    ↑    ↑
            ┌─────────────────┼────┼────┼────┼─────────────────┐
            │                 │    │    │    │                 │
      ┌─────┴─────┐    ┌──────┴────┴────┴────┴──────┐    ┌─────┴─────┐
      │ hanzo.id  │    │       Nginx/Caddy          │    │  zoo.id   │
      │ (Org:     │    │   Domain → Org Routing     │    │ (Org:     │
      │  hanzo)   │    │                            │    │  zoo)     │
      └───────────┘    └────────────────────────────┘    └───────────┘
            │                                                  │
      ┌─────┴─────┐                                      ┌─────┴─────┐
      │ lux.id    │                                      │ pars.id   │
      │ (Org:lux) │                                      │ (Org:pars)│
      └───────────┘                                      └───────────┘
```

## Architecture Options

### Option A: Single Frontend + Domain Routing (Recommended)

One IAM deployment with Nginx/Caddy routing domains to organizations:

```nginx
# /etc/nginx/conf.d/iam.conf
server {
    server_name hanzo.id;
    location / {
        proxy_pass http://iam-backend:8000;
        proxy_set_header X-Org-Name "hanzo";
        proxy_set_header Host $host;
    }
}

server {
    server_name zoo.id;
    location / {
        proxy_pass http://iam-backend:8000;
        proxy_set_header X-Org-Name "zoo";
        proxy_set_header Host $host;
    }
}
# ... same for lux.id, pars.id
```

**Pros:**
- Single deployment to maintain
- Shared infrastructure
- Easy updates

**Cons:**
- All tenants share same instance
- Downtime affects everyone

### Option B: Shared Backend + Separate Frontends

```
iam.hanzo.ai (API only, no UI)
     ↓
┌────┴────┬────────┬────────┐
│         │        │        │
hanzo.id  zoo.id  lux.id  pars.id
(React)   (React) (React) (React)
```

Each *.id domain runs its own React frontend that talks to iam.hanzo.ai.

**Pros:**
- Full branding control per tenant
- Frontend isolation
- Can deploy updates per-tenant

**Cons:**
- More deployments to manage
- Need to sync frontend versions

## Organization Configuration

### init_data.json - Multiple Organizations

```json
{
  "organizations": [
    {
      "name": "hanzo",
      "displayName": "Hanzo AI",
      "websiteUrl": "https://hanzo.ai",
      "favicon": "https://cdn.hanzo.ai/img/favicon.png",
      "themeData": {
        "themeType": "dark",
        "colorPrimary": "#fd4444"
      },
      "domains": ["hanzo.id", "auth.hanzo.ai"]
    },
    {
      "name": "zoo",
      "displayName": "Zoo Labs",
      "websiteUrl": "https://zoo.ngo",
      "favicon": "https://cdn.zoo.ngo/img/favicon.png",
      "themeData": {
        "themeType": "dark",
        "colorPrimary": "#10b981"
      },
      "domains": ["zoo.id", "auth.zoo.ngo"]
    },
    {
      "name": "lux",
      "displayName": "Lux Network",
      "websiteUrl": "https://lux.network",
      "favicon": "https://cdn.lux.network/img/favicon.png",
      "themeData": {
        "themeType": "dark",
        "colorPrimary": "#8b5cf6"
      },
      "domains": ["lux.id", "auth.lux.network"]
    },
    {
      "name": "pars",
      "displayName": "Pars",
      "websiteUrl": "https://pars.ai",
      "favicon": "https://cdn.pars.ai/img/favicon.png",
      "themeData": {
        "themeType": "light",
        "colorPrimary": "#3b82f6"
      },
      "domains": ["pars.id", "auth.pars.ai"]
    }
  ]
}
```

## Digital Ocean Deployment

### Infrastructure Setup

```yaml
# compose.production.yml
services:
  iam-backend:
    image: ghcr.io/hanzoai/iam:latest
    environment:
      - DATABASE_URL=postgres://...
      - REDIS_URL=redis://...
      - ORIGIN=https://iam.hanzo.ai
    deploy:
      replicas: 2
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]

  iam-frontend:
    image: ghcr.io/hanzoai/iam-frontend:latest
    environment:
      - CASDOOR_API_URL=http://iam-backend:8000
    deploy:
      replicas: 2

  caddy:
    image: caddy:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data

  postgres:
    image: postgres:16-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data
```

### Caddyfile for Multi-Domain

```caddyfile
# Core API
iam.hanzo.ai {
    reverse_proxy iam-backend:8000
}

# Tenant Login Pages
hanzo.id {
    reverse_proxy iam-frontend:80
    header X-Org-Name "hanzo"
}

zoo.id {
    reverse_proxy iam-frontend:80
    header X-Org-Name "zoo"
}

lux.id {
    reverse_proxy iam-frontend:80
    header X-Org-Name "lux"
}

pars.id {
    reverse_proxy iam-frontend:80
    header X-Org-Name "pars"
}
```

## User Flow

### Login Flow (hanzo.id example)

1. User visits `console.hanzo.ai`
2. Not logged in → Redirect to `hanzo.id/login?app=console&redirect=...`
3. `hanzo.id` shows Hanzo-branded login (red theme, Hanzo logo)
4. User authenticates
5. Redirect back to `console.hanzo.ai/api/auth/callback`
6. User is logged in

### Cross-Org SSO (Optional)

If user has accounts in multiple orgs:
1. User logged into `hanzo.id` visits `lux.id`
2. IAM checks for existing session cookie (domain: `.hanzo.ai`)
3. If trusted link exists, auto-login to Lux org
4. Otherwise, prompt for Lux credentials

## Security Model

### Tenant Isolation

```
┌─────────────────────────────────────────────────────────┐
│                    IAM Database                         │
├─────────────────────────────────────────────────────────┤
│ Users       │ org_id │ Only visible to own org admins  │
│ Apps        │ org_id │ Only accessible by org members  │
│ Permissions │ org_id │ Scoped to organization          │
│ Audit Logs  │ org_id │ Isolated per organization       │
└─────────────────────────────────────────────────────────┘
```

### Admin Levels

| Role | Scope | Can See |
|------|-------|---------|
| User | Self | Own profile only |
| Org Admin | Organization | All users/apps in their org |
| Global Admin | All | All orgs, all users (z@hanzo.ai) |

### API Access Control

```go
// Middleware checks org ownership
func OrgAuthMiddleware(c *gin.Context) {
    user := GetUser(c)
    orgName := c.Param("org")

    if !user.IsGlobalAdmin && user.Owner != orgName {
        c.AbortWithStatus(403)
        return
    }
    c.Next()
}
```

## Migration Steps

### Phase 1: Deploy Core IAM
1. Deploy iam.hanzo.ai to Digital Ocean
2. Configure PostgreSQL + Redis
3. Set up SSL certificates
4. Test with hanzo.id domain

### Phase 2: Add Organizations
1. Create Zoo, Lux, Pars organizations in IAM
2. Configure branding for each
3. Set up domain routing
4. Test login flows

### Phase 3: Integrate Applications
1. Update console.hanzo.ai → use hanzo.id OAuth
2. Update cloud.hanzo.ai → use hanzo.id OAuth
3. Update lux apps → use lux.id OAuth
4. Update zoo apps → use zoo.id OAuth

### Phase 4: Universe Integration
1. Add IAM service to ~/work/hanzo/universe
2. Add IAM service to ~/work/lux/universe
3. Configure shared secrets
4. Set up monitoring

## Files to Create

```
~/work/hanzo/iam/
├── compose.multi-tenant.yml    # Multi-org deployment
├── Caddyfile.multi-tenant      # Domain routing
├── init_data.multi-tenant.json # All orgs config
└── scripts/
    ├── deploy-do.sh            # Digital Ocean deploy
    └── add-org.sh              # Add new organization
```

## Environment Variables

```bash
# Core
DATABASE_URL=postgres://user:pass@postgres:5432/iam
REDIS_URL=redis://redis:6379
ENCRYPTION_KEY=<32-byte-hex>

# Multi-tenant
ENABLE_MULTI_TENANT=true
ALLOWED_ORIGINS=hanzo.id,zoo.id,lux.id,pars.id,iam.hanzo.ai

# Per-org secrets (in vault/secrets manager)
HANZO_CLIENT_SECRET=<secret>
ZOO_CLIENT_SECRET=<secret>
LUX_CLIENT_SECRET=<secret>
PARS_CLIENT_SECRET=<secret>
```

## Monitoring

```yaml
# Prometheus metrics
- iam_login_total{org="hanzo"}
- iam_login_total{org="zoo"}
- iam_active_sessions{org="*"}
- iam_api_latency_seconds
```

## Cost Estimate (Digital Ocean)

| Resource | Spec | Monthly |
|----------|------|---------|
| Droplet (IAM) | 2 vCPU, 4GB | $24 |
| Managed Postgres | 1GB | $15 |
| Managed Redis | 1GB | $15 |
| Load Balancer | | $12 |
| Spaces (backups) | 50GB | $5 |
| **Total** | | **~$71/mo** |

Or use App Platform:
| Resource | Spec | Monthly |
|----------|------|---------|
| App (IAM) | Basic | $12 |
| Database | Dev | $12 |
| **Total** | | **~$24/mo** |
