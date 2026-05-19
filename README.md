# iam

Identity and Access Management for the Hanzo platform. OAuth 2.1, OIDC, SAML, CAS, LDAP, SCIM, WebAuthn, TOTP, MFA, RADIUS — multi-tenant, white-label.

[![Status](https://img.shields.io/badge/status-stable-green)]()
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)]()

## Quick start

```bash
docker run -p 8000:8000 ghcr.io/hanzoai/iam:latest
```

Open `http://localhost:8000`.

## What this is

`iam` is the canonical identity provider for every Hanzo deployment. Serves SSO across `hanzo.id`, `lux.id`, `zoo.id`, `pars.id`, and any white-label domain a tenant configures. Issues JWTs that every other Hanzo subsystem trusts via a single JWKS endpoint.

## Specs

Implements:
- HIP-0026 IAM Standard (RFC 6749 / OIDC compliant endpoints)
- HIP-0106 Unified Cloud Binary (iam subsystem)

## Architecture

```
   user / app  ->  hanzo.id / {tenant}.id  ->  iam (zip.App)
                                                  |
                                          OAuth2/OIDC/SAML
                                          users, orgs, apps, roles
                                                  |
                                       JWT signed with per-tenant key
                                                  |
                              every other Hanzo subsystem trusts via JWKS
                              (gateway strips client-supplied identity
                              headers, mints validated ones from the JWT)
```


---

<h1 align="center" style="border-bottom: none;">Hanzo IAM</h1>
<h3 align="center">An open-source AI-first Identity and Access Management (IAM) /AI MCP gateway and auth server with web UI supporting MCP, A2A, OAuth 2.1, OIDC, SAML, CAS, LDAP, SCIM, WebAuthn, TOTP, MFA, Face ID, Google Workspace, Azure AD</h3>
<p align="center">
Identity and Access Management for the Hanzo ecosystem.<br/>
UI-first centralized authentication / Single-Sign-On (SSO) platform supporting
OAuth 2.0, OIDC, SAML, CAS, LDAP, SCIM, WebAuthn, TOTP, MFA, and RADIUS.
</p>

<p align="center">
  <a href="https://github.com/hanzoai/iam/actions/workflows/build.yml">
    <img alt="Build" src="https://github.com/hanzoai/iam/workflows/Build/badge.svg">
  </a>
  <a href="https://github.com/hanzoai/iam/releases/latest">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/hanzoai/iam">
  </a>
  <a href="https://hub.docker.com/r/hanzoai/iam">
    <img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/hanzoai/iam">
  </a>
  <a href="https://goreportcard.com/report/github.com/hanzoai/iam">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/hanzoai/iam">
  </a>
  <a href="https://github.com/hanzoai/iam/blob/master/LICENSE">
    <img alt="License" src="https://img.shields.io/github/license/hanzoai/iam">
  </a>
</p>

---

## Features

- **OAuth 2.0 / OIDC provider** -- standards-compliant identity provider with full authorization code, implicit, client-credentials, and device-code flows
- **SAML / CAS / LDAP** -- enterprise federation and directory integration
- **WebAuthn / Passkeys** -- passwordless authentication with FIDO2 hardware keys and platform authenticators
- **TOTP / MFA** -- time-based one-time passwords and multi-factor authentication
- **Social login** -- 40+ identity providers (GitHub, Google, Apple, Microsoft, Discord, and more)
- **RBAC** -- role-based access control with fine-grained permissions
- **Multi-tenancy** -- multiple organizations and applications in a single deployment
- **API-first** -- full REST API for programmatic user, application, and organization management
- **SCIM provisioning** -- automated user lifecycle management
- **RADIUS** -- network access authentication

## Quick Start

### Docker

```bash
docker run -d \
  --name hanzo-iam \
  -p 8000:8000 \
  hanzoai/iam:latest
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

### Docker Compose

```yaml
# compose.yml
services:
  iam:
    image: hanzoai/iam:latest
    ports:
      - "8000:8000"
    volumes:
      - iam-data:/var/lib/iam
    restart: unless-stopped

volumes:
  iam-data:
```

```bash
docker compose up -d
```

### From Source

```bash
git clone https://github.com/hanzoai/iam.git
cd iam
go build ./...
```

## Domains

Hanzo IAM serves SSO across multiple organizations via white-label domain support:

| Domain | Purpose |
|--------|---------|
| [hanzo.id](https://hanzo.id) | Hanzo AI accounts |

Additional domains can be configured per organization. Each domain gets its own branding, login flow, and user pool while sharing the same IAM infrastructure.

## Documentation

Full documentation is available at [docs.hanzo.ai](https://docs.hanzo.ai).

## License

[Apache-2.0](https://github.com/hanzoai/iam/blob/master/LICENSE) — historical attribution and third-party notices in [NOTICE](./NOTICE).

Copyright 2025-2026 Hanzo AI Inc
