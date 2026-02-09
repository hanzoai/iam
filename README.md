<h1 align="center" style="border-bottom: none;">📦⚡️ Casdoor</h1>
<h3 align="center">An open-source UI-first Identity and Access Management (IAM) / Single-Sign-On (SSO) platform with web UI supporting OAuth 2.0, OIDC, SAML, CAS, LDAP, SCIM, WebAuthn, TOTP, MFA and RADIUS</h3>
<p align="center">
  <a href="#badge">
    <img alt="semantic-release" src="https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg">
  </a>
  <a href="https://hub.docker.com/r/hanzoai/iam">
    <img alt="docker pull hanzoai/iam" src="https://img.shields.io/docker/pulls/hanzoai/iam.svg">
  </a>
  <a href="https://github.com/hanzoai/iam/actions/workflows/build.yml">
    <img alt="GitHub Workflow Status (branch)" src="https://github.com/hanzoai/iam/workflows/Build/badge.svg?style=flat-square">
  </a>
  <a href="https://github.com/hanzoai/iam/releases/latest">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/iam/iam.svg">
  </a>
  <a href="https://hub.docker.com/r/hanzoai/iam">
    <img alt="Docker Image Version (latest semver)" src="https://img.shields.io/badge/Docker%20Hub-latest-brightgreen">
  </a>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/hanzoai/iam">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/hanzoai/iam?style=flat-square">
  </a>
  <a href="https://github.com/hanzoai/iam/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/iam/iam?style=flat-square" alt="license">
  </a>
  <a href="https://github.com/hanzoai/iam/issues">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/iam/iam?style=flat-square">
  </a>
  <a href="#">
    <img alt="GitHub stars" src="https://img.shields.io/github/stars/iam/iam?style=flat-square">
  </a>
  <a href="https://github.com/hanzoai/iam/network">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/iam/iam?style=flat-square">
  </a>
  <a href="https://crowdin.com/project/iam-site">
    <img alt="Crowdin" src="https://badges.crowdin.net/iam-site/localized.svg">
  </a>
  <a href="https://discord.gg/5rPsrAzK7S">
    <img alt="Discord" src="https://img.shields.io/discord/1022748306096537660?style=flat-square&logo=discord&label=discord&color=5865F2">
  </a>
</p>

## Online demo

- Read-only site: https://door.iam.com (any modification operation will fail)
- Writable site: https://demo.iam.com (original data will be restored for every 5 minutes)

## Documentation

https://iam.hanzo.ai

## Install

- By source code: https://iam.hanzo.ai/docs/basic/server-installation
- By Docker: https://iam.hanzo.ai/docs/basic/try-with-docker
- By Kubernetes Helm: https://iam.hanzo.ai/docs/basic/try-with-helm

## How to connect to Casdoor?

https://iam.hanzo.ai/docs/how-to-connect/overview

## Casdoor Public API

- Docs: https://iam.hanzo.ai/docs/basic/public-api
- Swagger: https://door.iam.com/swagger

## Integrations

https://iam.hanzo.ai/docs/category/integrations

## How to contact?

- Discord: https://discord.gg/5rPsrAzK7S
- Contact: https://iam.hanzo.ai/help

## Contribute

For iam, if you have any questions, you can give Issues, or you can also directly start Pull Requests(but we recommend giving issues first to communicate with the community).

### I18n translation

If you are contributing to iam, please note that we use [Crowdin](https://crowdin.com/project/iam-site) as translating platform and i18next as translating tool. When you add some words using i18next in the `web/` directory, please remember to add what you have added to the `web/src/locales/en/data.json` file.

## License

[Apache-2.0](https://github.com/hanzoai/iam/blob/master/LICENSE)
