// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"slices"

	policy "github.com/hanzoai/authz"
)

// reservedSlugs is THE table of names no organization may take: the top-level paths
// the hanzo.ai site and its edge answer, the IAM root's own routes, and the platform and
// brand names. An organization's issuer is `<tenant issuer>/<org>`, so an org named like
// any of these would put its discovery and key set on a path another route owns, and
// would read as that route's owner.
//
// It is one sorted table, kept here and nowhere else. It is read by ReservedSlug, which
// every path that founds an organization asks, and by TenantOrg, which every tenant
// issuer is derived through, so a name in it is neither creatable nor ever given an
// issuer. Its sources, merged and sorted: the hanzo.ai pages (hanzo-inc/app app/, its (app)
// and (marketing) route groups) and static directories (public/), the paths the edge routes
// name (universe infra/sites/sites.yaml, docs/urls.md), IAM's root routes, the well-known and
// framework paths, and the platform and brand names. A page the site gains is added here
// with the page. TestCreate_refusesEveryReservedSlug (organizations) and
// TestReservedSlugsAreNeverFoundedBySelfService (oidc) fail when a name in it can be created.
var reservedSlugs = []string{
	"about", "account", "admin", "affiliate", "agent", "agents", "ai", "analytics",
	"api", "app", "apps", "assets", "aup", "auth", "authors", "authz",
	"auto", "automations", "badge", "badges", "base", "benchmarks", "beta", "betaa",
	"billing", "blockchain", "blog", "board", "bot", "bots", "bounty", "brand",
	"builds", "built-in", "buying-specialist", "cal", "calculator", "callback", "captable", "careers",
	"chat", "chrome", "cli", "cloud", "commerce", "compare", "comparison", "computer",
	"connect", "connectors", "console", "contact", "contact-sales", "contacts", "cookies", "crawl",
	"css", "customers", "dashboard", "dashboards", "data-deletion", "dataroom", "datastore", "deploy",
	"design", "desktop", "dev", "dns", "docdb", "docs", "download", "drive",
	"edge", "email", "engine", "enso", "enterprise", "extension", "f", "favicon",
	"features", "files", "flow", "fonts", "forget", "forward", "founder", "functions",
	"gallery", "gateway", "gen", "git", "grants", "guard", "gui", "hanzo",
	"healthz", "help", "history", "home", "hsm", "iam", "id", "ide",
	"identity", "idv", "images", "inbox", "ingress", "insights", "install", "integrations",
	"investors", "invite", "iro", "jin", "join", "js", "kai", "kata",
	"kms", "koe", "koma", "leaderboard", "learn", "ledger", "legal", "library",
	"llms", "login", "logos", "logout", "lux", "machines", "mcp", "media",
	"meet", "memoji", "metrics", "models", "mori", "mq", "network", "newsletter",
	"node", "o11y", "oauth", "og", "oidc", "onboarding", "open-source", "opensearch",
	"operative", "operator", "oss", "oto", "pars", "pay", "payments", "philosophy",
	"platform", "playground", "press", "pricing", "privacy", "products", "providers", "public",
	"pubsub", "readyz", "realtime", "referral", "refunds", "registry", "research", "research-access",
	"returns", "reviews", "risk", "robots", "s3", "schema", "science", "sdks",
	"search", "security", "sentinel", "settings", "shots", "sign", "signin", "signup",
	"sitemap", "skill", "skills", "slack", "sms-opt-in", "solutions", "start", "startups",
	"static", "status", "stream", "studio", "support", "tabs", "tag", "tasks",
	"team", "telemetry", "templates", "terms", "treasury", "trust", "tunnel", "u",
	"ui", "university", "unsubscribe", "uploads", "uta", "v1", "videos", "visor",
	"work", "world", "zap", "zen", "zoo",
}

// ReservedSlug reports whether name may not be the name of an organization: the platform's
// own held orgs (reserved, brands, directories, the estate's) and every name in the
// reserved table. It is the one predicate for "is this name taken by the platform"; run
// it over existing organizations to find any that collide.
func ReservedSlug(name string) bool {
	return policy.IsHeldOrg(name) || slices.Contains(reservedSlugs, name)
}

// ReservedSlugs is a copy of the reserved table, sorted.
func ReservedSlugs() []string {
	out := slices.Clone(reservedSlugs)
	slices.Sort(out)
	return out
}
