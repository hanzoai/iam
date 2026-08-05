// Deprecated: THIS MODULE PATH — github.com/hanzoai/iam/pkg/iam — is the last
// Casdoor-lineage module resolvable under the canonical prefix; see the
// retraction note below for why it is retracted rather than deleted. Depend on
// github.com/hanzoai/iam itself.
//
// What this note used to say, and why it was wrong. It read: "v2 has no
// in-process embed — IAM is a binary you run, not a library you link into your
// server; talk to it over HTTP with github.com/hanzoai/iamsdk/v2." Every clause
// of that is false, and it was false while it was being read as guidance:
//
//   - IAM IS linked in-process, in production, by the thing that matters most.
//     hanzoai/cloud requires github.com/hanzoai/iam v1.34.20 with NO replace
//     directive, imports `iamserver "github.com/hanzoai/iam/server"` in
//     apps/iam/iam.go, and composes iamserver.NewApp(db) into cloud's own router
//     via zip.Graft. 25 non-vendor .go files across cloud import
//     github.com/hanzoai/iam/*.
//   - So "a binary you run, not a library you link into your server" inverts the
//     actual deployment. It is both, and the in-process path is the live one.
//   - github.com/hanzoai/iamsdk is not somewhere to send anyone: it redirects to
//     a private repo, so the link is a 404 for any reader outside the org, and
//     the SDK is being retired.
//
// Retiring an entry point is a claim about the code. Check it against the code
// before writing it down — this one shipped, propagated into the docs as an
// `iamsdk` import path that never existed, and stayed there.
module github.com/hanzoai/iam/pkg/iam

go 1.26.5

// The root go.mod retracts the Casdoor versions of github.com/hanzoai/iam, but
// retraction is per-module: it cannot reach this path. Without the block below,
// github.com/hanzoai/iam/pkg/iam stayed the last Casdoor-lineage module still
// resolvable under the canonical prefix — `go get` it today and you get Beego,
// xorm, and iam v1.31.17 from a path that looks like v2.
//
// Deleting the pkg/iam/* tags would not fix that: proxy.golang.org has all seven
// cached (verified — @v/list returns them, @latest resolves v1.18.6), and module
// versions are immutable there. Deletion would only split the world — proxied
// resolvers would keep serving Casdoor code while direct-VCS resolvers 404.
// Retraction reaches both.
//
// The range is self-inclusive: v1.18.7 carries no package either, so every
// version of this path is withdrawn and `go get .../pkg/iam` fails loudly
// instead of silently handing back the old lineage.

retract [v1.18.0, v1.18.7] // Casdoor lineage; use github.com/hanzoai/iam-v1/pkg/iam
