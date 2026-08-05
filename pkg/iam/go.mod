// Deprecated: this module carries no package and never will. It exists ONLY to
// retract the Casdoor-lineage versions published under this path (below).
//
// To embed IAM in a Go process, import github.com/hanzoai/iam/server directly:
//
//	host.Use(iamserver.NewApp(db))              // the whole IAM surface, in-process
//	claims, err := iamserver.VerifyToken(ctx, db, bearer)
//
// That is not aspirational — hanzoai/cloud links github.com/hanzoai/iam and
// mounts it as its `iam` plugin (apps/iam/iam.go), serving .well-known/jwks,
// .well-known/openid-configuration and /login/oauth in production today.
//
// The note that used to be here said the opposite — "IAM is a binary you run,
// not a library you link into your server; talk to it over HTTP with
// github.com/hanzoai/iamsdk/v2". Both halves were false: IAM is linked in-process
// by cloud, and that SDK is gone. Being the one document a reader finds when they
// go looking, it sent a KMS token-verification fix to an HTTP SDK instead of the
// in-process verifier, which is how KMS ended up with a hand-rolled JWKS cache
// whose algorithm allowlist disagrees with the one IAM actually mints under.
//
// A process that is NOT the IAM host does not link this library at all. Plugins
// are processes: they ask the iam plugin over the ZAP/UDS plane with a typed op,
// the same way every other cross-plugin call in cloud works.
module github.com/hanzoai/iam/pkg/iam

go 1.26.5

// The root go.mod retracts the Casdoor versions of github.com/hanzoai/iam, but
// retraction is per-module: it cannot reach this path. Without the block below,
// github.com/hanzoai/iam/pkg/iam stays the last Casdoor-lineage module still
// resolvable under the canonical prefix — `go get` it today and you get Beego,
// xorm, and iam v1.31.17 from a path that looks current.
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

retract [v1.18.0, v1.18.7] // Casdoor lineage; use github.com/hanzoai/iam/server
