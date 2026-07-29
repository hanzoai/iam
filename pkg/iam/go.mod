// Deprecated: the in-process Embed + Mount entry points belonged to the
// Casdoor-derived lineage of github.com/hanzoai/iam, retired at v1.32.0. They
// live on, byte-identical, at github.com/hanzoai/iam-v1/pkg/iam. v2 has no
// in-process embed — IAM is a binary you run, not a library you link into your
// server; talk to it over HTTP with github.com/hanzoai/iamsdk/v2.
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
