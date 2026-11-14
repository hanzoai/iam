package oidc

import (
	"strings"

	"github.com/hanzoai/iam/pkg/schema"
)

// A relying party that is a forge (git.hanzo.ai) reads a token's `scope` claim in
// its own vocabulary: `read:<area>`, `write:<area>`, `public-only` and `all`. The
// claim is one space-separated list (RFC 9068 §2.2.3) in which these ride beside
// the OIDC scopes; there is no second token format.
//
// IAM is the issuer, so IAM is where a request is held to what the application
// may be granted. An OIDC scope is untouched. A forge scope is kept only when the
// application lists it in its Scopes (the same list that bounds a device grant
// and a dynamic client), so a client asking for `all` gets it only if an
// administrator put `all` on that application. The forge then narrows once more
// to the holder's role; scope only ever narrows.

// forgeAreas are the areas the forge's `read:`/`write:` scopes name.
var forgeAreas = map[string]bool{
	"activitypub": true, "admin": true, "issue": true, "misc": true,
	"notification": true, "organization": true, "package": true,
	"repository": true, "user": true,
}

// isForgeScope reports whether s is spelled in the forge's vocabulary.
func isForgeScope(s string) bool {
	if s == "all" || s == "public-only" {
		return true
	}
	verb, area, ok := strings.Cut(s, ":")
	return ok && (verb == "read" || verb == "write") && forgeAreas[area]
}

// forgeScoped is scope with every forge scope the application does not hold taken
// out, in the order asked and without repeats. An application holding `write:X`
// may also be asked for `read:X`, since read is the narrower of the pair.
func forgeScoped(app *schema.Application, scope string) string {
	held := map[string]bool{}
	if app != nil {
		for _, s := range app.Scopes {
			if s != nil {
				held[strings.TrimSpace(s.Name)] = true
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.Fields(scope) {
		if seen[s] {
			continue
		}
		if isForgeScope(s) && !held[s] && !(strings.HasPrefix(s, "read:") && held["write:"+s[len("read:"):]]) {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, " ")
}
