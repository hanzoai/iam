package authz

import (
	"context"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
)

// listInput is the shape every list op decodes to when the caller names nothing —
// which is exactly what an MCP `tools/call` with `{}` produces.
type listInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// THE SEAM IS THE ONLY CHECK MCP GETS.
//
// A REST read is authorized by Guard on the way in, using the target it reads
// off the query. MCP never passes Guard — Control only authenticates /mcp — so
// Authorize is the whole of the decision there.
//
// The seam used to admit `owner == ""` outright, on the reasoning that "the
// Guard did it on the way in and an input naming no owner has nothing left to
// check". That holds for REST and is false for MCP, where nothing checked
// anything: a regular user who is 403 for `GET /v1/iam/roles?owner=hanzo` got
// 200 and the rows from `get_v1_iam_roles {}`.
//
// One policy must not answer differently per transport, so an empty target is
// now decided rather than admitted.
func TestSeamDecidesAnEmptyTargetRatherThanAdmittingIt(t *testing.T) {
	regular := &principal.Principal{Org: "hanzo", User: "alice"}
	ctx := principal.Bind(context.Background(), regular)

	// The op an MCP `get_v1_iam_roles {}` invokes. `roles` is not on the
	// handler-authorized list, so the seam owns the decision.
	op := zip.Op{Method: "GET", Path: "/v1/iam/roles"}

	if err := Authorize(ctx, op, &listInput{}); err == nil {
		t.Fatal("a regular user listed roles with no target named — the seam admitted " +
			"what the Guard refuses over REST, which is the cross-transport hole")
	}
}

// The same read, named, is still refused — so the fix did not merely move the
// hole to "name the owner and you are through".
func TestSeamRefusesANamedForeignTargetToo(t *testing.T) {
	regular := &principal.Principal{Org: "hanzo", User: "alice"}
	ctx := principal.Bind(context.Background(), regular)
	op := zip.Op{Method: "GET", Path: "/v1/iam/roles"}

	if err := Authorize(ctx, op, &listInput{Owner: "orgb"}); err == nil {
		t.Fatal("a regular user read another org's roles")
	}
}

// REST-NEUTRALITY, stated as a test rather than as a claim.
//
// A read whose path IS handler-authorized still passes the seam untouched: those
// are the reads whose rule is wider than the tenant rule (belonging opens a
// project or workspace list), and the handler authorizes them. Guard skips them
// by the same predicate, so both sides agree about who is responsible.
func TestSeamStillDefersToTheHandlerAuthorizedReads(t *testing.T) {
	regular := &principal.Principal{Org: "hanzo", User: "alice"}
	ctx := principal.Bind(context.Background(), regular)

	for _, path := range handlerAuthorizedPaths(t) {
		op := zip.Op{Method: "GET", Path: path}
		if err := Authorize(ctx, op, &listInput{}); err != nil {
			t.Fatalf("%s is handler-authorized; the seam must defer, got %v", path, err)
		}
	}
}

// handlerAuthorizedPaths returns paths pathAuthorized admits, so the test above
// is written against the real predicate rather than a copy of its list.
func handlerAuthorizedPaths(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, p := range []string{
		"/v1/iam/projects", "/v1/iam/workspaces", "/v1/iam/roles",
		"/v1/iam/users", "/v1/iam/certs",
	} {
		if pathAuthorized(p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Skip("no handler-authorized path among the probes; nothing to assert deferral on")
	}
	return out
}
