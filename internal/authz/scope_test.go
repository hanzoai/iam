// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package authz_test

// AN ORG-SCOPED REQUEST IS HONOURED OR REFUSED, NEVER SILENTLY REINTERPRETED.
//
// A listing that quietly drops the ?owner= filter answers 200 with the caller's
// own rows whatever org was asked for, so a fabricated org is indistinguishable
// from a real one AND from the caller's own. Nothing in the status code, the
// `status` field, the message or the count carries the difference — the caller
// holds tenant A believing it holds tenant B, and then filters and writes.
//
// A status code is therefore NOT the contract here. Every case asserts on the
// RECORDS that crossed the wire, because "200 with somebody else's rows" is the
// exact answer these tests exist to make impossible.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

// The two spellings an unauthorized caller must not be able to tell apart: a
// FOREIGN-BUT-REAL tenant, and a name no tenant has ever had. If these two
// answers differ in any byte, the refusal is an org-existence oracle.
const (
	foreignRealOrg = "lux"
	fabricatedOrg  = "nonexistent-org-xyz"
	// reservedOrg is the organization whose membership IS SuperAdmin, spelled here
	// because these tests are the package's outside view (authz_test) and the
	// constant is unexported. store.IsSuperAdmin holds the same word.
	reservedOrg = "admin"
)

// ---- request helpers -------------------------------------------------------

// reply is one response reduced to what a client can actually observe.
type reply struct {
	status int
	body   string
}

// records decodes a user listing into the rows that actually crossed the wire.
// The noun surface names its page after the resource (`users`); the retired verb
// surface wrapped everything in a compat `data` array, and a decoder still reading
// that key returns an empty page for a healthy 200 — which passes every "no
// foreign rows" loop without executing it once.
func (r reply) records(t *testing.T) []schema.User {
	t.Helper()
	var env struct {
		Users []schema.User `json:"users"`
	}
	if err := json.Unmarshal([]byte(r.body), &env); err != nil {
		return nil // an error envelope carries no array; zero records is the point
	}
	return env.Users
}

// owners returns the DISTINCT owners present in a listing — the misattribution
// assertion: a request for org X must never answer with rows owned by Y.
func (r reply) owners(t *testing.T) map[string]int {
	t.Helper()
	got := map[string]int{}
	for _, u := range r.records(t) {
		got[u.Owner]++
	}
	return got
}

// send issues one request through the REAL registered router and returns
// everything a client sees. auth is applied verbatim as the Authorization value.
func (h *harness) send(t *testing.T, method, path, auth string, body any) reply {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return reply{status: resp.StatusCode, body: string(b)}
}

// asApp is the client_secret_basic header a confidential client sends — the
// exact transport the hanzo-console credential used in the production repro.
func asApp(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

// asUser is the bearer header a human carries.
func asUser(tok string) string { return "Bearer " + tok }

// ---- fixtures --------------------------------------------------------------

// seedScopeFixture builds the production shape: a foreign-but-real tenant `lux`
// with its own users and projects alongside hanzo's, plus the admin-owned
// hanzo-console application whose capability allowlist admits it to the users
// entity. That capability is what carries the request PAST the Guard and into
// authz.Scope — without it the Guard refuses first and the silent discard is
// never reached, which is why a unit test on authorize() alone proves nothing
// here.
func seedScopeFixture(t *testing.T, h *harness) {
	t.Helper()
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")

	seedAppRow(t, h.db, "admin", "hanzo-console", "s3cret", signingKid)

	// The foreign-but-real tenant. Its org row exists, its users exist — so a
	// refusal that consulted the store COULD tell it apart from a fabrication.
	seedOrgRow(t, h.db, foreignRealOrg)
	seedUser(t, h.db, foreignRealOrg, "lux-alice", true, false, false)
	seedUser(t, h.db, foreignRealOrg, "lux-bob", false, false, false)
	seedProjectRow(t, h.db, foreignRealOrg, "lux-secret-project")

	seedOrgRow(t, h.db, "hanzo")
	seedProjectRow(t, h.db, "hanzo", "hanzo-project")
}

// seedOrgRow registers a tenant in the org registry, which is admin-owned: the
// org's identity is its NAME, not its owner.
func seedOrgRow(t *testing.T, db orm.DB, name string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", name
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org %s: %v", name, err)
	}
}

// seedWorkspaceRow adds one workspace under a tenant. Projects and workspaces are
// the two kinds a member may read across the orgs they belong to, so a test of
// that read has to seed both or half of it asserts over an empty page.
func seedWorkspaceRow(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	w := orm.New[schema.Workspace](db)
	w.Owner, w.Name = owner, name
	w.SetId(owner + "/" + name)
	if err := w.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed workspace %s/%s: %v", owner, name, err)
	}
}

// seedProjectRow adds one project under a tenant.
func seedProjectRow(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	p := orm.New[schema.Project](db)
	p.Owner, p.Name = owner, name
	p.SetId(owner + "/" + name)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed project %s/%s: %v", owner, name, err)
	}
}

// ---- the bug ---------------------------------------------------------------

// THE PRODUCTION REPRO. A principal holding NO cross-tenant grant, asking for an
// org that is not its own, must be REFUSED — not answered with its own org's rows
// under the foreign org's name.
//
// The subject is a PERSON. It used to be hanzo-console, an application the fixture
// grants IAM_USER_ADMIN_APPS two lines earlier, so the case asserted that a
// capability IAM had deliberately issued does not work. The retired verb surface
// did answer 403 there, because compat's listHandler ran authz.Scope ahead of the
// handler and Scope does not consult capabilities — so the verb was overriding the
// grant rather than enforcing a boundary. What a capability holder may do is
// pinned directly below, in both directions.
func TestScope_ForeignOrgIsRefusedNotSilentlyReinterpreted(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	seedUser(t, h.db, "hanzo", "staff", true, false, false) // admin OF hanzo, not platform
	auth := asUser(h.token(t, "hanzo/staff"))

	// Own org: unchanged, and it is what makes the foreign case meaningful —
	// there ARE hanzo rows to be misattributed.
	own := h.send(t, "GET", "/v1/iam/users?owner=hanzo", auth, nil)
	if own.status != 200 {
		t.Fatalf("own-org listing = %d, want 200 (unchanged): %s", own.status, own.body)
	}
	if len(own.records(t)) == 0 {
		t.Fatal("own-org listing returned no rows; the fixture cannot prove misattribution")
	}

	for _, org := range []string{foreignRealOrg, fabricatedOrg} {
		t.Run(org, func(t *testing.T) {
			got := h.send(t, "GET", "/v1/iam/users?owner="+org, auth, nil)

			// (1) The refusal must be EXPLICIT.
			if got.status != 403 {
				t.Errorf("GET /v1/iam/users?owner=%s = %d, want 403 — an org-scoped request "+
					"is honoured or refused, never silently reinterpreted: %s",
					org, got.status, got.body)
			}
			// (2) And it must carry NOTHING. A 403 that still ships rows, or a
			//     200 carrying the caller's own rows under another org's name, is
			//     the misattribution this closes.
			if owners := got.owners(t); len(owners) > 0 {
				t.Errorf("GET /v1/iam/users?owner=%s returned rows owned by %v — the caller "+
					"asked for %s and was handed somebody else's tenant", org, owners, org)
			}
		})
	}
}

// WHAT THE CAPABILITY BUYS, stated rather than left to be discovered.
//
// IAM_USER_ADMIN_APPS names the applications trusted to administer USERS, and an
// app's authority is its capability allowlist and nothing else — there is no org
// term in it, deliberately: an app that could only administer its own org's users
// would serve no tenant, and cloud's roster read (apps/account nameOf) forwards a
// tenant's owner under exactly this credential.
//
// So a capability holder reaching another tenant is the grant working. The
// boundary that remains is WHO HOLDS IT: the allowlist is an environment value,
// so widening it is a deployment decision somebody makes in writing.
func TestScope_ACapabilityHolderReachesTheTenantItAdministers(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	auth := asApp("hanzo-console", "s3cret")

	got := h.send(t, "GET", "/v1/iam/users?owner="+foreignRealOrg, auth, nil)
	if got.status != 200 {
		t.Fatalf("a holder of IAM_USER_ADMIN_APPS reading %s = %d, want 200: %s",
			foreignRealOrg, got.status, got.body)
	}
	// It must answer for the org ASKED FOR — the capability grants reach, never a
	// substitution of the caller's own tenant.
	owners := got.owners(t)
	if len(owners) == 0 {
		t.Fatalf("no rows, so the grant cannot be shown to work: %s", got.body)
	}
	for owner := range owners {
		if owner != foreignRealOrg {
			t.Errorf("asked for %s and got rows owned by %s", foreignRealOrg, owner)
		}
	}
}

// An app WITHOUT the capability is refused, which is what makes the allowlist the
// boundary rather than a formality.
func TestScope_AnAppWithoutTheCapabilityIsRefused(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	// A second application, absent from every allowlist the fixture set.
	seedAppRow(t, h.db, "admin", "hanzo-widget", "w1dget", signingKid)

	got := h.send(t, "GET", "/v1/iam/users?owner="+foreignRealOrg,
		asApp("hanzo-widget", "w1dget"), nil)
	if got.status != 403 {
		t.Errorf("an app holding no user capability read %s = %d, want 403: %s",
			foreignRealOrg, got.status, got.body)
	}
}

// The refusal must not become an ORG-EXISTENCE ORACLE. A foreign-but-real tenant
// and a name no tenant has ever had must be answered IDENTICALLY, byte for byte,
// or an unauthorized caller enumerates the customer list one guess at a time.
//
// The property is structural, not cosmetic: the decision is taken from the
// verified principal alone and never touches the store, so there is no lookup
// whose outcome could differ. This test is what keeps it that way.
//
// The subject is a PERSON, because the property is only about a caller who may
// NOT read the org. A holder of IAM_USER_ADMIN_APPS learns which tenants exist by
// administering them, so hiding existence from it would be theatre — the same
// argument IAM already makes for CapOrgAdmin, which can create orgs and read
// their founder.
func TestScope_ForeignAndFabricatedOrgsAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	seedUser(t, h.db, "hanzo", "staff", true, false, false) // admin OF hanzo, not platform
	auth := asUser(h.token(t, "hanzo/staff"))

	for _, path := range []string{
		"/v1/iam/users?owner=",
		"/v1/iam/organizations?owner=",
		"/v1/iam/projects?owner=",
		"/v1/iam/scim/v2/Users?owner=",
	} {
		t.Run(path, func(t *testing.T) {
			real := h.send(t, "GET", path+foreignRealOrg, auth, nil)
			fake := h.send(t, "GET", path+fabricatedOrg, auth, nil)
			if real.status != fake.status {
				t.Errorf("%s: real org -> %d, fabricated org -> %d: the STATUS distinguishes "+
					"a tenant that exists from one that does not", path, real.status, fake.status)
			}
			if real.body != fake.body {
				t.Errorf("%s: the BODY distinguishes a real tenant from a fabricated one\n"+
					"  real (%s): %s\n  fake (%s): %s",
					path, foreignRealOrg, real.body, fabricatedOrg, fake.body)
			}
		})
	}
}

// A SuperAdmin's cross-tenant reach is the ONE cross-tenant scope and is
// unchanged: it asks for lux and it gets LUX, not hanzo.
func TestScope_SuperAdminCrossOrgReadIsUnchanged(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	root := asUser(h.token(t, "admin/root"))

	got := h.send(t, "GET", "/v1/iam/users?owner="+foreignRealOrg, root, nil)
	if got.status != 200 {
		t.Fatalf("SuperAdmin cross-org listing = %d, want 200: %s", got.status, got.body)
	}
	owners := got.owners(t)
	if owners[foreignRealOrg] == 0 {
		t.Errorf("SuperAdmin asked for %s and got %v — cross-tenant reach regressed",
			foreignRealOrg, owners)
	}
	if len(owners) != 1 {
		t.Errorf("SuperAdmin asked for %s and got rows from %v — the owner filter was dropped",
			foreignRealOrg, owners)
	}
}

// Own-org access is untouched for a HUMAN, on the listing whose target rides in
// the query rather than in the path.
func TestScope_OwnOrgReadIsUnchangedForAHuman(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss"))

	got := h.send(t, "GET", "/v1/iam/projects?owner=hanzo", boss, nil)
	if got.status != 200 {
		t.Fatalf("own-org project list = %d, want 200 (unchanged): %s", got.status, got.body)
	}
	var env struct {
		Data []schema.Project `json:"projects"`
	}
	if err := json.Unmarshal([]byte(got.body), &env); err != nil {
		t.Fatalf("decode %s: %v", got.body, err)
	}
	if len(env.Data) == 0 {
		t.Errorf("own-org project list came back empty: %s", got.body)
	}
}

// The SAME silent discard, reachable by an ORDINARY HUMAN — no client credential
// needed. get-organization-projects and get-organization-workspaces are
// handler-authorized (their target rides in ?organization=, which the Guard does
// not inspect), so authz.Scope is the whole gate, and it rewrote the parameter.
// An org admin asking for lux's projects got HANZO's, labelled lux.
func TestScope_HandlerAuthorizedReadsAreNotSilentlyRewritten(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss"))

	for _, path := range []string{
		"/v1/iam/projects?organization=" + foreignRealOrg,
		"/v1/iam/workspaces?organization=" + foreignRealOrg,
	} {
		t.Run(path, func(t *testing.T) {
			got := h.send(t, "GET", path, boss, nil)
			if got.status != 403 {
				t.Errorf("GET %s = %d, want 403: %s", path, got.status, got.body)
			}
			var env struct {
				Data []map[string]any `json:"data"`
			}
			_ = json.Unmarshal([]byte(got.body), &env)
			for _, row := range env.Data {
				t.Errorf("GET %s returned a row owned by %v — a hanzo row answering a "+
					"request for %s is the misattribution, not a leak", path, row["owner"], foreignRealOrg)
			}
		})
	}
}

// THE WORST SHAPE OF THE BUG: a path-targeted SCIM read. `/Users/lux/alice`
// named a specific row in a specific tenant; Scope rewrote the owner half and
// the handler answered with hanzo/alice — a DIFFERENT HUMAN, under the requested
// identity's URL. A caller that then acts on that record acts on the wrong
// person in the wrong tenant.
func TestScope_SCIMPathTargetIsNeverRewrittenToAnotherTenant(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss"))

	got := h.send(t, "GET", "/v1/iam/scim/v2/Users/"+foreignRealOrg+"/alice", boss, nil)
	if got.status == 200 {
		t.Errorf("GET /Users/%s/alice = 200 — it resolved SOMEBODY, and hanzo/alice is "+
			"the only alice there is: %s", foreignRealOrg, got.body)
	}
	if got.status != 403 {
		t.Errorf("GET /Users/%s/alice = %d, want 403: %s", foreignRealOrg, got.status, got.body)
	}
}

// A WRITE misattribution is worse than a read one: a SCIM provisioning call that
// named tenant `lux` created the account inside `hanzo`. Assert the refusal AND
// that nothing was persisted anywhere — the real security property, not the
// status code.
func TestScope_SCIMProvisioningNeverLandsInTheWrongTenant(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss"))

	body := map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "misfiled",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User": map[string]any{
			"owner": foreignRealOrg,
		},
	}
	got := h.send(t, "POST", "/v1/iam/scim/v2/Users", boss, body)
	if got.status == 201 {
		t.Errorf("SCIM create naming owner=%s succeeded (%d): %s", foreignRealOrg, got.status, got.body)
	}
	if h.userExists(t, "hanzo", "misfiled") {
		t.Errorf("a create that NAMED tenant %s persisted the account under hanzo — "+
			"the caller believes it provisioned %s", foreignRealOrg, foreignRealOrg)
	}
	if h.userExists(t, foreignRealOrg, "misfiled") {
		t.Errorf("a hanzo admin provisioned an account inside %s", foreignRealOrg)
	}
}

// get-users AND get-organization must give the SAME answer to "may this
// principal see another tenant's org?" — for every principal that holds no
// cross-tenant grant. A human org-admin is the case that carries a secret, and on
// both verbs a foreign-but-real org and a fabricated one are the identical
// existence-independent refusal. Answering one of them differently would make the
// pair an org-existence oracle no matter how carefully the other was written.
func TestScope_GetUsersAndGetOrganizationAgreeForAnUngrantedPrincipal(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss")) // org-admin of hanzo, no capability, not super

	for _, verb := range []struct{ name, pattern string }{
		{"get-users", "/v1/iam/users?owner=%s"},
		{"get-organization", "/v1/iam/organizations/get?id=admin%%2F%s"},
	} {
		t.Run(verb.name, func(t *testing.T) {
			real := h.send(t, "GET", fmt.Sprintf(verb.pattern, foreignRealOrg), boss, nil)
			fake := h.send(t, "GET", fmt.Sprintf(verb.pattern, fabricatedOrg), boss, nil)
			if real.status == 200 || fake.status == 200 {
				t.Errorf("%s admitted a foreign org: real=%d fake=%d", verb.name, real.status, fake.status)
			}
			if real.status != fake.status || real.body != fake.body {
				t.Errorf("%s distinguishes a real tenant from a fabricated one — that pair IS "+
					"the org-existence oracle\n  real: %d %s\n  fake: %d %s",
					verb.name, real.status, real.body, fake.status, fake.body)
			}
		})
	}
}

// The other half of the coherent policy: where a cross-tenant grant DOES exist,
// it HONOURS the org the request names. CapOrgAdmin is the brand consoles'
// registry authority — they create customer orgs during onboarding and read
// Organization.Founder to resume a partial one — so a grant holder asking for lux
// gets LUX's row. Correctly attributed is the whole requirement; substituting
// hanzo's row here would be the same misattribution wearing a capability.
func TestScope_AGrantHonoursTheOrgItNamesAndNeverSubstitutes(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)

	got := h.send(t, "GET", "/v1/iam/organizations/get?owner=admin&name="+foreignRealOrg,
		asApp("hanzo-console", "s3cret"), nil)
	if got.status != 200 {
		t.Fatalf("CapOrgAdmin registry read = %d, want 200 — onboarding reads Founder "+
			"through this: %s", got.status, got.body)
	}
	var env struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal([]byte(got.body), &env); err != nil {
		t.Fatalf("decode %s: %v", got.body, err)
	}
	if env.Name != foreignRealOrg {
		t.Errorf("asked for org %q, got %q — a grant must return the org it was asked for, "+
			"never another", foreignRealOrg, env.Name)
	}
}

// AN UNSTATED ORG IS REFUSED, and that is a change from the retired surface.
//
// Omitting ?owner= used to mean "my own org": compat's listHandler resolved it
// through authz.Scope, which answers the caller's org for an empty request. The
// noun handler cannot do that — internal/users may not import internal/authz,
// because authz needs oidc.VerifyToken and oidc needs users.Authenticate, so the
// principal the default would come from is unreachable from there. It names the
// org or it is refused.
//
// Nothing live depended on the default: hanzoai/ai sends the owner on every read
// (internal/iam/user.go passes c.OrganizationName explicitly). The remaining cost
// is that IAM's own rule — "unstated is not reinterpreted, it means your own org"
// — now holds for the handlers that CAN reach authz.Scope and not for users,
// applications or permissions. One rule with two answers is what this contract
// exists to remove, so this is a gap to close rather than a decision that was
// made: it wants the principal's context carriage lifted into hanzoai/authz,
// beside the Principal type it is about, which breaks the cycle for all three.
func TestScope_AnUnstatedOrgIsRefusedRatherThanGuessed(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)

	got := h.send(t, "GET", "/v1/iam/users", asApp("hanzo-console", "s3cret"), nil)
	if got.status != 400 {
		t.Fatalf("an unstated owner = %d, want 400: %s", got.status, got.body)
	}
	// Refused, not answered with SOMEBODY's rows. A default that guessed wrong is
	// the misattribution this file is about, one step earlier.
	if owners := got.owners(t); len(owners) > 0 {
		t.Errorf("an unstated owner returned rows owned by %v", owners)
	}
}

func seedMembership(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = org, user+"@"+org
	m.User, m.Org, m.Role = user, org, role
	m.SetId(org + "/" + user)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership %s in %s: %v", user, org, err)
	}
}

// THE PRODUCTION BUG, and its exact repro. z@hanzo.ai administers several orgs;
// the console's switcher listed them and clicking one did nothing, because
// get-organization-projects?organization=<other> answered 403 and the switcher
// swallowed it. The account's HOME org was the only org it could read — the
// membership set, which IAM itself mints into the token's `orgs` claim to
// authorize exactly this switch, was ignored on IAM's own surface.
func TestScopeRead_AnOrgYouBelongToOpens(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	// A hanzo account that ADMINISTERS the other tenant, the way a real operator does.
	seedUser(t, h.db, "hanzo", "crossorg", false, false, false)
	seedMembership(t, h.db, "hanzo/crossorg", foreignRealOrg, "admin")
	seedWorkspaceRow(t, h.db, foreignRealOrg, "lux-secret-workspace")
	crossorg := asUser(h.token(t, "hanzo/crossorg"))

	// The org is named with ?owner=, the one spelling every noun on this surface
	// scopes by. The retired verb spelled it ?organization=, and a rename that
	// carried the address without the query would answer for the home org at 200.
	for _, tc := range []struct{ path, key string }{
		{"/v1/iam/projects?owner=" + foreignRealOrg, "projects"},
		{"/v1/iam/workspaces?owner=" + foreignRealOrg, "workspaces"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got := h.send(t, "GET", tc.path, crossorg, nil)
			if got.status != 200 {
				t.Fatalf("GET %s = %d, want 200 — a member of %s cannot read it: %s",
					tc.path, got.status, foreignRealOrg, got.body)
			}
			// Through RawMessage because the envelope carries a `total` beside the
			// page, and a map of slices cannot hold a number.
			var env map[string]json.RawMessage
			if err := json.Unmarshal([]byte(got.body), &env); err != nil {
				t.Fatalf("decode %s: %v", got.body, err)
			}
			var rows []map[string]any
			if err := json.Unmarshal(env[tc.key], &rows); err != nil {
				t.Fatalf("decode %s of %s: %v", tc.key, got.body, err)
			}
			// An empty page would pass the ownership loop below without executing it
			// once, so the seeded org must actually come back.
			if len(rows) == 0 {
				t.Fatalf("GET %s answered 200 with no %s — an empty page proves nothing "+
					"about who the rows belong to: %s", tc.path, tc.key, got.body)
			}
			// It must answer for the org ASKED FOR, never quietly for the home org.
			for _, row := range rows {
				if row["owner"] != foreignRealOrg {
					t.Errorf("GET %s returned a row owned by %v — answering for the home org "+
						"is the misattribution the strict clause existed to prevent", tc.path, row["owner"])
				}
			}
		})
	}
}

// The other half, and the reason this is a separate entry point: belonging to an
// org is permission to SEE it. A stranger is still refused, byte-identically.
func TestScopeRead_AStrangerIsStillRefused(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss")) // no membership anywhere but hanzo

	got := h.send(t, "GET", "/v1/iam/projects?organization="+foreignRealOrg, boss, nil)
	if got.status != 403 {
		t.Fatalf("a non-member read of %s = %d, want 403: %s", foreignRealOrg, got.status, got.body)
	}
}

// An operator is someone an existing operator put IN the reserved org, and that
// grant reaches every tenant. This asks it on `users` deliberately: users is the
// STRICT clause, the one ordinary membership never opens, so a 200 here can only
// come from Super.
//
// The repro is z@hanzo.ai. It holds the admin membership row, and IAM read the
// HOME org to decide sudo — so the operator grant bought nothing on IAM's own
// surface, while memberships.mayGrant already refused that same row to anyone but
// a SuperAdmin and cloud already honoured it. Two answers to one question.
func TestSuper_ReservedMembershipReachesEveryTenant(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	// Anchored in a brand org, as every operator who also does ordinary work is.
	seedUser(t, h.db, "hanzo", "operator", false, false, false)
	seedMembership(t, h.db, "hanzo/operator", reservedOrg, "admin")
	operator := asUser(h.token(t, "hanzo/operator"))

	got := h.send(t, "GET", "/v1/iam/users?owner="+foreignRealOrg, operator, nil)
	if got.status != 200 {
		t.Fatalf("GET get-users?owner=%s as a member of %q = %d, want 200 — the reserved "+
			"org is the one cross-tenant scope and its membership IS the grant: %s",
			foreignRealOrg, reservedOrg, got.status, got.body)
	}
	// And it must answer for the tenant ASKED FOR — masquerade, not a home-org read.
	owners := got.owners(t)
	if owners[foreignRealOrg] == 0 {
		t.Fatalf("GET get-users?owner=%s returned no %s rows (owners=%v); a SuperAdmin must be "+
			"handed the tenant it named, not its own", foreignRealOrg, foreignRealOrg, owners)
	}
	for owner := range owners {
		if owner != foreignRealOrg {
			t.Errorf("GET get-users?owner=%s returned a row owned by %q — masquerade answers "+
				"for the tenant asked for and nothing else", foreignRealOrg, owner)
		}
	}
}

// The other half, and the reason the reserved org is named rather than membership
// in general: ordinary membership still carries NO authority outside organizations.
// Belonging to a tenant lets you SEE that tenant (ScopeRead); it never makes you an
// operator of it, and never reaches a third one.
func TestSuper_OrdinaryMembershipIsNotSudo(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	seedUser(t, h.db, "hanzo", "member", false, false, false)
	seedMembership(t, h.db, "hanzo/member", foreignRealOrg, "admin")
	member := asUser(h.token(t, "hanzo/member"))

	got := h.send(t, "GET", "/v1/iam/users?owner="+foreignRealOrg, member, nil)
	if got.status != 403 {
		t.Fatalf("GET get-users?owner=%s as an ADMIN of %s = %d, want 403 — administering a "+
			"tenant is not platform sudo, and users is the strict clause: %s",
			foreignRealOrg, foreignRealOrg, got.status, got.body)
	}
	if owners := got.owners(t); len(owners) > 0 {
		t.Errorf("the refusal shipped rows owned by %v", owners)
	}
}
