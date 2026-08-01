// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// AN ORG-SCOPED REQUEST IS HONOURED OR REFUSED, NEVER SILENTLY REINTERPRETED.
//
// The defect these tests pin down, reproduced twice against production on
// 2026-07-28 with the hanzo-console client credential (home org `hanzo`):
//
//	GET /v1/iam/get-users?owner=hanzo             -> 200 ok, 262 records, owner=hanzo
//	GET /v1/iam/get-users?owner=lux               -> 200 ok, 262 records, owner=hanzo
//	GET /v1/iam/get-users?owner=nonexistent-xyz   -> 200 ok, 262 records, owner=hanzo
//
// Nothing in the status code, the `status` field, the message or the count says
// the filter was dropped, so a FABRICATED org is indistinguishable from a real
// one AND from the caller's own. That is not a confidentiality breach — no
// tenant's rows escape — it is MISATTRIBUTION, which is worse in one specific
// way: the caller believes it holds tenant B while holding tenant A. It nearly
// caused a production purge of the wrong tenant: an operator asked for
// owner=lux, received 262 hanzo accounts, and every surface signal read success.
//
// A status code is therefore NOT the contract here. Every case asserts on the
// RECORDS that crossed the wire, because "200 with somebody else's rows" is the
// exact failure being closed.

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
)

// ---- request helpers -------------------------------------------------------

// reply is one response reduced to what a client can actually observe.
type reply struct {
	status int
	body   string
}

// records decodes the v1 envelope's `data` array into (owner, name) pairs — the
// rows that actually crossed the wire.
func (r reply) records(t *testing.T) []schema.User {
	t.Helper()
	var env struct {
		Data []schema.User `json:"data"`
	}
	if err := json.Unmarshal([]byte(r.body), &env); err != nil {
		return nil // an error envelope carries no array; zero records is the point
	}
	return env.Data
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

// THE PRODUCTION REPRO. A non-super principal asking for an org that is not its
// own must be REFUSED — not answered with its own org's rows under the foreign
// org's name.
func TestScope_ForeignOrgIsRefusedNotSilentlyReinterpreted(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	auth := asApp("hanzo-console", "s3cret")

	// Own org: unchanged, and it is what makes the foreign case meaningful —
	// there ARE hanzo rows to be misattributed.
	own := h.send(t, "GET", "/v1/iam/get-users?owner=hanzo", auth, nil)
	if own.status != 200 {
		t.Fatalf("own-org listing = %d, want 200 (unchanged): %s", own.status, own.body)
	}
	if len(own.records(t)) == 0 {
		t.Fatal("own-org listing returned no rows; the fixture cannot prove misattribution")
	}

	for _, org := range []string{foreignRealOrg, fabricatedOrg} {
		t.Run(org, func(t *testing.T) {
			got := h.send(t, "GET", "/v1/iam/get-users?owner="+org, auth, nil)

			// (1) The refusal must be EXPLICIT.
			if got.status != 403 {
				t.Errorf("GET get-users?owner=%s = %d, want 403 — an org-scoped request "+
					"is honoured or refused, never silently reinterpreted: %s",
					org, got.status, got.body)
			}
			// (2) And it must carry NOTHING. A 403 that still ships rows, or a
			//     200 carrying the caller's own rows under another org's name, is
			//     the misattribution this closes.
			if owners := got.owners(t); len(owners) > 0 {
				t.Errorf("GET get-users?owner=%s returned rows owned by %v — the caller "+
					"asked for %s and was handed somebody else's tenant", org, owners, org)
			}
		})
	}
}

// The refusal must not become an ORG-EXISTENCE ORACLE. A foreign-but-real tenant
// and a name no tenant has ever had must be answered IDENTICALLY, byte for byte,
// or an unauthorized caller enumerates the customer list one guess at a time.
//
// The property is structural, not cosmetic: the decision is taken from the
// verified principal alone and never touches the store, so there is no lookup
// whose outcome could differ. This test is what keeps it that way.
func TestScope_ForeignAndFabricatedOrgsAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	auth := asApp("hanzo-console", "s3cret")

	for _, path := range []string{
		"/v1/iam/get-users?owner=",
		"/v1/iam/get-organizations?owner=",
		"/v1/iam/get-organization-projects?organization=",
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

	got := h.send(t, "GET", "/v1/iam/get-users?owner="+foreignRealOrg, root, nil)
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

// Own-org access is untouched for a HUMAN too, on the endpoints the Guard does
// not pre-authorize (their target rides in ?organization=, so authz.Scope is the
// only gate they have).
func TestScope_OwnOrgReadIsUnchangedForAHuman(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)
	boss := asUser(h.token(t, "hanzo/boss"))

	got := h.send(t, "GET", "/v1/iam/get-organization-projects?organization=hanzo", boss, nil)
	if got.status != 200 {
		t.Fatalf("own-org project list = %d, want 200 (unchanged): %s", got.status, got.body)
	}
	var env struct {
		Data []schema.Project `json:"data"`
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
		"/v1/iam/get-organization-projects?organization=" + foreignRealOrg,
		"/v1/iam/get-organization-workspaces?organization=" + foreignRealOrg,
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
		{"get-users", "/v1/iam/get-users?owner=%s"},
		{"get-organization", "/v1/iam/get-organization?id=admin%%2F%s"},
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

	got := h.send(t, "GET", "/v1/iam/get-organization?id=admin%2F"+foreignRealOrg,
		asApp("hanzo-console", "s3cret"), nil)
	if got.status != 200 {
		t.Fatalf("CapOrgAdmin registry read = %d, want 200 — onboarding reads Founder "+
			"through this: %s", got.status, got.body)
	}
	var env struct {
		Data struct {
			Owner string `json:"owner"`
			Name  string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(got.body), &env); err != nil {
		t.Fatalf("decode %s: %v", got.body, err)
	}
	if env.Data.Name != foreignRealOrg {
		t.Errorf("asked for org %q, got %q — a grant must return the org it was asked for, "+
			"never another", foreignRealOrg, env.Data.Name)
	}
}

// An UNSTATED scope is not a reinterpreted one. Omitting ?owner= has always
// meant "my own org" and still does — the rule is about a request that NAMES an
// org it may not have, not about one that names none.
func TestScope_UnstatedOwnerStillMeansOwnOrg(t *testing.T) {
	h := newHarness(t)
	seedScopeFixture(t, h)

	got := h.send(t, "GET", "/v1/iam/get-users", asApp("hanzo-console", "s3cret"), nil)
	if got.status != 200 {
		t.Fatalf("get-users with no owner = %d, want 200 (unchanged): %s", got.status, got.body)
	}
	owners := got.owners(t)
	if owners["hanzo"] == 0 || len(owners) != 1 {
		t.Errorf("get-users with no owner returned %v, want hanzo only", owners)
	}
}
