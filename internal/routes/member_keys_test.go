// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// Who lists which keys, through the real router with real bearers. Belonging to an
// org opens its key list and administering it opens every key in it: a member sees
// the keys they hold, an admin sees the org's, a SuperAdmin sees any tenant's, and
// a confidential client presenting only its own credential sees the org it serves
// and no other.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const mintSecret = "mint-secret"

// memberKeyFixtures adds a plain member of orgb, makes hanzo/alice a member of
// orgb, files one key per holder, and registers hanzo-console (serving hanzo) as
// the deployment's credential administrator beside an app that is not one.
func memberKeyFixtures(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	seedUser(t, h.db, "orgb", "carol", false)
	if _, err := store.EnsureMembership(ctx, h.db, "hanzo/alice", "orgb", store.RoleMember); err != nil {
		t.Fatalf("grant: %v", err)
	}
	for _, k := range []struct{ owner, name, user string }{
		{"hanzo", "boss-key", "hanzo/boss"},
		{"hanzo", "alice-key", "alice"},
		{"orgb", "bob-key", "orgb/bob"},
		{"orgb", "carol-key", "carol"},
		{"orgb", "alice-key", "hanzo/alice"},
	} {
		row := orm.New[schema.Key](h.db)
		row.Owner, row.Name, row.User, row.State = k.owner, k.name, k.user, "Active"
		row.AccessKey = "pk-live-" + k.owner + "-" + k.name
		row.SetId(k.owner + "/" + k.name)
		if err := row.CreateCtx(ctx); err != nil {
			t.Fatalf("seed %s/%s: %v", k.owner, k.name, err)
		}
	}
	seedClientApp(t, h.db, "hanzo-console", mintSecret)
	seedClientApp(t, h.db, "hanzo-other", mintSecret)
	t.Setenv(policy.CapKeyMint.Env, "hanzo-console")
}

// listed is the "<owner>/<name>" of every key a 200 listing returned, sorted.
func listed(t *testing.T, status int, body string) []string {
	t.Helper()
	if status != 200 {
		t.Fatalf("listing answered %d: %s", status, body)
	}
	var out struct{ Keys []schema.Key }
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	got := make([]string, 0, len(out.Keys))
	for _, k := range out.Keys {
		got = append(got, k.Owner+"/"+k.Name)
	}
	slices.Sort(got)
	return got
}

func want(t *testing.T, who, path string, got []string, keys ...string) {
	t.Helper()
	slices.Sort(keys)
	if !slices.Equal(got, keys) {
		t.Fatalf("%s %s listed %v, want %v", who, path, got, keys)
	}
}

// A plain member lists their own keys in their own org, and in an org they joined,
// and never a colleague's.
func TestKeyList_aMemberListsTheKeysTheyHold(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	alice := h.token(t, "hanzo/alice")
	for _, path := range []string{"/v1/iam/keys?owner=hanzo", "/v1/iam/keys"} {
		s, b := h.get(t, path, alice)
		want(t, "hanzo/alice", path, listed(t, s, b), "hanzo/alice-key")
	}
	s, b := h.get(t, "/v1/iam/keys?owner=orgb", alice)
	want(t, "hanzo/alice", "?owner=orgb", listed(t, s, b), "orgb/alice-key")

	carol := h.token(t, "orgb/carol")
	s, b = h.get(t, "/v1/iam/keys?owner=orgb", carol)
	want(t, "orgb/carol", "?owner=orgb", listed(t, s, b), "orgb/carol-key")
}

// A person who does not belong to an org is refused its list, with the same bytes
// for a real org and an invented one, so the refusal says nothing about which
// exist.
func TestKeyList_aNonMemberIsRefused(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	carol := h.token(t, "orgb/carol")
	s, real := h.get(t, "/v1/iam/keys?owner=hanzo", carol)
	if s != 403 {
		t.Fatalf("orgb/carol listed hanzo's keys: %d %s", s, real)
	}
	s, invented := h.get(t, "/v1/iam/keys?owner=nonexistent-org-xyz", carol)
	if s != 403 || invented != real {
		t.Fatalf("an invented org answered differently from a real one: %d %q vs %q", s, invented, real)
	}
	if strings.Contains(real, "pk-live-") {
		t.Fatalf("a refusal carried a key: %s", real)
	}
}

// The admin of one org reads every key of that org and none of another's.
func TestKeyList_anOrgAdminReadsTheirOrgAndNoOther(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	boss, bob := h.token(t, "hanzo/boss"), h.token(t, "orgb/bob")

	s, b := h.get(t, "/v1/iam/keys?owner=hanzo", boss)
	want(t, "hanzo/boss", "?owner=hanzo", listed(t, s, b), "hanzo/boss-key", "hanzo/alice-key")
	s, b = h.get(t, "/v1/iam/keys?owner=orgb", bob)
	want(t, "orgb/bob", "?owner=orgb", listed(t, s, b), "orgb/bob-key", "orgb/carol-key", "orgb/alice-key")

	if s, b := h.get(t, "/v1/iam/keys?owner=orgb", boss); s != 403 {
		t.Fatalf("the admin of hanzo read orgb's keys: %d %s", s, b)
	}
	if s, b := h.get(t, "/v1/iam/keys?owner=hanzo", bob); s != 403 {
		t.Fatalf("the admin of orgb read hanzo's keys: %d %s", s, b)
	}
}

// A SuperAdmin reads any tenant's keys, and every tenant's when it names none.
func TestKeyList_aSuperAdminIsUnchanged(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	root := h.token(t, "admin/root")
	s, b := h.get(t, "/v1/iam/keys?owner=orgb", root)
	want(t, "admin/root", "?owner=orgb", listed(t, s, b), "orgb/bob-key", "orgb/carol-key", "orgb/alice-key")
	s, b = h.get(t, "/v1/iam/keys", root)
	want(t, "admin/root", "(no owner)", listed(t, s, b),
		"hanzo/boss-key", "hanzo/alice-key", "orgb/bob-key", "orgb/carol-key", "orgb/alice-key")
}

// The credential administrator presenting only its own credential reads the org it
// serves and is refused every other, so its mint reaching a tenant is never a read
// of that tenant. An app the allowlist does not name reads nothing at all.
func TestKeyList_theMintClientAloneReadsOnlyTheOrgItServes(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	s, b := h.getBasic(t, "/v1/iam/keys?owner=hanzo", "hanzo-console", mintSecret)
	want(t, "hanzo-console", "?owner=hanzo", listed(t, s, b), "hanzo/boss-key", "hanzo/alice-key")
	if s, b := h.getBasic(t, "/v1/iam/keys?owner=orgb", "hanzo-console", mintSecret); s != 403 {
		t.Fatalf("the mint client read orgb's keys on its own credential: %d %s", s, b)
	}
	if s, b := h.getBasic(t, "/v1/iam/keys?owner=hanzo", "hanzo-other", mintSecret); s != 403 {
		t.Fatalf("an app off the key-mint allowlist read keys: %d %s", s, b)
	}
}

// Two spellings of the owner bind one value, and whichever one binds is the one
// authorized: a member of orgb naming hanzo beside it never receives hanzo's keys.
func TestKeyList_aRepeatedOwnerNeverReadsAnotherOrg(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	carol := h.token(t, "orgb/carol")
	for range 40 {
		s, b := h.get(t, "/v1/iam/keys?owner=orgb&Owner=hanzo", carol)
		if strings.Contains(b, "pk-live-hanzo-") {
			t.Fatalf("orgb/carol received hanzo's keys: %d %s", s, b)
		}
	}
}

// A reserved org's keys are a SuperAdmin's alone: an admin of built-in or app, and
// a machine whose account lives in admin, read none of them.
func TestKeyList_aReservedOrgIsTheSuperAdminsAlone(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	ctx := context.Background()
	for _, org := range []string{"built-in", "app"} {
		seedUser(t, h.db, org, "ops", true)
		row := orm.New[schema.Key](h.db)
		row.Owner, row.Name, row.User = org, "ops-key", org+"/ops"
		row.SetId(org + "/ops-key")
		if err := row.CreateCtx(ctx); err != nil {
			t.Fatalf("seed %s key: %v", org, err)
		}
		for _, path := range []string{"/v1/iam/keys?owner=" + org, "/v1/iam/keys"} {
			if s, b := h.get(t, path, h.token(t, org+"/ops")); s != 403 {
				t.Fatalf("%s/ops listed %s: %d %s", org, path, s, b)
			}
		}
	}
	seedUser(t, h.db, "admin", "ci", false)
	ci, err := store.GetUserByName(ctx, h.db, "admin", "ci")
	if err != nil || ci == nil {
		t.Fatalf("read admin/ci: %v", err)
	}
	ci.Type = schema.ServiceAccount
	if err := ci.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if s, b := h.get(t, "/v1/iam/keys", h.token(t, "admin/ci")); s != 403 {
		t.Fatalf("a machine in admin listed admin's keys: %d %s", s, b)
	}
	s, b := h.get(t, "/v1/iam/keys?owner=built-in", h.token(t, "admin/root"))
	want(t, "admin/root", "?owner=built-in", listed(t, s, b), "built-in/ops-key")
}

// Belonging opens the LIST and nothing beneath it: a named key is still read by
// its org's admin alone.
func TestKeyList_aNamedKeyStaysTheAdmins(t *testing.T) {
	h := newHarness(t)
	memberKeyFixtures(t, h)
	if s, b := h.get(t, "/v1/iam/keys/hanzo/alice-key", h.token(t, "hanzo/alice")); s != 403 {
		t.Fatalf("a plain member read a named key: %d %s", s, b)
	}
	if s, b := h.get(t, "/v1/iam/keys/hanzo/alice-key", h.token(t, "hanzo/boss")); s != 200 {
		t.Fatalf("the org's admin could not read a named key: %d %s", s, b)
	}
}
