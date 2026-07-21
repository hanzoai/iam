package object

import "testing"

// brandSharedClients is every brand's shared login client (name, org) — one per
// white-label brand, all owner=admin, all satisfying name == org+"-app".
var brandSharedClients = []struct{ name, org string }{
	{"hanzo-app", "hanzo"},
	{"lux-app", "lux"},
	{"zoo-app", "zoo"},
	{"pars-app", "pars"},
	{"adnexus-app", "adnexus"},
	{"bootnode-app", "bootnode"},
}

// TestIsSharedLoginClient pins the white-label-symmetric predicate: EVERY brand's
// <brand>-app is a shared login client, and a per-app published client
// (<brand>-app-<slug>) or a normal platform app is NOT.
func TestIsSharedLoginClient(t *testing.T) {
	for _, s := range brandSharedClients {
		if !IsSharedLoginClient(&Application{Owner: "admin", Name: s.name, Organization: s.org}) {
			t.Errorf("IsSharedLoginClient(%s/%s) = false; want true (brand shared login client)", s.org, s.name)
		}
	}
	notShared := []struct{ name, org string }{
		{"hanzo-app-blog", "hanzo"}, // per-app published client — the extra -<slug> suffix
		{"zoo-app-store", "zoo"},    // per-app published client
		{"hanzo-cloud", "hanzo"},    // a normal platform app
		{"", ""},
	}
	for _, n := range notShared {
		if IsSharedLoginClient(&Application{Name: n.name, Organization: n.org}) {
			t.Errorf("IsSharedLoginClient(%s/%s) = true; want false", n.org, n.name)
		}
	}
	if IsSharedLoginClient(nil) {
		t.Error("IsSharedLoginClient(nil) = true; want false")
	}
}

// TestDeleteApplicationRefusesSharedLoginClientsSymmetrically is the white-label
// blocker RED found: the delete hard-refuse must protect EVERY brand's shared login
// client, not just hanzo-app. It asserts (1) all brands' <brand>-app are refused with
// a service token (isSuperAdmin=true — the guard short-circuits before any DB access,
// so the shared client can never be deleted), and (2) a legitimate per-app client
// (<org>-app-<slug>) still deletes.
func TestDeleteApplicationRefusesSharedLoginClientsSymmetrically(t *testing.T) {
	// (1) Symmetric refusal — no engine needed; the guard returns before touching the DB.
	for _, s := range brandSharedClients {
		deleted, err := DeleteApplication(&Application{Owner: "admin", Name: s.name, Organization: s.org}, true)
		if deleted || err != nil {
			t.Errorf("DeleteApplication(%s/%s, isSuperAdmin=true) = (%v, %v); want (false, nil) — shared login client must be refused",
				s.org, s.name, deleted, err)
		}
	}

	// (2) A legitimate per-app published client still deletes — real create→delete
	// against an in-memory engine so we prove the guard does NOT block it.
	engine := newTestEngine(t)
	if err := engine.Sync2(new(Application)); err != nil {
		t.Fatalf("sync Application: %v", err)
	}
	prev := ormer
	t.Cleanup(func() { ormer = prev })
	ormer = &Ormer{driverName: "sqlite", Engine: engine}

	perApp := &Application{Owner: "hanzo", Name: "hanzo-app-blog", Organization: "hanzo"}
	if _, err := engine.Insert(perApp); err != nil {
		t.Fatalf("insert per-app client: %v", err)
	}
	deleted, err := DeleteApplication(perApp, true)
	if err != nil || !deleted {
		t.Fatalf("per-app client hanzo-app-blog must delete, got (deleted=%v, err=%v)", deleted, err)
	}
	if n, _ := engine.Where("name = ?", "hanzo-app-blog").Count(&Application{}); n != 0 {
		t.Errorf("per-app client still present after delete (count=%d)", n)
	}
}

// TestUpdateApplicationRefusesRenamingSharedLoginClientsSymmetrically is the RENAME
// twin of the delete test (the asymmetry RED caught a second time): UpdateApplication
// must refuse renaming EVERY brand's shared login client (the login surface is keyed
// on <org>-app), not just hanzo-app. It asserts (1) a rename attempt on each brand's
// <brand>-app is a no-op — the name is pinned back to the stored value — even with a
// service token (isSuperAdmin=true), and (2) a legitimate <org>-app-<slug> rename is
// NOT pinned (proceeds normally).
func TestUpdateApplicationRefusesRenamingSharedLoginClientsSymmetrically(t *testing.T) {
	engine := newTestEngine(t)
	// UpdateApplication fetches oldApplication via getApplication (which hydrates
	// providers → needs Provider) and, on a real rename, applicationChangeTrigger
	// touches Organization/User/Resource/Permission. Sync them all so the fetch
	// succeeds (else UpdateApplication early-returns before the guard) and the per-app
	// path runs cleanly.
	if err := engine.Sync2(new(Application), new(Provider), new(Organization), new(User), new(Resource), new(Permission)); err != nil {
		t.Fatalf("sync: %v", err)
	}
	prev := ormer
	t.Cleanup(func() { ormer = prev })
	ormer = &Ormer{driverName: "sqlite", Engine: engine}

	// (1) Every brand's shared login client rename is refused (name pinned). The guard
	// runs early (before any DB mutation), so the pinned pointer is the authoritative
	// signal; because the name ends up unchanged, applicationChangeTrigger never fires.
	for _, s := range brandSharedClients {
		if _, err := engine.Insert(&Application{Owner: "admin", Name: s.name, Organization: s.org}); err != nil {
			t.Fatalf("insert %s: %v", s.name, err)
		}
		attempt := &Application{Owner: "admin", Name: s.name + "-hijack", Organization: s.org}
		_, _ = UpdateApplication("admin/"+s.name, attempt, true, "en") // service token; may error later, guard runs first
		if attempt.Name != s.name {
			t.Errorf("rename of shared login client %s NOT refused: got %q, want pinned %q", s.name, attempt.Name, s.name)
		}
		if n, _ := engine.Where("name = ?", s.name+"-hijack").Count(&Application{}); n != 0 {
			t.Errorf("shared login client %s was renamed on disk (hijack row exists)", s.name)
		}
	}

	// (2) A legitimate per-app published client is NOT pinned — the guard does not fire,
	// so the rename proceeds.
	perApp := &Application{Owner: "hanzo", Name: "hanzo-app-blog", Organization: "hanzo"}
	if IsSharedLoginClient(perApp) {
		t.Fatal("precondition: a per-app client must NOT be a shared login client")
	}
	if _, err := engine.Insert(perApp); err != nil {
		t.Fatalf("insert per-app: %v", err)
	}
	attempt := &Application{Owner: "hanzo", Name: "hanzo-app-blog-renamed", Organization: "hanzo"}
	_, _ = UpdateApplication("hanzo/hanzo-app-blog", attempt, true, "en")
	if attempt.Name != "hanzo-app-blog-renamed" {
		t.Errorf("legit per-app rename was blocked: name pinned to %q", attempt.Name)
	}
}
