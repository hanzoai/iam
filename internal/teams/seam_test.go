// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// These ask the op-invoke seam (authz.Authorize) and the handlers directly, with
// the real teams inputs. teams_test.go drives the same rules over REST; here the
// concern is the transports that never pass the Guard — MCP and the call plane —
// for which the seam is the whole write decision and the handler the whole read
// decision.
package teams

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

var (
	sudo   = &principal.Principal{Org: "admin", User: "root", Sudo: true}
	boss   = &principal.Principal{Org: "acme", User: "boss", Admin: true}
	alice  = &principal.Principal{Org: "acme", User: "alice"}
	eve    = &principal.Principal{Org: "orgb", User: "eve", Admin: true}
	nobody *principal.Principal
)

func as(p *principal.Principal) context.Context {
	if p == nil {
		return context.Background()
	}
	return principal.Bind(context.Background(), p)
}

func admitted(t *testing.T, p *principal.Principal, op zip.Op, in any) bool {
	t.Helper()
	d, err := authz.Authorize(as(p), op, in)
	return err == nil && d.Effect == zip.Allow
}

var (
	create = zip.Op{Method: "POST", Path: "/v1/iam/teams"}
	update = zip.Op{Method: "PUT", Path: "/v1/iam/teams/:name"}
	remove = zip.Op{Method: "DELETE", Path: "/v1/iam/teams/:name"}
	list   = zip.Op{Method: "GET", Path: "/v1/iam/teams"}
	read   = zip.Op{Method: "GET", Path: "/v1/iam/teams/:name"}
)

// A team write names its org optionally. Naming none is the caller's own org, and
// the seam decides THAT org — not the empty string it used to refuse everyone but a
// SuperAdmin on.
func TestSeam_WriteDecidesTheOrgTheHandlerWrites(t *testing.T) {
	cases := []struct {
		who  string
		p    *principal.Principal
		in   any
		op   zip.Op
		want bool
	}{
		{"admin, own org, create", boss, &Input{Name: "eng"}, create, true},
		{"admin, own org, update", boss, &Input{Name: "eng"}, update, true},
		{"admin, own org, delete", boss, &Ref{Name: "eng"}, remove, true},
		{"admin, own org named", boss, &Input{Owner: "acme", Name: "eng"}, create, true},
		{"member, create", alice, &Input{Name: "eng"}, create, false},
		{"member, update", alice, &Input{Name: "eng"}, update, false},
		{"member, delete", alice, &Ref{Name: "eng"}, remove, false},
		{"stranger naming acme, create", eve, &Input{Owner: "acme", Name: "eng"}, create, false},
		{"stranger naming acme, update", eve, &Input{Owner: "acme", Name: "eng"}, update, false},
		{"stranger naming acme, delete", eve, &Ref{Owner: "acme", Name: "eng"}, remove, false},
		{"admin naming a reserved org", boss, &Input{Owner: "admin", Name: "eng"}, create, false},
		{"SuperAdmin naming acme", sudo, &Input{Owner: "acme", Name: "eng"}, create, true},
		{"no principal", nobody, &Input{Name: "eng"}, create, false},
	}
	for _, c := range cases {
		if got := admitted(t, c.p, c.op, c.in); got != c.want {
			t.Errorf("%s: admitted=%v, want %v", c.who, got, c.want)
		}
	}
}

// A team read is the handler's to authorize (belonging opens it, which is wider
// than the seam's tenant rule), so the seam defers — but only for a caller there is
// one to authorize for.
func TestSeam_ReadsDeferToTheHandlerButNeedACaller(t *testing.T) {
	for _, op := range []zip.Op{list, read} {
		if !admitted(t, alice, op, &Ref{Name: "eng"}) {
			t.Errorf("%s %s: the seam refused a read the handler authorizes", op.Method, op.Path)
		}
		if admitted(t, nobody, op, &Ref{Name: "eng"}) {
			t.Errorf("%s %s: admitted with no principal", op.Method, op.Path)
		}
	}
}

// Because the seam defers a read, the handler is the only gate an MCP read meets:
// it must refuse a stranger naming another org, and pin a caller naming none to
// their own.
func TestHandler_ReadsAreScopedToTheCallersOrgs(t *testing.T) {
	db := openStore(t)
	h := New(db)
	if _, err := h.Create(as(boss), &Input{Name: "eng"}); err != nil {
		t.Fatalf("seed acme/eng: %v", err)
	}

	if _, err := h.List(as(eve), &ListInput{Owner: "acme"}); !isStatus(err, 403) {
		t.Errorf("stranger list of acme: err=%v, want 403", err)
	}
	if _, err := h.Get(as(eve), &Ref{Owner: "acme", Name: "eng"}); !isStatus(err, 403) {
		t.Errorf("stranger read of acme/eng: err=%v, want 403", err)
	}
	out, err := h.List(as(eve), &ListInput{})
	if err != nil {
		t.Fatalf("stranger's own list: %v", err)
	}
	for _, tm := range out.Teams {
		if tm.Owner != "orgb" {
			t.Errorf("VULN: orgb's own list returned %s/%s", tm.Owner, tm.Name)
		}
	}

	if _, err := h.Get(as(alice), &Ref{Name: "eng"}); err != nil {
		t.Errorf("member read of their org's team: %v", err)
	}
	if _, err := h.Get(as(nobody), &Ref{Owner: "acme", Name: "eng"}); !isStatus(err, 403) {
		t.Errorf("read with no principal: err=%v, want 403", err)
	}
}

// The handler writes the org the seam authorized: both ask the input's AuthzScope.
// A caller who reaches the handler directly is still bound by it.
func TestHandler_WritesFileUnderTheResolvedOrg(t *testing.T) {
	db := openStore(t)
	h := New(db)
	team, err := h.Create(as(boss), &Input{Name: "eng"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if team.Owner != "acme" || team.Id() != "acme/eng" {
		t.Fatalf("filed as %s (%s), want acme/eng", team.Id(), team.Owner)
	}
	if _, err := h.Create(as(eve), &Input{Owner: "acme", Name: "planted"}); !isStatus(err, 403) {
		t.Errorf("stranger create in acme: err=%v, want 403", err)
	}
	if _, err := h.Create(as(sudo), &Input{Name: "ops"}); !isStatus(err, 400) {
		t.Errorf("SuperAdmin create naming no org: err=%v, want 400", err)
	}
}

func openStore(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func isStatus(err error, status int) bool {
	var he *zip.HTTPError
	return errors.As(err, &he) && he.Status == status
}
