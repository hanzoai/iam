package organizations_test

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// RED-4a: a founder is named by subject id. A person created through users.Create
// is named by the id it was given; "<home>/<username>" names nobody.
func TestRedFounderByHomeName(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	in := &users.CreateInput{}
	in.User.Owner, in.User.Name = "acme", "bob"
	bob, err := users.New(db).Create(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	c := createIn("admin", "sideproject")
	c.Founder = "acme/bob"
	if _, err := organizations.NewOrganizationAPI(db).Create(ctx, c); err == nil {
		t.Fatal("a founder named by <home>/<username> was taken")
	}
	c = createIn("admin", "sideproject")
	c.Founder = bob.Id
	if _, err := organizations.NewOrganizationAPI(db).Create(ctx, c); err != nil {
		t.Fatalf("a founder named by subject id: %v", err)
	}
	if owners, _ := store.Owners(ctx, db, "sideproject"); len(owners) != 1 || owners[0] != "acme/bob" {
		t.Fatalf("owners = %v, want [acme/bob]", owners)
	}
}

// RED-4b: a storage key "acme/bob" left on an account that moved home resolves a
// later acme/bob's founder string to the moved person, who is made owner.
func TestRedFounderStorageKeyCollision(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	p := orm.New[schema.User](db)
	p.Owner, p.Name, p.Id = "pco", "bob", "uuid-p" // was acme/bob; moved home, key stays
	p.SetId("acme/bob")
	if err := p.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	in := &users.CreateInput{}
	in.User.Owner, in.User.Name = "acme", "bob" // a different, later person
	if _, err := users.New(db).Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	c := createIn("admin", "sideproject")
	c.Founder = "acme/bob"
	if _, err := organizations.NewOrganizationAPI(db).Create(ctx, c); err != nil {
		return
	}
	owners, _ := store.Owners(ctx, db, "sideproject")
	if len(owners) == 1 && owners[0] != "acme/bob" {
		t.Fatalf("MISASSIGNED: org created for acme/bob is owned by %v", owners)
	}
}

// RED-5: an org whose people all live elsewhere (every additional org cloud
// creates) leaves its projects and applications behind on delete, and its name
// is free again: the next org of that name, founded by a stranger, holds them.
func TestRedNameReuseInheritsRows(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	for _, u := range []struct{ owner, name, id string }{{"acme", "alice", "uuid-alice"}, {"evil", "mallory", "uuid-mallory"}} {
		row := orm.New[schema.User](db)
		row.Owner, row.Name, row.Id = u.owner, u.name, u.id
		if err := row.CreateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
	api := organizations.NewOrganizationAPI(db)
	c := createIn("admin", "side")
	c.Founder = "uuid-alice"
	if _, err := api.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	p := orm.New[schema.Project](db)
	p.Owner, p.Name = "side", "secret-project"
	p.SetId("side/secret-project")
	if err := p.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.Organization, a.ClientId = "side", "side-app", "side", "cid-side"
	a.SetId("side/side-app")
	if err := a.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: "admin", Name: "side"}); err != nil {
		t.Fatal(err)
	}
	again := createIn("admin", "side")
	again.Founder = "uuid-mallory"
	if _, err := api.Create(ctx, again); err != nil {
		return
	}
	t.Fatal("a deleted org's name was given again")
	pr, _ := orm.Get[schema.Project](db, "side/secret-project")
	ap, _ := orm.Get[schema.Application](db, "side/side-app")
	owners, _ := store.Owners(ctx, db, "side")
	if pr != nil || ap != nil {
		t.Fatalf("NAME REUSE: new org side (owners %v) inherits project=%v app=%v", owners, pr != nil, ap != nil)
	}
}
