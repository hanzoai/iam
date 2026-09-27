// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

// A token minted with a key names the key's application as its client, so a key
// names an application of its own org only.

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

func TestKey_namesAnApplicationOfItsOwnOrgOnly(t *testing.T) {
	db := memDB(t)
	for _, a := range []struct{ name, org string }{{"acme-app", "acme"}, {"hanzo-console", "hanzo"}} {
		app := orm.New[schema.Application](db)
		app.Owner, app.Name, app.ClientId, app.Organization = "admin", a.name, a.name, a.org
		app.SetId("admin/" + a.name)
		if err := app.CreateCtx(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	admin := principal.Bind(context.Background(), &principal.Principal{Org: "acme", User: "boss", Admin: true})

	if _, err := create(db)(admin, &schema.Key{Owner: "acme", Name: "k1", Application: "hanzo-console"}); err == nil {
		t.Fatal("an acme key named hanzo's application")
	}
	if _, err := create(db)(admin, &schema.Key{Owner: "acme", Name: "k2", Application: "nobody"}); err == nil {
		t.Fatal("a key named an application that does not exist")
	}
	if _, err := create(db)(admin, &schema.Key{Owner: "acme", Name: "k3", Application: "acme-app"}); err != nil {
		t.Fatalf("a key naming its own org's application: %v", err)
	}
	if _, err := update(db)(admin, &schema.Key{Owner: "acme", Name: "k3", Application: "hanzo-console"}); err == nil {
		t.Fatal("an update moved a key onto hanzo's application")
	}
	root := principal.Bind(context.Background(), &principal.Principal{Org: "admin", User: "root", Sudo: true})
	if _, err := create(db)(root, &schema.Key{Owner: "acme", Name: "k4", Application: "hanzo-console"}); err != nil {
		t.Fatalf("a SuperAdmin's key: %v", err)
	}
}
