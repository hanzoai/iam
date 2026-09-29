package webauthn

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// RED-6: an admin files no passkey under a member, so none survives the
// member being made an owner.
func TestRedAdminPlantsNoPasskey(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Id = "hanzo", "alice", "uuid-alice"
	u.SetId("hanzo/alice")
	if err := u.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	admin := actingForAlice(ctx) // hanzo/boss, IsAdmin
	if _, err := addWebauthnCredential(db)(admin, &schema.WebauthnCredential{
		Owner: "hanzo", Name: "boss-authenticator", User: "hanzo/alice", PublicKey: []byte("admin-held-key"),
	}); err == nil {
		t.Fatal("an admin filed a passkey that signs in as a member")
	}
	if c, _ := orm.Get[schema.WebauthnCredential](db, "hanzo/boss-authenticator"); c != nil {
		t.Fatal("a refused passkey was stored")
	}
}
