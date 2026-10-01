// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A person's key is their own, through the real router: a key an org's admin
// creates naming nobody names them and acts in the org it is filed in, naming
// anyone else is refused, and a SuperAdmin names the person a key is for — how an
// existing org's owner is given their default key.
func TestAPersonsKeyIsTheirOwn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	boss, root := h.person(t, "hanzo/boss"), h.person(t, "admin/root")

	status, body := h.send(t, boss, "POST", "/v1/iam/keys", `{"owner":"hanzo","name":"mine"}`)
	if status != 200 {
		t.Fatalf("hanzo/boss could not create a key: %d %s", status, body)
	}
	var made schema.Key
	if err := json.Unmarshal([]byte(body), &made); err != nil {
		t.Fatalf("decode: %v %s", err, body)
	}
	if made.User != "hanzo/boss" {
		t.Fatalf("key holder = %q, want the caller hanzo/boss", made.User)
	}
	hd, err := store.HolderByAccessKey(ctx, h.db, made.AccessSecret)
	if err != nil {
		t.Fatalf("the key does not authenticate: %s", store.Reason(err))
	}
	if hd.User.Owner != "hanzo" || hd.User.Name != "boss" || hd.Org != "hanzo" {
		t.Fatalf("the key speaks for %s/%s in %s, want hanzo/boss in hanzo", hd.User.Owner, hd.User.Name, hd.Org)
	}

	for _, other := range []string{"alice", "hanzo/alice"} {
		if status, body := h.send(t, boss, "POST", "/v1/iam/keys", `{"owner":"hanzo","name":"theirs","user":"`+other+`"}`); status != 403 {
			t.Fatalf("hanzo/boss created a key held by %s: %d %s", other, status, body)
		}
	}
	if _, err := orm.Get[schema.Key](h.db, "hanzo/theirs"); err == nil {
		t.Fatal("a refused create wrote a key")
	}

	if status, body := h.send(t, root, "POST", "/v1/iam/keys", `{"owner":"hanzo","name":"default","displayName":"Default","user":"hanzo/alice"}`); status != 200 {
		t.Fatalf("a SuperAdmin could not give alice her key: %d %s", status, body)
	}
	if k, err := orm.Get[schema.Key](h.db, "hanzo/default"); err != nil || k.User != "hanzo/alice" || k.DisplayName != "Default" {
		t.Fatalf("hanzo/default = %+v, %v; want \"Default\" held by hanzo/alice", k, err)
	}
}

// An edit through the router that leaves the holder out — the shape a display-name
// change sends — keeps the holder; naming another holder is refused.
func TestAPersonsKeyEditKeepsItsHolder(t *testing.T) {
	h := newHarness(t)
	boss := h.person(t, "hanzo/boss")
	if status, body := h.send(t, boss, "POST", "/v1/iam/keys", `{"owner":"hanzo","name":"mine"}`); status != 200 {
		t.Fatalf("create: %d %s", status, body)
	}
	if status, body := h.send(t, boss, "PUT", "/v1/iam/keys/hanzo/mine", `{"owner":"hanzo","name":"mine","displayName":"renamed"}`); status != 200 {
		t.Fatalf("a display-name edit was refused: %d %s", status, body)
	}
	if k, err := orm.Get[schema.Key](h.db, "hanzo/mine"); err != nil || k.User != "hanzo/boss" || k.DisplayName != "renamed" {
		t.Fatalf("hanzo/mine = %+v, %v; want \"renamed\" held by hanzo/boss", k, err)
	}
	if status, body := h.send(t, boss, "PUT", "/v1/iam/keys/hanzo/mine", `{"owner":"hanzo","name":"mine","user":"alice"}`); status != 403 {
		t.Fatalf("a person repointed their key at alice: %d %s", status, body)
	}
	if k, err := orm.Get[schema.Key](h.db, "hanzo/mine"); err != nil || k.User != "hanzo/boss" {
		t.Fatalf("the refused repoint moved the key: %+v %v", k, err)
	}
}
