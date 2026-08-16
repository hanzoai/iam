// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

// PUT /v1/iam/account is the one self-service write on a user row, so the cases
// that matter are the ones about what it will NOT do: reach another account, and
// carry a privileged field in beside the four it is for.

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const (
	account   = "/v1/iam/account"
	inlinePNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
)

// save drives one profile write and returns the status and body VERBATIM.
func (r *rig) save(t *testing.T, sub, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("PUT", account, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.bearer(t, sub))
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("PUT %s: %v", account, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// row reads a user back out of the store, past the answer.
func (r *rig) row(t *testing.T, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), r.db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("read %s/%s back: %v", owner, name, err)
	}
	return u
}

// The four fields it is for.
func TestAccount_savesTheProfile(t *testing.T) {
	r := newRig(t)

	status, body := r.save(t, "hanzo/boss", `{"displayName":"The Boss","bio":"builds things","homepage":"https://example.com","avatar":"`+inlinePNG+`"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	u := r.row(t, "hanzo", "boss")
	if u.DisplayName != "The Boss" || u.Bio != "builds things" || u.Homepage != "https://example.com" {
		t.Fatalf("stored %q/%q/%q", u.DisplayName, u.Bio, u.Homepage)
	}
	if u.Avatar != inlinePNG {
		t.Fatalf("stored avatar %q", u.Avatar)
	}
}

// An omitted field KEEPS its value; an empty one CLEARS it. A screen that saves
// one control must not blank the three it did not render.
func TestAccount_omittedKeepsEmptyClears(t *testing.T) {
	r := newRig(t)

	if status, body := r.save(t, "hanzo/boss", `{"displayName":"The Boss","bio":"builds things"}`); status != 200 {
		t.Fatalf("first save: status=%d body=%s", status, body)
	}
	if status, body := r.save(t, "hanzo/boss", `{"displayName":"Boss"}`); status != 200 {
		t.Fatalf("second save: status=%d body=%s", status, body)
	}
	if u := r.row(t, "hanzo", "boss"); u.Bio != "builds things" {
		t.Fatalf("an omitted field was blanked: bio=%q", u.Bio)
	}
	if status, body := r.save(t, "hanzo/boss", `{"bio":""}`); status != 200 {
		t.Fatalf("clear: status=%d body=%s", status, body)
	}
	if u := r.row(t, "hanzo", "boss"); u.Bio != "" {
		t.Fatalf("an explicit empty did not clear: bio=%q", u.Bio)
	}
}

// NOTHING PRIVILEGED RIDES IN. Every one of these is a field somebody would try,
// and the body is the only place they could come from.
func TestAccount_privilegedFieldsCannotRideIn(t *testing.T) {
	r := newRig(t)
	// A REGULAR account, so "isAdmin":true below would be a real promotion. Run
	// against an admin the assertion proves nothing: the flag was already set.
	before := r.row(t, "hanzo", "nobody")
	if before.IsAdmin {
		t.Fatal("this case needs an account that is NOT an admin")
	}

	status, body := r.save(t, "hanzo/nobody", `{
		"displayName":"Nobody",
		"isAdmin":true,
		"owner":"admin",
		"name":"root",
		"passwordHash":"$2a$10$forged",
		"permissions":["*"],
		"email":"attacker@example.com",
		"phone":"+15550000000",
		"properties":{"preferences":"{\"training\":\"granted\"}"},
		"accessKey":"sk-forged",
		"score":99999
	}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200 — the extra keys are ignored, not fatal", status, body)
	}

	after := r.row(t, "hanzo", "nobody")
	if after.DisplayName != "Nobody" {
		t.Fatalf("the one real field did not save: %q", after.DisplayName)
	}
	for _, c := range []struct {
		field     string
		got, want any
	}{
		{"isAdmin", after.IsAdmin, before.IsAdmin},
		{"owner", after.Owner, before.Owner},
		{"name", after.Name, before.Name},
		{"passwordHash", after.PasswordHash, before.PasswordHash},
		{"email", after.Email, before.Email},
		{"phone", after.Phone, before.Phone},
		{"accessKey", after.AccessKey, before.AccessKey},
		{"score", after.Score, before.Score},
	} {
		if c.got != c.want {
			t.Fatalf("%s rode in: %v, want it untouched at %v", c.field, c.got, c.want)
		}
	}
	if len(after.Properties) != len(before.Properties) {
		t.Fatalf("properties rode in: %v — the consent record nests there", after.Properties)
	}
	// A promoted account is the one that would matter most.
	if after.IsAdmin {
		t.Fatal("the caller promoted themselves")
	}
}

// The account written is ALWAYS the caller's. There is no field to name another.
func TestAccount_writesOnlyTheCaller(t *testing.T) {
	r := newRig(t)

	if status, body := r.save(t, "hanzo/nobody", `{"displayName":"changed","owner":"hanzo","name":"boss"}`); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if u := r.row(t, "hanzo", "boss"); u.DisplayName == "changed" {
		t.Fatal("a caller wrote somebody else's profile by naming them")
	}
	if u := r.row(t, "hanzo", "nobody"); u.DisplayName != "changed" {
		t.Fatalf("the caller's own profile did not save: %q", u.DisplayName)
	}
}

// A picture this service will not store is a refusal, never a half-saved profile.
func TestAccount_refusesAPictureItWillNotStore(t *testing.T) {
	r := newRig(t)

	for _, c := range []struct{ name, avatar string }{
		{"a script url", "javascript:alert(1)"},
		{"an svg", "data:image/svg+xml;base64,PHN2Zz4="},
		{"http on a TLS page", "http://example.com/a.png"},
		{"over the limit", "data:image/png;base64," + strings.Repeat("A", schema.AvatarLimit)},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]string{"displayName": "Boss", "avatar": c.avatar})
			status, body := r.save(t, "hanzo/boss", string(b))
			if status == 200 {
				t.Fatalf("accepted %s: %s", c.name, body)
			}
			if u := r.row(t, "hanzo", "boss"); u.Avatar != "" || u.DisplayName == "Boss" {
				t.Fatalf("a refused write saved something: avatar=%q displayName=%q", u.Avatar, u.DisplayName)
			}
		})
	}
}

// No credential, no write.
func TestAccount_unauthenticated(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest("PUT", account, strings.NewReader(`{"displayName":"nobody"}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == 200 && !strings.Contains(string(b), "sign in") {
		t.Fatalf("an unauthenticated write was accepted: %s", b)
	}
	if u := r.row(t, "hanzo", "boss"); u.DisplayName == "nobody" {
		t.Fatal("an unauthenticated request wrote a profile")
	}
}

// The answer is the bounded projection, not the row: a secret cannot appear in
// it even by accident, because only six fields can.
func TestAccount_answerIsBounded(t *testing.T) {
	r := newRig(t)
	// Give the account something secret to leak.
	if _, err := orm.TypedQuery[schema.User](r.db).Filter("Owner=", "hanzo").Filter("Name=", "boss").First(); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	status, body := r.save(t, "hanzo/boss", `{"displayName":"Boss"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	for _, leak := range []string{"passwordHash", "accessSecret", "isAdmin", "properties", "permissions"} {
		if strings.Contains(body, leak) {
			t.Fatalf("the answer carried %s: %s", leak, body)
		}
	}
}
