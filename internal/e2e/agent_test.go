// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package e2e_test

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// TestJourney_AgentRegistration is WorkOS auth.md's service_auth flow through the
// whole router, Guard included: discover, register, a person approves on the
// device page, the agent claims and exchanges, and the person revokes it by
// deleting its service account on the service-account surface.
func TestJourney_AgentRegistration(t *testing.T) {
	e := boot(t)
	t.Setenv("IAM_AGENT_SKILL_MAP", `{"hanzo.id":"https://hanzo.ai/auth.md"}`)
	t.Setenv("IAM_AGENT_CLIENT", "hanzo-agents")
	ctx := context.Background()

	// The application agents register through, as provision declares it.
	a := orm.New[schema.Application](e.db)
	a.Owner, a.Name, a.ClientId, a.Organization, a.Cert = "admin", "hanzo-agents", "hanzo-agents", "hanzo", kid
	a.GrantTypes = []string{"urn:workos:agent-auth:grant-type:claim"}
	a.ExpireInHours = 1
	a.SetId("admin/hanzo-agents")
	if err := a.CreateCtx(ctx); err != nil {
		t.Fatalf("seed agent app: %v", err)
	}
	// The person: the admin of acme, whose address is proven.
	seedOrg(t, e.db, "acme")
	ada := orm.New[schema.User](e.db)
	ada.Owner, ada.Name, ada.Email, ada.EmailVerified, ada.IsAdmin = "acme", "ada", "ada@acme.test", true, true
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	ada.PasswordHash, ada.PasswordType = string(hash), "bcrypt"
	ada.SetId("acme/ada")
	if err := ada.CreateCtx(ctx); err != nil {
		t.Fatalf("seed ada: %v", err)
	}

	// 1. Discover.
	meta := e.getJSON(t, "/.well-known/oauth-authorization-server", "")
	block, _ := meta["agent_auth"].(map[string]any)
	if block["identity_endpoint"] != "https://hanzo.id/v1/iam/oauth/agent/identity" || block["skill"] != "https://hanzo.ai/auth.md" {
		t.Fatalf("agent_auth = %v", meta["agent_auth"])
	}

	// 2. Register, with no credential.
	st, body := e.req(t, "POST", "/v1/iam/oauth/agent/identity", "", `{"type":"service_auth","login_hint":"Ada@acme.test"}`, "application/json")
	if st != 200 {
		t.Fatalf("register: %d %s", st, body)
	}
	var reg struct {
		RegistrationId string `json:"registration_id"`
		ClaimToken     string `json:"claim_token"`
		Claim          struct {
			UserCode string `json:"user_code"`
		} `json:"claim"`
	}
	if err := json.Unmarshal([]byte(body), &reg); err != nil || reg.ClaimToken == "" || reg.Claim.UserCode == "" {
		t.Fatalf("registration = %s (%v)", body, err)
	}
	claim := url.Values{"grant_type": {"urn:workos:agent-auth:grant-type:claim"}, "claim_token": {reg.ClaimToken}}
	if m := e.token(t, claim); m["error"] != "authorization_pending" {
		t.Fatalf("before approval: %v", m)
	}

	// 3. The person approves on the device page.
	approve, _ := json.Marshal(map[string]string{
		"type": "device", "organization": "acme", "username": "ada", "password": "pw", "userCode": reg.Claim.UserCode,
	})
	if st, body := e.req(t, "POST", "/v1/iam/login", "", string(approve), "application/json"); st != 200 {
		t.Fatalf("approve: %d %s", st, body)
	}

	// 4. The agent claims: one service account in acme, its token, and the assertion.
	tok := e.token(t, claim)
	access, _ := tok["access_token"].(string)
	assertion, _ := tok["identity_assertion"].(string)
	if access == "" || assertion == "" || tok["refresh_token"] != nil {
		t.Fatalf("claim = %v", tok)
	}
	adaBearer := e.mint(t, "acme/ada")
	list := e.getJSON(t, "/v1/iam/service-accounts?organization=acme", adaBearer)
	rows, _ := list["data"].([]any)
	if len(rows) != 1 {
		t.Fatalf("acme's service accounts = %v", list)
	}
	sa, _ := rows[0].(map[string]any)
	name, _ := sa["name"].(string)
	if sa["tag"] != reg.RegistrationId {
		t.Fatalf("service account = %v, want tag %s", sa, reg.RegistrationId)
	}

	// The agent's token is a bearer the Guard admits as that account.
	if acct := e.getJSON(t, "/v1/iam/account", access); acct["status"] != "ok" {
		t.Fatalf("the agent's token is refused: %v", acct)
	}

	// 5. The assertion exchanges for a fresh token.
	exchange := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	if m := e.token(t, exchange); m["access_token"] == nil {
		t.Fatalf("exchange: %v", m)
	}

	// 6. The person revokes the agent by deleting its account; the assertion is dead.
	st, body = e.req(t, "DELETE", "/v1/iam/service-accounts/"+name+"?organization=acme", adaBearer, "", "")
	if st != 200 {
		t.Fatalf("delete %s: %d %s", name, st, body)
	}
	if m := e.token(t, exchange); m["error"] != "invalid_grant" || m["access_token"] != nil {
		t.Fatalf("exchange after revocation: %v", m)
	}
}
