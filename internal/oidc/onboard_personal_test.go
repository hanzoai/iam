// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// NAMING AN ORG AND OWNING IT ARE TWO THINGS.
//
// Self-service onboarding read `personal` as "derive the slug from my username",
// which welded the two together: a caller who named their org got one marked as
// belonging to nobody in particular, and a caller who said the org was theirs got
// one called <username> whatever they typed. The service-token path never had that
// knot — it honours a given slug and derives one only when none was given — so the
// two surfaces disagreed about what the same word meant.
//
// One resolution, both surfaces: the name wins, the derivation is the fallback, and
// `personal` rides through independently and lands on the org row.

import (
	"context"
	"net/http"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/store"
)

// onboardBody posts an arbitrary onboarding body with the caller's session cookie,
// so a test can drive combinations onboardAs does not spell.
func onboardBody(t *testing.T, app *zip.App, cookie string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	req := jsonReq("POST", PathOnboard, body)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, raw := do(t, app, req)
	return resp, decode(t, raw)
}

// founder signs a seeded user in and returns their session cookie.
func founder(t *testing.T, app *zip.App, db orm.DB, org, user string) string {
	t.Helper()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, org, user)
	return portalSession(t, app, org, user)
}

// THE COMBINATION. A named org that is also the caller's own keeps the name and is
// marked personal — neither half overrides the other.
func TestOnboard_ANamedOrgCanAlsoBePersonal(t *testing.T) {
	app, db := newServer(t)
	cookie := founder(t, app, db, "hanzo", "alice")

	resp, env := onboardBody(t, app, cookie, map[string]any{"name": "Alice Labs", "personal": true})
	if resp.StatusCode != 200 {
		t.Fatalf("onboarding refused: status=%d body=%+v", resp.StatusCode, env)
	}
	if env["org"] != "alice-labs" {
		t.Fatalf("org = %v, want alice-labs — the name was overridden by the derivation", env["org"])
	}
	org, err := store.GetOrganizationByName(context.Background(), db, "alice-labs")
	if err != nil || org == nil {
		t.Fatalf("org row missing: %v", err)
	}
	if !org.IsPersonal {
		t.Error("org.IsPersonal = false — the org was named, so whose it is went unrecorded")
	}
	if org.DisplayName != "Alice Labs" {
		t.Errorf("displayName = %q, want %q", org.DisplayName, "Alice Labs")
	}
}

// The one-click path is unchanged: no name means the slug is derived from the
// caller's own username, and it is personal.
func TestOnboard_PersonalWithNoNameDerivesTheUsername(t *testing.T) {
	app, db := newServer(t)
	cookie := founder(t, app, db, "hanzo", "alice")

	resp, env := onboardBody(t, app, cookie, map[string]any{"personal": true})
	if resp.StatusCode != 200 {
		t.Fatalf("onboarding refused: status=%d body=%+v", resp.StatusCode, env)
	}
	if env["org"] != "alice" {
		t.Fatalf("org = %v, want alice", env["org"])
	}
	org, err := store.GetOrganizationByName(context.Background(), db, "alice")
	if err != nil || org == nil {
		t.Fatalf("org row missing: %v", err)
	}
	if !org.IsPersonal {
		t.Error("the one-click personal org is not marked personal")
	}
}

// And a named org with no claim on it stays shared.
func TestOnboard_ANamedOrgIsNotPersonalByDefault(t *testing.T) {
	app, db := newServer(t)
	cookie := founder(t, app, db, "hanzo", "alice")

	resp, env := onboardBody(t, app, cookie, map[string]any{"name": "Acme Corp"})
	if resp.StatusCode != 200 {
		t.Fatalf("onboarding refused: status=%d body=%+v", resp.StatusCode, env)
	}
	org, err := store.GetOrganizationByName(context.Background(), db, "acme-corp")
	if err != nil || org == nil {
		t.Fatalf("org row missing (env %+v): %v", env, err)
	}
	if org.IsPersonal {
		t.Error("a named org with no personal flag was marked personal")
	}
}
