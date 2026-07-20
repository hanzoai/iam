// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
)

// Unlink authorizes through the real internal/authz seam: the tests carry
// signed bearers and assert on the STORE, so "refused" means the column is
// still there, not merely that the response said no.

// linked seeds an account with a GitHub link.
func linked(t *testing.T, db orm.DB, name string) *schema.User {
	t.Helper()
	u := user(name, name+"@hanzo.ai", true)
	u.Github = "999"
	return seedUser(t, db, u)
}

func unlinkBody(owner, name string) map[string]any {
	return map[string]any{
		"providerType": "GitHub",
		"user":         map[string]string{"owner": owner, "name": name},
	}
}

func TestUnlinkSelf(t *testing.T) {
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{canSignIn: true, canUnlink: true})
	linked(t, db, "z")

	resp, body := postAs(t, app, "/v1/iam/unlink", "hanzo/z", unlinkBody("hanzo", "z"))
	if status(t, body) != "ok" {
		t.Fatalf("self-unlink refused: %d %s", resp.StatusCode, body)
	}
	if u := getUser(t, db, "hanzo", "z"); u.Github != "" {
		t.Fatalf("the link survived the unlink: %q", u.Github)
	}
}

func TestUnlinkSelfNeedsCanUnlink(t *testing.T) {
	// The application forbids it: a holder may not strand itself.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{canSignIn: true, canUnlink: false})
	linked(t, db, "z")

	_, body := postAs(t, app, "/v1/iam/unlink", "hanzo/z", unlinkBody("hanzo", "z"))
	if status(t, body) == "ok" {
		t.Fatalf("CanUnlink is off, yet the unlink succeeded: %s", body)
	}
	if u := getUser(t, db, "hanzo", "z"); u.Github != "999" {
		t.Fatalf("the link was cleared anyway: %q", u.Github)
	}
}

func TestUnlinkOther(t *testing.T) {
	// Only a SuperAdmin may unlink someone else. An ORG ADMIN may not: the
	// generic entity rule would let it (an org admin manages everything its org
	// owns), which is the wrong answer for someone else's sign-in method.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{canSignIn: true, canUnlink: true})
	linked(t, db, "z")

	orgAdmin := user("boss", "boss@hanzo.ai", true)
	orgAdmin.IsAdmin = true
	seedUser(t, db, orgAdmin)
	seedUser(t, db, user("nobody", "nobody@hanzo.ai", true))
	su := user("root", "root@hanzo.ai", true)
	su.Owner = "admin"
	seedUser(t, db, su)

	for _, who := range []string{"hanzo/nobody", "hanzo/boss"} {
		t.Run(who, func(t *testing.T) {
			_, body := postAs(t, app, "/v1/iam/unlink", who, unlinkBody("hanzo", "z"))
			if status(t, body) == "ok" {
				t.Fatalf("%s unlinked another account: %s", who, body)
			}
			if u := getUser(t, db, "hanzo", "z"); u.Github != "999" {
				t.Fatalf("%s cleared another account's link", who)
			}
		})
	}

	t.Run("admin/root", func(t *testing.T) {
		_, body := postAs(t, app, "/v1/iam/unlink", "admin/root", unlinkBody("hanzo", "z"))
		if status(t, body) != "ok" {
			t.Fatalf("a SuperAdmin was refused: %s", body)
		}
		if u := getUser(t, db, "hanzo", "z"); u.Github != "" {
			t.Fatalf("the link survived a SuperAdmin unlink: %q", u.Github)
		}
	})
}

func TestUnlinkNeedsABearer(t *testing.T) {
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{canSignIn: true, canUnlink: true})
	linked(t, db, "z")

	resp, _ := postJSON(t, app, "/v1/iam/unlink", unlinkBody("hanzo", "z"))
	if resp.StatusCode != 401 {
		t.Fatalf("want 401 without a bearer, got %d", resp.StatusCode)
	}
	if u := getUser(t, db, "hanzo", "z"); u.Github != "999" {
		t.Fatalf("an unauthenticated request cleared the link")
	}
}

func TestUnlinkRefusesUnknownProviderAndUnlinked(t *testing.T) {
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{canSignIn: true, canUnlink: true})
	linked(t, db, "z")
	seedUser(t, db, user("bare", "bare@hanzo.ai", true))

	// An unknown provider type is a hard miss — never a silent no-op, which is
	// what v1's reflection does for "GitLab".
	_, body := postAs(t, app, "/v1/iam/unlink", "hanzo/z", map[string]any{
		"providerType": "Wecom",
		"user":         map[string]string{"owner": "hanzo", "name": "z"},
	})
	if status(t, body) == "ok" {
		t.Fatalf("an unlinkable provider type reported success: %s", body)
	}
	if u := getUser(t, db, "hanzo", "z"); u.Github != "999" {
		t.Fatal("an unknown provider type cleared a different column")
	}

	// Nothing linked: say so rather than reporting a no-op as success.
	_, body = postAs(t, app, "/v1/iam/unlink", "hanzo/bare", unlinkBody("hanzo", "bare"))
	if status(t, body) == "ok" {
		t.Fatalf("unlinking an unlinked account reported success: %s", body)
	}
}

func TestUnlinkGitlab(t *testing.T) {
	// v1 reads the GitLab column by reflecting the type "GitLab" onto the field
	// `Gitlab`, gets "<invalid Value>" back, compares it to "" and carries on —
	// then clears nothing. The whole endpoint silently no-ops for GitLab.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{kind: "GitLab", canSignIn: true, canUnlink: true})
	u := user("z", "z@hanzo.ai", true)
	u.Gitlab = "42"
	seedUser(t, db, u)

	_, body := postAs(t, app, "/v1/iam/unlink", "hanzo/z", map[string]any{
		"providerType": "GitLab",
		"user":         map[string]string{"owner": "hanzo", "name": "z"},
	})
	if status(t, body) != "ok" {
		t.Fatalf("GitLab unlink refused: %s", body)
	}
	if got := getUser(t, db, "hanzo", "z"); got.Gitlab != "" {
		t.Fatalf("the GitLab link survived: %q", got.Gitlab)
	}
}

func TestNoSecretCrossesTheWire(t *testing.T) {
	// A provider's client secret is read server-side only. It must not appear on
	// the pre-login app config, nor anywhere the callback answers with.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")

	_, cfg := get(t, app, "/v1/iam/get-app-login?clientId=console-client")
	if !strings.Contains(string(cfg), "provider-github") {
		t.Fatalf("get-app-login renders no provider button: %s", cfg)
	}
	resp, land := signin(t, app, "provider-github")
	for _, tc := range []struct {
		where string
		body  []byte
	}{{"get-app-login", cfg}, {"callback", land}, {"callback location", []byte(resp.Header.Get("Location"))}} {
		for _, secret := range []string{"client-secret", "console-secret"} {
			if strings.Contains(string(tc.body), secret) {
				t.Fatalf("%s leaked %q: %s", tc.where, secret, tc.body)
			}
		}
	}
	_ = db
}

// status reads the envelope's status field — the SDK branches on it, not on the
// HTTP code.
func status(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	s, _ := m["status"].(string)
	return s
}
