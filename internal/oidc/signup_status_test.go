package oidc

// A refused signup answered HTTP 200 carrying {"status":"error"}. Every SDK that
// checks the transport first — `res.ok` in fetch, `resp.StatusCode/100 == 2` in Go,
// `raise_for_status()` in Python — read that as a completed signup, so the failure
// presented as success and the caller went on to the next step of an onboarding
// that had not happened.
//
// The envelope is NOT the thing to change: `status`, `msg` and `code` are the
// contract the @hanzo/iam SDK and the portal branch on, and they stay byte for
// byte. What changes is the number in front of it, which is the one part that was
// never true.

import (
	"net/http"
	"testing"
)

// TestSignup_FailureIsNotSuccess drives every distinct way the endpoint refuses
// a signup and holds ONE line: none of them may answer 2xx.
func TestSignup_FailureIsNotSuccess(t *testing.T) {
	newbieBody := func() map[string]string {
		return map[string]string{
			"application": "conf", "organization": "hanzo",
			"username": "newbie", "password": "correct horse battery staple",
		}
	}

	cases := []struct {
		name string
		run  func(t *testing.T) (int, map[string]any)
	}{
		{"missing required fields", func(t *testing.T) (int, map[string]any) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
			seedOrg(t, db, "hanzo")
			return signupReq(t, app, map[string]string{"application": "conf", "organization": "hanzo"})
		}},
		{"application does not exist", func(t *testing.T) (int, map[string]any) {
			app, db := newServer(t)
			seedOrg(t, db, "hanzo")
			b := newbieBody()
			b["application"] = "ghost"
			return signupReq(t, app, b)
		}},
		{"signup disabled", func(t *testing.T) (int, map[string]any) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: false})
			seedOrg(t, db, "hanzo")
			return signupReq(t, app, newbieBody())
		}},
		{"organization does not exist", func(t *testing.T) (int, map[string]any) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
			return signupReq(t, app, newbieBody())
		}},
		{"username already taken", func(t *testing.T) (int, map[string]any) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
			seedOrg(t, db, "hanzo")
			seedUser(t, db, "newbie", "newbie@hanzo.ai", "pw")
			return signupReq(t, app, newbieBody())
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, env := tc.run(t)
			if status >= 200 && status < 300 {
				t.Fatalf("a refused signup answered %d — an SDK checking the transport reads that as success (env %v)", status, env)
			}
			if status < 400 || status > 499 {
				t.Fatalf("status = %d, want a 4xx: the caller's request was refused, not our fault (env %v)", status, env)
			}
			// The envelope is unchanged — this is a status fix, not a contract break.
			if env["status"] != "error" {
				t.Fatalf(`env["status"] = %v, want "error" (the SDK contract must survive)`, env["status"])
			}
			if msg, _ := env["msg"].(string); msg == "" {
				t.Fatalf("a refusal must still say why: %v", env)
			}
		})
	}
}

// TestSignup_SuccessIsStill200 is the other half: the fix must not move the happy
// path. A created account answers 200 with the same envelope it always did.
func TestSignup_SuccessIsStill200(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "hanzo",
		"username": "newbie", "password": "correct horse battery staple",
	})
	if status != http.StatusOK {
		t.Fatalf("a successful signup answered %d, want 200 (env %v)", status, env)
	}
	if env["status"] != "ok" {
		t.Fatalf(`env["status"] = %v, want "ok"`, env["status"])
	}
}
