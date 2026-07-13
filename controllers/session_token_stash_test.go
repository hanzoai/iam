// Copyright © 2026 Hanzo AI. MIT License.

package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	beecontext "github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/beego/v2/server/web/session"
	"github.com/hanzoai/iam/object"
)

// freshSessionStore returns a real (empty) Beego in-memory session store — the
// same Store type a live request carries — so the stash is exercised against
// genuine session machinery, not a mock.
func freshSessionStore(t *testing.T, sid string) session.Store {
	t.Helper()
	mgr, err := session.NewManager("memory", &session.ManagerConfig{
		CookieName: "iam_session_id",
		Gclifetime: 3600,
	})
	if err != nil {
		t.Fatalf("session.NewManager(memory): %v", err)
	}
	store, err := mgr.GetSessionStore(sid)
	if err != nil {
		t.Fatalf("GetSessionStore(%q): %v", sid, err)
	}
	return store
}

// newStashController builds the minimum real ApiController the stash needs: a
// Beego context whose Request.Host feeds getEffectiveHost, plus a live session
// store as the current session.
func newStashController(t *testing.T, store session.Store) *ApiController {
	t.Helper()
	c := &ApiController{}
	ctx := beecontext.NewContext()
	ctx.Reset(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "https://console.hanzo.ai/v1/iam/login", nil))
	c.Ctx = ctx
	c.CruSession = store
	return c
}

func readSessionAccessToken(t *testing.T, store session.Store) string {
	t.Helper()
	v := store.Get(context.Background(), "accessToken")
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("session accessToken is not a string: %T", v)
	}
	return s
}

// TestStashSessionAccessToken_StashesLoginAppToken is the regression that pins
// the fix: after a login establishes the session, the session carries a
// NON-EMPTY "accessToken" JWT — the value the cloud-embed cookie→principal
// bridge (hanzoai/cloud middleware_identity.sessionAccessToken) reads to resolve
// a same-origin money call. Before the fix nothing wrote it (the sole writer,
// routers/timeout_filter, sets it to ""), so the bridge always saw "".
//
// It also proves the CRUX of the audience fix: the token is minted for the LOGIN
// application (aud = application.ClientId, e.g. hanzo-cloud — in the cloud
// audience allowlist), NOT the user's default app.
func TestStashSessionAccessToken_StashesLoginAppToken(t *testing.T) {
	const fakeJWT = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJoYW56by1jbG91ZCJ9.sig"

	var gotApp *object.Application
	var gotUser *object.User
	var gotHost string
	orig := sessionTokenMinter
	t.Cleanup(func() { sessionTokenMinter = orig })
	sessionTokenMinter = func(app *object.Application, user *object.User, host string) (string, error) {
		gotApp, gotUser, gotHost = app, user, host
		return fakeJWT, nil
	}

	store := freshSessionStore(t, "stash-happy-sid")
	if pre := readSessionAccessToken(t, store); pre != "" {
		t.Fatalf("precondition: session accessToken must start empty, got %q", pre)
	}

	c := newStashController(t, store)
	loginApp := &object.Application{Owner: "admin", Name: "hanzo-cloud", ClientId: "hanzo-cloud"}
	user := &object.User{Owner: "hanzo", Name: "z"}

	c.stashSessionAccessToken(loginApp, user)

	got := readSessionAccessToken(t, store)
	if got == "" {
		t.Fatal("expected a NON-EMPTY accessToken stashed in the session (the cloud-embed bridge reads it); got empty")
	}
	if got != fakeJWT {
		t.Fatalf("stashed token = %q, want %q", got, fakeJWT)
	}
	if gotApp != loginApp {
		t.Fatalf("minter must receive the LOGIN application (aud=%q), not the user's default app; got %+v",
			loginApp.ClientId, gotApp)
	}
	if gotUser != user {
		t.Fatalf("minter must mint for the authenticated session user; got %+v", gotUser)
	}
	if gotHost != "console.hanzo.ai" {
		t.Fatalf("minter host = %q, want the request host console.hanzo.ai", gotHost)
	}
}

// TestStashSessionAccessToken_SafeNoops proves the stash never writes an empty
// or bogus "accessToken" and never blocks the login: a nil app/user, a mint
// error, and an empty mint all leave the session untouched (no panic, no
// overwrite) — the login proceeds on the username alone.
func TestStashSessionAccessToken_SafeNoops(t *testing.T) {
	orig := sessionTokenMinter
	t.Cleanup(func() { sessionTokenMinter = orig })

	loginApp := &object.Application{Owner: "admin", Name: "hanzo-cloud", ClientId: "hanzo-cloud"}
	user := &object.User{Owner: "hanzo", Name: "z"}

	cases := []struct {
		name   string
		app    *object.Application
		user   *object.User
		minter func(*object.Application, *object.User, string) (string, error)
	}{
		{
			name:   "nil application",
			app:    nil,
			user:   user,
			minter: func(*object.Application, *object.User, string) (string, error) { return "should.not.mint", nil },
		},
		{
			name:   "nil user",
			app:    loginApp,
			user:   nil,
			minter: func(*object.Application, *object.User, string) (string, error) { return "should.not.mint", nil },
		},
		{
			name: "mint error",
			app:  loginApp,
			user: user,
			minter: func(*object.Application, *object.User, string) (string, error) {
				return "", errors.New("no signing cert")
			},
		},
		{
			name:   "empty mint, no error",
			app:    loginApp,
			user:   user,
			minter: func(*object.Application, *object.User, string) (string, error) { return "", nil },
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionTokenMinter = tc.minter
			store := freshSessionStore(t, "stash-noop-sid-"+string(rune('a'+i)))
			c := newStashController(t, store)

			c.stashSessionAccessToken(tc.app, tc.user)

			if got := readSessionAccessToken(t, store); got != "" {
				t.Fatalf("expected session accessToken to stay empty, got %q", got)
			}
		})
	}
}
