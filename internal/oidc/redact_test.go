package oidc

import (
	"strings"
	"testing"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/users"
)

// TestUserReadNeverLeaksDigest: PasswordHash carries a real json tag (it must
// persist), so only redact() keeps it out of a response. If a read path ever
// skips redact, the digest ships to the client. Assert on the raw wire bytes.
func TestUserReadNeverLeaksDigest(t *testing.T) {
	app, _ := newFullServer(t)
	const pw = "leak-check-password"

	resp, body := do(t, app, jsonReq("POST", "/v1/iam/users", users.CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "leaky", Email: "leaky@hanzo.ai"},
		Password: pw,
	}))
	if resp.StatusCode != 200 {
		t.Fatalf("create: HTTP %d: %s", resp.StatusCode, body)
	}
	assertNoDigest(t, "create response", body)

	_, body = do(t, app, jsonReq("GET", "/v1/iam/users/get", map[string]string{"owner": "hanzo", "name": "leaky"}))
	assertNoDigest(t, "get response", body)

	_, body = do(t, app, jsonReq("GET", "/v1/iam/users", map[string]string{"owner": "hanzo"}))
	assertNoDigest(t, "list response", body)
}

func assertNoDigest(t *testing.T, where string, body []byte) {
	t.Helper()
	s := string(body)
	for _, marker := range []string{"$argon2id$", "$2a$", "$2b$", "passwordHash", "leak-check-password"} {
		if strings.Contains(s, marker) {
			t.Fatalf("%s leaked %q", where, marker)
		}
	}
}
