// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// F1 (half 2) — the cert-poisoning half, proven closed at the REST seam. The Cert
// an application names is the key IAM signs that app's tokens with (oidc.signerFor
// -> store.GetSigningCert, trusted ONLY under admin/built-in). applications.Create/
// Update bound Cert verbatim, so an org admin could register an app in its OWN org
// naming a PLATFORM signing cert and have IAM mint platform-signed tokens through
// it. The binding is now scoped to the app's own org.

import (
	"context"
	"net/http"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

// appExists reports whether an application row (owner, name) is persisted.
func (h *harness) appExists(t *testing.T, owner, name string) bool {
	t.Helper()
	a, err := store.GetApplicationByName(context.Background(), h.db, owner, name)
	if err != nil {
		t.Fatalf("lookup app %s/%s: %v", owner, name, err)
	}
	return a != nil
}

// An org admin registering an app in its OWN org may NOT bind a platform (admin/
// built-in) signing cert. signingKid is the seeded admin-owned signing cert.
// Fail-before: the app persisted with cert=cert-hanzo. Create AND update are
// covered, and the positive controls prove the gate refuses by SCOPE, not blanket.
func TestApplicationCertBindingIsScoped(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	// Create: a tenant app naming the platform signing cert → 403, nothing persists.
	poison := map[string]any{"owner": "hanzo", "name": "poison-app", "clientId": "poison-app", "cert": signingKid}
	if got := h.do(t, "POST", "/v1/iam/application", boss, poison); got != http.StatusForbidden {
		t.Fatalf("tenant app binding platform cert %q = %d, want 403", signingKid, got)
	}
	if h.appExists(t, "hanzo", "poison-app") {
		t.Fatal("a tenant app bound to the PLATFORM signing cert PERSISTED — cert poisoning is OPEN")
	}

	// Update: seed a plain (certless) tenant app, then try to re-point it at the platform cert → 403.
	if got := h.do(t, "POST", "/v1/iam/application", boss, map[string]any{"owner": "hanzo", "name": "plain-app", "clientId": "plain-app"}); got < 200 || got >= 300 {
		t.Fatalf("seed a certless tenant app = %d, want 2xx", got)
	}
	if got := h.do(t, "PUT", "/v1/iam/application", boss, map[string]any{"owner": "hanzo", "name": "plain-app", "clientId": "plain-app", "cert": signingKid}); got != http.StatusForbidden {
		t.Fatalf("tenant app UPDATE binding platform cert = %d, want 403", got)
	}

	// Positive controls: no cert is fine (mints nothing), and a SAME-ORG cert is fine.
	seedCert(t, h.db, "hanzo", "cert-hanzo-local", rsaKeyToPEM(t, h.key))
	if got := h.do(t, "POST", "/v1/iam/application", boss, map[string]any{"owner": "hanzo", "name": "local-app", "clientId": "local-app", "cert": "cert-hanzo-local"}); got < 200 || got >= 300 {
		t.Fatalf("tenant app binding a SAME-ORG cert = %d, want 2xx", got)
	}
}
