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

	// Positive controls: no cert is fine (mints nothing), and a tenant-owned non-kid
	// cert is fine (inert — GetSigningCert ignores non-reserved owners).
	seedCert(t, h.db, "hanzo", "cert-hanzo-local", rsaKeyToPEM(t, h.key))
	if got := h.do(t, "POST", "/v1/iam/application", boss, map[string]any{"owner": "hanzo", "name": "local-app", "clientId": "local-app", "cert": "cert-hanzo-local"}); got < 200 || got >= 300 {
		t.Fatalf("tenant app binding a tenant-owned non-kid cert = %d, want 2xx", got)
	}
}

// R1 (Red's decoy-collision PoC): an org-admin plants a cert under its OWN org named
// exactly like a platform signing kid (an allowed own-org cert write), then binds an
// app to that name. The gate resolves the name the way the SIGNER does
// (GetSigningCert over admin/built-in), so the platform kid is what governs — the
// decoy does not launder it. Fail-before: authorizeCert gated on own-org GetCert, so
// the decoy PASSED and the app would have signed with the platform key.
func TestApplicationCertDecoyCollisionRefused(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	// (1) Plant the decoy under the tenant's own org — signingKid is the admin-owned
	// JWKS kid; an own-org cert write of that NAME is legitimately allowed.
	if got := h.do(t, "POST", "/v1/iam/certs", boss, cert("hanzo", signingKid)); got < 200 || got >= 300 {
		t.Fatalf("planting an own-org decoy cert = %d, want 2xx (own-org cert write is allowed)", got)
	}
	// (2) Bind an app to that name → refused; the hanzo decoy does not change what
	// GetSigningCert(signingKid) resolves (still the admin platform cert).
	bind := map[string]any{"owner": "hanzo", "name": "decoy-app", "clientId": "decoy-app", "cert": signingKid}
	if got := h.do(t, "POST", "/v1/iam/application", boss, bind); got != http.StatusForbidden {
		t.Fatalf("tenant app binding a platform kid via a same-named decoy = %d, want 403", got)
	}
	if h.appExists(t, "hanzo", "decoy-app") {
		t.Fatal("a decoy-laundered platform-cert app PERSISTED — trust-anchor confusion is OPEN")
	}
}
