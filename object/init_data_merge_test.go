// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import "testing"

func hasCol(cols []string, want string) bool {
	for _, c := range cols {
		if c == want {
			return true
		}
	}
	return false
}

// An inline PEM is exactly the drift that broke OAuth callbacks: consumers call
// GetOwnerAndNameFromId(org + "/" + cert) and a PEM's slashes/newlines blow the
// "owner/name" token count, so the signing cert never loads.
const driftPEM = `-----BEGIN CERTIFICATE-----
MIIBszre/cTak3enTokenCountWillBeWrong+slashes//and+newlines
abc/def/ghi/jkl
-----END CERTIFICATE-----`

// TestReconcileCertHealsDrift is the regression guard for the console/builder
// login bug: the application.cert field must reconcile to the declared cert
// NAME (a reference), and an inline-PEM value MUST self-heal on a universe
// redeploy instead of being skipped by the old fill-if-empty guard.
func TestReconcileCertHealsDrift(t *testing.T) {
	cases := []struct {
		name        string
		existing    string
		desired     string
		wantCert    string
		wantCertCol bool
	}{
		{"empty heals to name", "", "cert-hanzo", "cert-hanzo", true},
		{"inline PEM heals to name", driftPEM, "cert-hanzo", "cert-hanzo", true},
		{"stale name reconciles to desired", "cert-old", "cert-hanzo", "cert-hanzo", true},
		{"correct name is untouched", "cert-hanzo", "cert-hanzo", "cert-hanzo", false},
		{"desired empty leaves existing", "cert-hanzo", "", "cert-hanzo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			existing := &Application{Owner: "admin", Name: "hanzo-cloud", Cert: tc.existing}
			desired := &Application{Owner: "admin", Name: "hanzo-cloud", Cert: tc.desired}

			cols := reconcileApplicationOAuthDefaults(existing, desired)

			if existing.Cert != tc.wantCert {
				t.Fatalf("cert = %q, want %q", existing.Cert, tc.wantCert)
			}
			if got := hasCol(cols, "cert"); got != tc.wantCertCol {
				t.Fatalf("cert in updateCols = %v, want %v (cols=%v)", got, tc.wantCertCol, cols)
			}
		})
	}
}

// TestReconcileNoSpuriousColumns: identical apps produce no update columns (the
// reconcile must be idempotent so a redeploy doesn't rewrite unchanged rows).
func TestReconcileNoSpuriousColumns(t *testing.T) {
	app := func() *Application {
		return &Application{
			Owner: "admin", Name: "hanzo-cloud", Cert: "cert-hanzo",
			RedirectUris: []string{"https://console2.hanzo.ai/auth/callback"},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
		}
	}
	cols := reconcileApplicationOAuthDefaults(app(), app())
	if len(cols) != 0 {
		t.Fatalf("expected no update columns for identical apps, got %v", cols)
	}
}

// TestGetMaskedApplicationKeepsCertName is the read-path regression guard. The
// masked get-application response (the SDK contract surface) MUST keep the cert
// NAME (a public reference consumers resolve via GetCert) and MUST NOT mask it
// to "***" or stuff the inline PEM — either breaks cloud-api's OAuth callback
// (password + GitHub + Google). R-1 is preserved: clientSecret stays masked.
func TestGetMaskedApplicationKeepsCertName(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nMIIBpublic\n-----END CERTIFICATE-----"
	app := &Application{
		Owner: "admin", Name: "hanzo-cloud",
		Cert: "cert-hanzo", ClientSecret: "super-secret", CertPublicKey: pem,
	}
	// userId == "" → anonymous → the masked path (no DB user lookup).
	masked := GetMaskedApplication(app, "")

	if masked.ClientSecret != "***" {
		t.Fatalf("R-1 regression: clientSecret must be masked, got %q", masked.ClientSecret)
	}
	if masked.Cert != "cert-hanzo" {
		t.Fatalf("cert must stay the public NAME reference, got %q", masked.Cert)
	}
	if masked.CertPublicKey != pem {
		t.Fatalf("certPublicKey (public PEM for SPAs) must remain, got %q", masked.CertPublicKey)
	}
}
