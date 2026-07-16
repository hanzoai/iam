// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "testing"

// The Mask methods are the ONE redaction contract for every read path (entity
// CRUD, compat aliases, get-account). These tests are the security assertion:
// (1) every secret field is stripped from the returned value, and (2) the
// RECEIVER is never mutated — Mask returns a copy, so masking a row for a
// response can never blank the secret in a row another caller (the login verify
// path) still holds.

func TestUserMask_stripsEverySecret_andCopiesReceiver(t *testing.T) {
	u := &User{
		PasswordHash:         "$argon2id$v=19$m=65536,t=1,p=2$abc$def",
		PasswordSalt:         "salt",
		PasswordType:         "argon2id",
		AccessSecret:         "acc-secret",
		AccessSecretHash:     "acc-secret-hash",
		AccessToken:          "acc-token",
		OriginalToken:        "orig-token",
		OriginalRefreshToken: "orig-refresh",
		TotpSecret:           "totp",
		RecoveryCodes:        []string{"r1", "r2"},
		VerificationCode:     "123456",
	}
	u.Owner, u.Name = "acme", "bob"
	u.Email = "bob@acme.test"

	m := u.Mask()

	// (1) no secret survives on the masked copy.
	for label, got := range map[string]string{
		"PasswordHash":         m.PasswordHash,
		"PasswordSalt":         m.PasswordSalt,
		"AccessSecret":         m.AccessSecret,
		"AccessSecretHash":     m.AccessSecretHash,
		"AccessToken":          m.AccessToken,
		"OriginalToken":        m.OriginalToken,
		"OriginalRefreshToken": m.OriginalRefreshToken,
		"TotpSecret":           m.TotpSecret,
		"VerificationCode":     m.VerificationCode,
	} {
		if got != "" {
			t.Errorf("User.Mask left %s = %q, want empty", label, got)
		}
	}
	if m.RecoveryCodes != nil {
		t.Errorf("User.Mask left RecoveryCodes = %v, want nil", m.RecoveryCodes)
	}
	// non-secret identity is preserved for the UI.
	if m.Owner != "acme" || m.Name != "bob" || m.Email != "bob@acme.test" {
		t.Errorf("User.Mask dropped identity: owner=%q name=%q email=%q", m.Owner, m.Name, m.Email)
	}

	// (2) the receiver still carries its secret — Mask copied, never mutated.
	if u.PasswordHash == "" || u.AccessToken == "" || u.RecoveryCodes == nil {
		t.Fatal("User.Mask MUTATED the receiver — a response mask would blank the live login row")
	}
}

func TestOrganizationMask_sentinelsSecrets_andCopiesReceiver(t *testing.T) {
	o := &Organization{
		PasswordSalt:           "salt",
		PasswordObfuscatorKey:  "obf-key",
		MasterPassword:         "master-pw",
		DefaultPassword:        "default-pw",
		MasterVerificationCode: "mvc",
		KerberosKeytab:         "keytab",
	}
	o.Owner, o.Name = "admin", "acme"

	m := o.Mask()

	// v1 uses the "***" sentinel (a set-but-hidden marker), not "".
	for label, got := range map[string]string{
		"PasswordSalt":           m.PasswordSalt,
		"PasswordObfuscatorKey":  m.PasswordObfuscatorKey,
		"MasterPassword":         m.MasterPassword,
		"DefaultPassword":        m.DefaultPassword,
		"MasterVerificationCode": m.MasterVerificationCode,
		"KerberosKeytab":         m.KerberosKeytab,
	} {
		if got != "***" {
			t.Errorf("Organization.Mask left %s = %q, want \"***\"", label, got)
		}
	}
	if m.Name != "acme" {
		t.Errorf("Organization.Mask dropped name: %q", m.Name)
	}
	if o.MasterPassword != "master-pw" {
		t.Fatal("Organization.Mask MUTATED the receiver")
	}
}

func TestApplicationMask_stripsClientSecret_andEveryEnrichedJoin(t *testing.T) {
	a := &Application{
		ClientSecret:    "app-client-secret",
		ClientId:        "acme-console",
		CertObj:         &Cert{PrivateKey: "-----BEGIN PRIVATE KEY-----", AccessSecret: "acme-dns"},
		OrganizationObj: &Organization{MasterPassword: "org-master-pw"},
		Providers: []*ProviderItem{{
			Name:     "provider-github",
			Provider: &Provider{ClientSecret: "prov-cs", ClientSecret2: "prov-cs2"},
		}},
	}
	a.Owner, a.Name = "acme", "console"

	m := a.Mask()

	if m.ClientSecret != "" {
		t.Errorf("Application.Mask left ClientSecret = %q", m.ClientSecret)
	}
	if m.ClientId != "acme-console" {
		t.Errorf("Application.Mask dropped ClientId: %q", m.ClientId)
	}
	// Every in-memory join carries its own secret; all must be masked through.
	if m.CertObj == nil || m.CertObj.PrivateKey != "" || m.CertObj.AccessSecret != "" {
		t.Errorf("Application.Mask left a secret in the nested CertObj: %+v", m.CertObj)
	}
	if m.OrganizationObj == nil || m.OrganizationObj.MasterPassword != "***" {
		t.Errorf("Application.Mask left a secret in OrganizationObj: %+v", m.OrganizationObj)
	}
	if m.Providers[0].Provider == nil ||
		m.Providers[0].Provider.ClientSecret != "" || m.Providers[0].Provider.ClientSecret2 != "" {
		t.Errorf("Application.Mask left a secret in Providers[].Provider: %+v", m.Providers[0].Provider)
	}

	// The receiver — and its SHARED ProviderItem/join backing — must be untouched.
	if a.ClientSecret != "app-client-secret" || a.CertObj.PrivateKey == "" {
		t.Fatal("Application.Mask MUTATED the receiver (or its shared CertObj)")
	}
	if a.OrganizationObj.MasterPassword != "org-master-pw" {
		t.Fatal("Application.Mask MUTATED the receiver's OrganizationObj")
	}
	if a.Providers[0].Provider.ClientSecret != "prov-cs" {
		t.Fatal("Application.Mask MUTATED the receiver's shared Providers[].Provider")
	}
}

func TestProviderMask_stripsBothClientSecrets(t *testing.T) {
	p := &Provider{ClientSecret: "cs1", ClientSecret2: "cs2", Type: "GitHub"}
	p.Owner, p.Name = "admin", "provider-github"

	m := p.Mask()

	if m.ClientSecret != "" || m.ClientSecret2 != "" {
		t.Errorf("Provider.Mask left a secret: cs=%q cs2=%q", m.ClientSecret, m.ClientSecret2)
	}
	if m.Type != "GitHub" {
		t.Errorf("Provider.Mask dropped Type: %q", m.Type)
	}
	if p.ClientSecret != "cs1" {
		t.Fatal("Provider.Mask MUTATED the receiver")
	}
}

func TestMask_nilReceiverIsNil(t *testing.T) {
	var u *User
	var o *Organization
	var a *Application
	var p *Provider
	if u.Mask() != nil || o.Mask() != nil || a.Mask() != nil || p.Mask() != nil {
		t.Fatal("Mask on a nil receiver must return nil")
	}
}
