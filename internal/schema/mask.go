// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

// Redaction is a property of the value, not of any handler: an entity knows its
// own secrets. Every read path — the entity CRUD, the Casdoor compat aliases,
// get-account — returns `x.Mask()`, never `x`, so no digest, client secret, or
// bearer material ever leaves the service. Masking is the ONE way secrets are
// stripped; there is no second copy of this logic in any handler package.
//
// Mask returns a masked COPY and never mutates the receiver. orm reads unmarshal
// into fresh instances (orm ModelQuery.First: "a new instance"), so the receiver
// is already private to the caller — but returning a copy keeps Mask a pure
// function of the value, safe to call on any entity a caller intends to keep
// using. Only fields with a real json tag can reach a response; nested secret
// fields tagged `json:"-"` are never serialized (and, since orm persists via
// json.Marshal, never even stored), so a shallow copy with the top-level secrets
// blanked is sufficient and leak-free.
//
// Cert.Mask lives beside the Cert type in cert.go (the original of this pattern);
// the other four entities that carry secrets are gathered here.

// Mask returns a copy of u with every response-serialized credential and bearer
// field blanked. Mirrors v1's read-path redaction (object/user.go), fail-safe.
func (u *User) Mask() *User {
	if u == nil {
		return nil
	}
	m := *u
	m.PasswordHash, m.PasswordSalt = "", ""
	m.AccessSecret, m.AccessSecretHash, m.AccessToken = "", "", ""
	m.OriginalToken, m.OriginalRefreshToken = "", ""
	m.TotpSecret, m.RecoveryCodes = "", nil
	m.VerificationCode = "" // a live one-time code — as secret as the TOTP seed
	return &m
}

// Mask returns a copy of k with the CONFIDENTIAL half blanked and the
// PUBLISHABLE half intact — the split that is the whole point of the key model.
// AccessSecret (sk-) authenticates its holder as a principal, so a listing must
// never carry it; AccessKey (pk-) is publishable by construction (it is shipped
// in client JS and resolves to an org, never a principal), so blanking it would
// hide from a holder the one value they need to use the key.
//
// Every read path returns k.Mask(). Without it a key LIST handed the reader every
// secret in the org, and the read authorization ("who may list keys") was doing
// the work redaction should do — so widening who may read a key list was
// unsafe by construction. Masking is what makes the read safe on its own.
func (k *Key) Mask() *Key {
	if k == nil {
		return nil
	}
	m := *k
	m.AccessSecret = ""
	return &m
}

// Mask returns a copy of o with every secret blanked to the "***" sentinel v1
// uses (object/organization.go GetMaskedOrganization) — "***" signals "a value
// is set but hidden", distinct from "" ("no value"), which some UIs rely on.
func (o *Organization) Mask() *Organization {
	if o == nil {
		return nil
	}
	m := *o
	for _, secret := range []*string{
		&m.MasterPassword,
		&m.DefaultPassword,
		&m.MasterVerificationCode,
		&m.PasswordSalt,
		&m.PasswordObfuscatorKey,
		&m.KerberosKeytab,
	} {
		if *secret != "" {
			*secret = "***"
		}
	}
	return &m
}

// Mask returns a copy of a with the OAuth client secret blanked and every
// in-memory join (orm:"-", but carrying real json tags) masked THROUGH — an
// enriched read (get-app-login populates Providers[].Provider via
// store.EnrichProviders; other paths attach CertObj/OrganizationObj) otherwise
// carries a linked entity's own secret (a provider's clientSecret, a cert's
// private key, an org's master password) straight past the top-level mask. Each
// join is copied before it is masked so the receiver's shared slice/pointer is
// never mutated.
func (a *Application) Mask() *Application {
	if a == nil {
		return nil
	}
	m := *a
	m.ClientSecret = ""
	if m.CertObj != nil {
		m.CertObj = m.CertObj.Mask()
	}
	if m.OrganizationObj != nil {
		m.OrganizationObj = m.OrganizationObj.Mask()
	}
	if len(m.Providers) > 0 {
		// The shallow copy shares the []*ProviderItem backing array with the
		// receiver; rebuild it with masked copies so blanking the nested provider
		// secret cannot reach back into the original row.
		items := make([]*ProviderItem, len(m.Providers))
		for i, it := range m.Providers {
			if it == nil {
				continue
			}
			clone := *it
			clone.Provider = it.Provider.Mask() // nil-safe; blanks clientSecret(2)
			items[i] = &clone
		}
		m.Providers = items
	}
	return &m
}

// Mask returns a copy of p with both OAuth client secrets blanked — the fields
// v1 masks (object/provider.go GetMaskedProvider). Content is left intact to
// match v1 (it holds public config/metadata for the provider types that use it).
func (p *Provider) Mask() *Provider {
	if p == nil {
		return nil
	}
	m := *p
	m.ClientSecret, m.ClientSecret2 = "", ""
	return &m
}
