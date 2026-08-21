// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package keyring holds the private half of the signing Certs this IAM issues
// tokens with.
//
// A Cert ROW is the key's IDENTITY — owner, name (the JWKS `kid`), algorithm,
// expiry — and identity is public: the JWKS publishes it. The private key is not
// identity and is not stored: schema.Cert.PrivateKey carries `json:"-"`, and
// since every orm backend persists an entity as json.Marshal(entity), that is
// what makes a row physically unable to hold one. It is supplied by the
// deployment and held only here, in memory, for the life of the process.
//
// ONE source: a directory of PEM files, one per Cert name, at $IAM_SIGNING_KEYS.
// A directory of files IS the shape both of the estate's KMS readers already
// deliver — kms-fetch (the initContainer; KMS_SECRETS names each file, written
// 0400, all-or-nothing) and a KMSSecret CR projected as a read-only mount — so
// this reads what those write and adds no new convention. It is also the same
// clean-room path the registry signing key already takes
// (internal/registry/signkey.go). Either way something ELSE performs the KMS
// read; iam holds no KMS credential and makes no KMS call of its own.
//
// It could not make one anyway, and that is the load-bearing reason this is a
// mount rather than an in-process fetch. The KMS client's HTTP transport mints
// its bearer by posting client_credentials to iam's OWN token endpoint, and kmsd
// verifies that bearer against iam's JWKS. An iam that fetched its signing key
// over KMS would have to sign a token with the key it was asking for, and
// publish that same key in order for the token to be accepted. The operator sits
// outside that cycle, which is what makes it the thing that can do the fetch.
//
// Resolution is FAIL-CLOSED, and the mount is the ONLY source. With nothing
// mounted a Cert resolves to no key and the token endpoint refuses
// (oidc.ErrNoSigningCert). A dev box mounts a PEM like every other deployment
// does: one way to establish the trust root, the same way everywhere. A key
// minted in-process would be a second way, and it would die with the process,
// differ between replicas under one `kid`, and invalidate every live token on a
// restart — so a machine that has no key does not sign, it says so.
package keyring

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/pkg/schema"
)

// EnvDir names the read-only directory holding one PEM file per signing Cert,
// each file named for the Cert it keys — which is the JWKS `kid`, so the
// operator projecting the Secret and the verifier reading the token agree on the
// name with no mapping table in between.
const EnvDir = "IAM_SIGNING_KEYS"

// held is the process ring: Cert name -> key material. Guarded by mu; read on
// every signing-cert load, written once per Cert — by the mount read, or by a
// caller staging a key with Set.
var (
	mu   sync.RWMutex
	held = map[string]string{}
)

// Set registers key material under a Cert name. It is the ONE way material
// enters the ring: the mount read calls it, and a test calls it with the key it
// wants that Cert to sign under. Material already
// held for the name is replaced, which is what lets a rotation take effect
// without a restart.
func Set(name, material string) {
	if name == "" || material == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	held[name] = material
}

// Forget drops the material held for a Cert name, so a caller that staged a key
// can put the ring back the way it found it.
func Forget(name string) {
	mu.Lock()
	defer mu.Unlock()
	delete(held, name)
}

// Fill populates a Cert's private key from the ring — the one place a loaded row
// gains key material. The store calls it on every cert it reads, so signing,
// verification, the JWKS and the session-cookie key all see the same value they
// saw when the key was a column, and not one of those callers had to change.
//
// A cert that arrives already carrying material keeps it: a caller that built a
// Cert in memory has already said what it signs with. A cert with no material
// anywhere is left keyless, and every consumer already reads keyless as "does
// not sign, and is not published".
func Fill(cert *schema.Cert) {
	if cert == nil || cert.Name == "" || cert.PrivateKey != "" {
		return
	}
	// Only a cert that is ALLOWED to sign is ever given a key. Material is
	// addressed by NAME, because the name is the `kid` — so without this a
	// tenant-owned cert sharing a platform cert's name would be handed the
	// platform's key on load. The three consumers each refuse a tenant cert
	// already (GetSigningCert, oidc.Publishes, PlatformSigningCert); this is what
	// keeps the material from ever being on the row for one of them to slip on.
	// The owner is compared VERBATIM, as it is at all three, so this gate admits
	// exactly the certs they do and never a row they would refuse.
	if !policy.IsSigningOwner(cert.Owner) {
		return
	}
	cert.PrivateKey = lookup(cert.Name)
}

// lookup resolves key material for a Cert name: the ring first, then the mount.
// A mount hit is remembered; a MISS is not, so a key the operator projects after
// this process started — the second half of a rotation — is picked up on the
// next read rather than at the next restart.
func lookup(name string) string {
	mu.RLock()
	m, ok := held[name]
	mu.RUnlock()
	if ok {
		return m
	}
	m = read(name)
	if m == "" {
		return ""
	}
	Set(name, m)
	return m
}

// read returns the PEM the deployment mounted for a Cert name, or "" when the
// mount is unset, the name cannot address a file inside it, or no such file
// exists.
func read(name string) string {
	dir := strings.TrimSpace(os.Getenv(EnvDir))
	if dir == "" || !addressable(name) {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// addressable reports whether a Cert name may name a file in the key directory.
// The name is ROW data — an operator creates certs, and a token states its own
// `kid` — so it is checked rather than trusted: a cert named
// "../../var/run/secrets/kubernetes.io/serviceaccount/token" must not read a
// file outside the mount, and one named "." must not read the directory itself.
// Letters, digits, dash, underscore and dot only, and no dot run that could walk
// upward.
func addressable(name string) bool {
	if name == "" || name == "." || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
