// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keyring

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Vault holds the private half of ORGANIZATION signing certs (schema.CertTenant),
// which IAM generates and the host keeps in custody. It is a different thing from
// the platform ring above: platform keys are supplied by the deployment and read
// from its mount, and a tenant's key is never read from there, so no mount path,
// kid or name can hand one org's key to another or a platform key to an org.
//
// The host supplies the implementation (cloud keeps it in KMS under the org).
// With none installed a tenant cert can be neither created nor used to sign: it
// fails closed, as a platform cert with no mounted key does.
//
// A key is addressed by (org, cert name) and nothing else. Put never overwrites;
// a rotation is a new cert under a new name.
type Vault interface {
	// Put stores one PEM private key. It returns ErrExists when (org, name) holds one.
	Put(ctx context.Context, org, name, pem string) error
	// Get returns the PEM held for (org, name), or ErrNoKey.
	Get(ctx context.Context, org, name string) (string, error)
	// Delete forgets the key held for (org, name); absent is not an error.
	Delete(ctx context.Context, org, name string) error
}

var (
	// ErrNoVault is a tenant key asked for where the host installed no Vault.
	ErrNoVault = errors.New("keyring: no tenant key vault is installed")
	// ErrNoKey is a tenant cert whose Vault holds no key.
	ErrNoKey = errors.New("keyring: the vault holds no key for this cert")
	// ErrExists is a Put over a key the Vault already holds.
	ErrExists = errors.New("keyring: the vault already holds a key for this cert")
)

var (
	vaultMu sync.RWMutex
	vault   Vault
	// tenant caches keys already read, so signing a token is not a vault call.
	tenant = map[[2]string]heldKey{}
)

type heldKey struct {
	pem string
	at  time.Time
}

const (
	// tenantTTL is how long a key read from the Vault is reused before it is read again.
	tenantTTL = 5 * time.Minute
	// tenantMax bounds the cache; past it the cache is dropped and refilled on demand.
	tenantMax = 256
)

// UseVault installs the host's Vault. nil removes it.
func UseVault(v Vault) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	vault = v
	tenant = map[[2]string]heldKey{}
}

func vaultOf() (Vault, error) {
	vaultMu.RLock()
	defer vaultMu.RUnlock()
	if vault == nil {
		return nil, ErrNoVault
	}
	return vault, nil
}

// PutTenant stores a newly generated key for (org, name).
func PutTenant(ctx context.Context, org, name, pem string) error {
	v, err := vaultOf()
	if err != nil {
		return err
	}
	if org == "" || name == "" || !addressable(name) || pem == "" {
		return errors.New("keyring: a tenant key needs an org, an addressable name and a key")
	}
	return v.Put(ctx, org, name, pem)
}

// TenantKey returns the PEM held for (org, name) that satisfies matches: from the cache
// while fresh, else from the Vault. matches binds the key to the cert row it signs for
// (its public half), so a cert deleted and created again under the same name never
// reuses a key cached for the old one, here or on another replica: a cached key that does
// not match is dropped and the Vault is read; a Vault key that does not match is no key.
func TenantKey(ctx context.Context, org, name string, matches func(pem string) bool) (string, error) {
	v, err := vaultOf()
	if err != nil {
		return "", err
	}
	if org == "" || !addressable(name) || matches == nil {
		return "", ErrNoKey
	}
	k := [2]string{org, name}
	vaultMu.RLock()
	h, ok := tenant[k]
	vaultMu.RUnlock()
	if ok && time.Since(h.at) < tenantTTL && matches(h.pem) {
		return h.pem, nil
	}
	vaultMu.Lock()
	delete(tenant, k)
	vaultMu.Unlock()
	pem, err := v.Get(ctx, org, name)
	if err != nil {
		return "", err
	}
	if pem == "" || !matches(pem) {
		return "", ErrNoKey
	}
	vaultMu.Lock()
	if len(tenant) >= tenantMax {
		tenant = map[[2]string]heldKey{}
	}
	tenant[k] = heldKey{pem: pem, at: time.Now()}
	vaultMu.Unlock()
	return pem, nil
}

// DropTenant forgets the key held for (org, name) in the Vault and in the cache.
func DropTenant(ctx context.Context, org, name string) error {
	vaultMu.Lock()
	delete(tenant, [2]string{org, name})
	vaultMu.Unlock()
	v, err := vaultOf()
	if err != nil {
		return err
	}
	return v.Delete(ctx, org, name)
}

// Addressable reports whether name may name a cert key: the rule the mount read
// applies to a file name, so one kid spells one key everywhere.
func Addressable(name string) bool { return addressable(name) }
