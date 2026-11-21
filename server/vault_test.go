// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/server"
)

type heldVault map[[2]string]string

func (h heldVault) Put(_ context.Context, org, name, pem string) error {
	if _, ok := h[[2]string{org, name}]; ok {
		return server.ErrKeyExists
	}
	h[[2]string{org, name}] = pem
	return nil
}

func (h heldVault) Get(_ context.Context, org, name string) (string, error) {
	if pem, ok := h[[2]string{org, name}]; ok {
		return pem, nil
	}
	return "", server.ErrNoKey
}

func (h heldVault) Delete(_ context.Context, org, name string) error {
	delete(h, [2]string{org, name})
	return nil
}

// A host's Vault is the one IAM keeps organization keys in, and its two refusals are
// the ones IAM reads.
func TestUseVaultInstallsTheHostsVault(t *testing.T) {
	ctx := context.Background()
	if err := keyring.PutTenant(ctx, "acme", "acme-signing", "pem"); !errors.Is(err, keyring.ErrNoVault) {
		t.Fatalf("with no vault a tenant key is stored: %v", err)
	}
	v := heldVault{}
	server.UseVault(v)
	t.Cleanup(func() { server.UseVault(nil) })
	if err := keyring.PutTenant(ctx, "acme", "acme-signing", "pem"); err != nil {
		t.Fatalf("put through the host's vault: %v", err)
	}
	if v[[2]string{"acme", "acme-signing"}] != "pem" {
		t.Fatalf("the key did not reach the host's vault: %v", v)
	}
	if err := keyring.PutTenant(ctx, "acme", "acme-signing", "other"); !errors.Is(err, keyring.ErrExists) {
		t.Fatalf("a second put over a held key was not refused as ErrExists: %v", err)
	}
	if _, err := keyring.TenantKey(ctx, "acme", "absent", func(string) bool { return true }); !errors.Is(err, keyring.ErrNoKey) {
		t.Fatalf("an absent key was not ErrNoKey: %v", err)
	}
}
