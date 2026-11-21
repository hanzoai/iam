// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server

import "github.com/hanzoai/iam/internal/keyring"

// Vault holds the private half of an organization's signing certs, which IAM
// generates and the host keeps in custody (cloud keeps it in KMS, under the org).
// A key is addressed by (org, cert name); Put never overwrites.
type Vault = keyring.Vault

var (
	// ErrKeyExists is what a Vault's Put answers for a key it already holds.
	ErrKeyExists = keyring.ErrExists
	// ErrNoKey is what a Vault's Get answers for a key it does not hold.
	ErrNoKey = keyring.ErrNoKey
)

// UseVault installs the host's Vault. Call it before serving. With none installed
// an organization's cert can be neither created nor used to sign; nil removes it.
func UseVault(v Vault) { keyring.UseVault(v) }
