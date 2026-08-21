// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keyring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// mount writes key material the way a deployment projects it — one file per Cert
// name — and points EnvDir at it.
func mount(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(EnvDir, dir)
	return dir
}

// clean drops a Cert name from the process ring so one test cannot see another's
// material (the ring is process-wide, exactly as it is in the service).
func clean(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		Forget(n)
	}
	t.Cleanup(func() {
		for _, n := range names {
			Forget(n)
		}
	})
}

func signingCert(name string) *schema.Cert {
	c := &schema.Cert{CryptoAlgorithm: "RS256"}
	c.Owner, c.Name = "admin", name
	return c
}

// The mounted PEM is what the Cert signs with.
func TestFill_ReadsTheMountedKey(t *testing.T) {
	clean(t, "cert-mounted")
	mount(t, map[string]string{"cert-mounted": "PEM-FROM-THE-MOUNT\n"})

	c := signingCert("cert-mounted")
	Fill(c)
	if c.PrivateKey != "PEM-FROM-THE-MOUNT" {
		t.Fatalf("PrivateKey = %q, want the mounted PEM (trailing newline trimmed)", c.PrivateKey)
	}
}

// FAIL CLOSED, AND THE MOUNT IS THE ONLY SOURCE. Nothing mounted leaves the Cert
// keyless whatever shape it is, so the token endpoint refuses instead of signing
// under a key that dies with the process and differs between replicas under one
// `kid`. Nothing in the environment mints one: a machine that has no key does not
// sign, it says so.
func TestFill_WithNothingMountedLeavesEveryCertKeyless(t *testing.T) {
	t.Setenv(EnvDir, "")

	rsa := signingCert("cert-absent")

	ssl := signingCert("cert-ssl")
	ssl.Type = "SSL"

	published := signingCert("cert-published")
	published.Certificate = "-----BEGIN CERTIFICATE-----"

	pq := signingCert("cert-pq")
	pq.CryptoAlgorithm = "MLDSA65"

	for _, c := range []*schema.Cert{rsa, ssl, published, pq} {
		clean(t, c.Name)
		Fill(c)
		if c.PrivateKey != "" {
			t.Errorf("%s: an unmounted deployment produced a key: %q", c.Name, c.PrivateKey)
		}
	}
}

// A Cert name is ROW data and a token states its own kid, so neither may address
// a file outside the mount. Each of these must read nothing rather than escape.
func TestFill_RefusesToEscapeTheKeyDirectory(t *testing.T) {
	dir := mount(t, nil)
	outside := filepath.Join(filepath.Dir(dir), "outside")
	if err := os.WriteFile(outside, []byte("STOLEN"), 0o400); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"../outside",
		"../../etc/passwd",
		"..",
		".",
		"sub/../../outside",
		"/etc/passwd",
	} {
		t.Run(name, func(t *testing.T) {
			clean(t, name)
			c := signingCert(name)
			Fill(c)
			if c.PrivateKey != "" {
				t.Fatalf("name %q read %q from outside the key directory", name, c.PrivateKey)
			}
		})
	}
}

// Material is addressed by NAME because the name is the `kid`. A tenant-owned
// cert sharing a platform cert's name must therefore never be handed the
// platform's key.
func TestFill_NeverKeysACertThatMayNotSign(t *testing.T) {
	clean(t, "cert-shared-name")
	mount(t, map[string]string{"cert-shared-name": "PLATFORM-PEM"})

	tenant := &schema.Cert{CryptoAlgorithm: "RS256"}
	tenant.Owner, tenant.Name = "attacker-org", "cert-shared-name"
	Fill(tenant)
	if tenant.PrivateKey != "" {
		t.Fatalf("a tenant cert was handed the platform key: %q", tenant.PrivateKey)
	}

	// The platform cert of the same name still gets it.
	platform := signingCert("cert-shared-name")
	Fill(platform)
	if platform.PrivateKey != "PLATFORM-PEM" {
		t.Fatalf("platform cert did not get its key: %q", platform.PrivateKey)
	}
}

// A Cert that already carries material keeps it: a caller that built a Cert in
// memory has already said what it signs with.
func TestFill_LeavesSuppliedMaterialAlone(t *testing.T) {
	clean(t, "cert-inmemory")
	mount(t, map[string]string{"cert-inmemory": "MOUNTED"})

	c := signingCert("cert-inmemory")
	c.PrivateKey = "CALLER-SUPPLIED"
	Fill(c)
	if c.PrivateKey != "CALLER-SUPPLIED" {
		t.Fatalf("PrivateKey = %q, want the caller's own material", c.PrivateKey)
	}
}

// A key the operator projects AFTER this process started is picked up on the next
// read — the second half of a rotation, without a restart. A miss must therefore
// never be cached.
func TestFill_PicksUpAKeyProjectedAfterAMiss(t *testing.T) {
	clean(t, "cert-rotating")
	dir := mount(t, nil)

	c := signingCert("cert-rotating")
	Fill(c)
	if c.PrivateKey != "" {
		t.Fatalf("key appeared before it was projected: %q", c.PrivateKey)
	}

	if err := os.WriteFile(filepath.Join(dir, "cert-rotating"), []byte("ROTATED-IN"), 0o400); err != nil {
		t.Fatal(err)
	}
	next := signingCert("cert-rotating")
	Fill(next)
	if next.PrivateKey != "ROTATED-IN" {
		t.Fatalf("PrivateKey = %q, want the newly projected key", next.PrivateKey)
	}
}
