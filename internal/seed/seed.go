// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package seed bootstraps the iam2 store from an init_data.json file — the same
// file the Casdoor iam uses. This is the ported InitFromFile behavior: on boot,
// upsert organizations, applications, providers, and certs so a fresh iam2
// (embedded in cloud or standalone) comes up with the real app/provider/cert
// config instead of an empty store.
//
// New-only by default (like Casdoor's initDataNewOnly): an entity that already
// exists is left untouched; only missing ones are created. ${VAR} references in
// the JSON (client ids/secrets, cert keys) are substituted from the environment
// before parsing — the same mechanism that injects KMS-synced secrets.
package seed

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// initData is the subset of the init_data.json shape iam2 seeds. Users and the
// Casbin/LDAP/syncer artifacts are deliberately excluded — identity config only.
type initData struct {
	Organizations []*schema.Organization `json:"organizations"`
	Applications  []*schema.Application  `json:"applications"`
	Providers     []*schema.Provider     `json:"providers"`
	Certs         []*schema.Cert         `json:"certs"`
}

// Summary reports what a seed run created vs skipped.
type Summary struct {
	Created map[string]int // kind -> created count
	Skipped map[string]int // kind -> already-existed count
}

var envRef = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)

// substituteEnv replaces ${VAR} with os.Getenv(VAR). An unset var becomes empty
// (Casdoor-compatible) — a provider/cert with an empty credential simply reads
// as unconfigured downstream, never a dead-end.
func substituteEnv(b []byte) []byte {
	return envRef.ReplaceAllFunc(b, func(m []byte) []byte {
		name := envRef.FindSubmatch(m)[1]
		return []byte(os.Getenv(string(name)))
	})
}

// FromInitData reads path, substitutes ${VAR}, and upserts the identity config
// into db. new-only: existing rows (by owner/name) are skipped.
func FromInitData(ctx context.Context, db orm.DB, path string) (*Summary, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seed: read %s: %w", path, err)
	}
	var data initData
	if err := json.Unmarshal(substituteEnv(raw), &data); err != nil {
		return nil, fmt.Errorf("seed: parse %s: %w", path, err)
	}
	return Apply(ctx, db, &data)
}

// Apply upserts an already-parsed initData. Split out so tests can seed from a
// literal without a file.
func Apply(ctx context.Context, db orm.DB, data *initData) (*Summary, error) {
	s := &Summary{Created: map[string]int{}, Skipped: map[string]int{}}
	for _, o := range data.Organizations {
		if err := upsert[schema.Organization](ctx, db, o.Owner, o.Name, o, s, "organizations"); err != nil {
			return s, err
		}
	}
	for _, p := range data.Providers {
		if err := upsert[schema.Provider](ctx, db, p.Owner, p.Name, p, s, "providers"); err != nil {
			return s, err
		}
	}
	for _, c := range data.Certs {
		// A reserved-org signing cert arrives from init_data without key material
		// (secrets can't ride a ConfigMap); mint the keypair so the JWKS publishes a
		// key and iam2 can sign — persisted once by the new-only upsert below.
		if err := ensureSigningKey(c); err != nil {
			return s, fmt.Errorf("seed: generate signing key for cert %s/%s: %w", c.Owner, c.Name, err)
		}
		if err := upsert[schema.Cert](ctx, db, c.Owner, c.Name, c, s, "certs"); err != nil {
			return s, err
		}
	}
	for _, a := range data.Applications {
		if err := upsert[schema.Application](ctx, db, a.Owner, a.Name, a, s, "applications"); err != nil {
			return s, err
		}
	}
	return s, nil
}

// upsert creates entity if (owner,name) is absent; otherwise counts it skipped
// (new-only). GetOrCreate wires a fresh Model + sets the id; the defaults func
// copies the entity's data fields via a JSON round-trip, which sets only the
// json-tagged fields and leaves the wired Model's internals (db handle, key)
// intact — the generic-safe way to persist a fully-formed struct.
func upsert[T any](_ context.Context, db orm.DB, owner, name string, entity *T, s *Summary, kind string) error {
	if owner == "" {
		owner = "admin"
	}
	id := owner + "/" + name
	blob, err := json.Marshal(entity)
	if err != nil {
		return fmt.Errorf("seed: marshal %s %s: %w", kind, id, err)
	}
	_, created, err := orm.GetOrCreate[T](db, id, func(dst *T) {
		_ = json.Unmarshal(blob, dst)
	})
	if err != nil {
		return fmt.Errorf("seed: create %s %s: %w", kind, id, err)
	}
	if created {
		s.Created[kind]++
	} else {
		s.Skipped[kind]++
	}
	return nil
}
