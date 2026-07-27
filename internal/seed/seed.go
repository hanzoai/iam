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

	// appDeclared is the RAW json object for each application, keyed "owner/name".
	// It is what makes an application's declared POLICY converge on an existing row
	// (see reconcileApp) — the typed struct above cannot, because an absent key and
	// a declared `false` are both the zero value once decoded. Populated by
	// FromInitData; nil when Apply is called with a literal (tests), in which case
	// seeding stays strictly new-only.
	appDeclared map[string]json.RawMessage
}

// Summary reports what a seed run created, skipped, or reconciled.
type Summary struct {
	Created    map[string]int // kind -> created count
	Skipped    map[string]int // kind -> already-existed, unchanged
	Reconciled map[string]int // kind -> already-existed, declared policy re-applied
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
	sub := substituteEnv(raw)
	var data initData
	if err := json.Unmarshal(sub, &data); err != nil {
		return nil, fmt.Errorf("seed: parse %s: %w", path, err)
	}
	// Second pass, applications only: keep each declared object VERBATIM so
	// reconcileApp can tell "declared false" from "not declared at all".
	var rawDoc struct {
		Applications []json.RawMessage `json:"applications"`
	}
	if err := json.Unmarshal(sub, &rawDoc); err != nil {
		return nil, fmt.Errorf("seed: parse %s (raw applications): %w", path, err)
	}
	data.appDeclared = make(map[string]json.RawMessage, len(rawDoc.Applications))
	for _, obj := range rawDoc.Applications {
		var ref struct {
			Owner string `json:"owner"`
			Name  string `json:"name"`
		}
		if err := json.Unmarshal(obj, &ref); err != nil {
			continue
		}
		if ref.Owner == "" {
			ref.Owner = "admin"
		}
		data.appDeclared[ref.Owner+"/"+ref.Name] = obj
	}
	return Apply(ctx, db, &data)
}

// Apply upserts an already-parsed initData. Split out so tests can seed from a
// literal without a file.
func Apply(ctx context.Context, db orm.DB, data *initData) (*Summary, error) {
	s := &Summary{Created: map[string]int{}, Skipped: map[string]int{}, Reconciled: map[string]int{}}
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
		owner := a.Owner
		if owner == "" {
			owner = "admin"
		}
		before := s.Skipped["applications"]
		if err := upsert[schema.Application](ctx, db, a.Owner, a.Name, a, s, "applications"); err != nil {
			return s, err
		}
		// Existing row: re-apply the DECLARED policy so init_data.json is converging
		// state rather than a one-shot bootstrap.
		if s.Skipped["applications"] > before {
			if err := reconcileApp(db, owner+"/"+a.Name, data.appDeclared, s); err != nil {
				return s, err
			}
		}
	}
	return s, nil
}

// reconcileApp re-applies an application's DECLARED fields onto the existing row.
//
// Seeding is new-only, which is right for identity DATA (a live user row must never
// be stomped by a bootstrap file) but wrong for application POLICY: init_data.json is
// how the platform declares whether an app allows sign-up, which org it belongs to,
// and how it lets users choose one. Because upsert skipped existing rows, flipping
// `enableSignUp` in init_data.json changed nothing on a seeded deployment — the flag
// read false in production while the declared state said otherwise, and the only way
// to move it was an out-of-band admin call. Declared policy now converges on boot.
//
// It merges the RAW declared object onto the loaded row, which is the whole point:
// json.Unmarshal sets only the keys PRESENT in the JSON, so a field init_data.json
// does not mention keeps its stored value. That is what protects `clientSecret`,
// which is generated at first seed and never written back to the file — decoding the
// typed struct and saving it would blank the secret and lock every client out (the
// same de-secret hazard update-application had to fix). Nothing is written when the
// application was not declared with a raw object (Apply called from a literal).
func reconcileApp(db orm.DB, id string, declared map[string]json.RawMessage, s *Summary) error {
	raw, ok := declared[id]
	if !ok {
		return nil
	}
	if _, err := orm.GetOrUpdate[schema.Application](db, id, func(dst *schema.Application) {
		_ = json.Unmarshal(raw, dst)
	}); err != nil {
		return fmt.Errorf("seed: reconcile application %s: %w", id, err)
	}
	s.Reconciled["applications"]++
	return nil
}

// upsert creates entity if (owner,name) is absent; otherwise counts it skipped
// (new-only). GetOrCreate binds a fresh Model + sets the id; the defaults func
// copies the entity's data fields via a JSON round-trip, which sets only the
// json-tagged fields and leaves the bound Model's internals (db handle, key)
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
