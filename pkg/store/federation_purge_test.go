// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// A purge takes the expired rows and nothing else, and what it leaves of each on
// disk carries none of the transaction: no verifier, nonce, binding hash, app
// request or provider reply. A second pass reads no tombstone, and the expiry
// is indexed over live rows.
func TestPurgeFederationStates(t *testing.T) {
	db, path := fileDB(t)
	ctx := context.Background()
	now := time.Unix(1_790_000_000, 0)
	put := func(name string, expire int64, used bool) {
		t.Helper()
		st := &schema.FederationState{
			Owner: "admin", Name: name, Provider: "provider-apple", ClientId: "webapp",
			RedirectUri: "https://app.example/cb", AppState: "state-" + name, AppNonce: "nonce-" + name,
			IdpVerifier: "verifier-" + name, IdpNonce: "idpnonce-" + name, BindHash: "bind-" + name,
			Reply: "user=Grace+Hopper+" + name, ExpireIn: expire, Used: used,
		}
		if err := PersistFederationState(ctx, db, st); err != nil {
			t.Fatal(err)
		}
	}
	put("expired", now.Add(-time.Hour).Unix(), false)
	put("spent", now.Add(-time.Hour).Unix(), true)
	put("live", now.Add(time.Minute).Unix(), false)
	put("used", now.Add(time.Minute).Unix(), true)
	put("lasting", 0, false)

	if n, err := PurgeFederationStates(ctx, db, now, 100); err != nil || n != 2 {
		t.Fatalf("purge = %d, %v; want the 2 expired rows", n, err)
	}
	for _, name := range []string{"expired", "spent"} {
		if st, err := GetFederationState(ctx, db, name); err != nil || st != nil {
			t.Errorf("%s: still readable after the purge (%v)", name, err)
		}
	}
	for _, name := range []string{"live", "used", "lasting"} {
		st, err := GetFederationState(ctx, db, name)
		if err != nil || st == nil || st.BindHash != "bind-"+name || st.Reply == "" {
			t.Errorf("%s: the purge changed a row in force: %+v, %v", name, st, err)
		}
	}
	if n, err := PurgeFederationStates(ctx, db, now, 100); err != nil || n != 0 {
		t.Fatalf("second purge = %d, %v; want nothing left to take", n, err)
	}
	if err := orm.Ready(db, "federation_states"); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT json_extract(data, '$.name'), deleted, data FROM _entities WHERE kind = 'federation_states'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, data string
		var deleted bool
		if err := rows.Scan(&name, &deleted, &data); err != nil {
			t.Fatal(err)
		}
		if name != "expired" && name != "spent" {
			continue
		}
		if !deleted {
			t.Errorf("%s: purged row is live", name)
		}
		for _, held := range []string{"verifier-", "idpnonce-", "bind-", "state-", "nonce-", "Grace", "app.example"} {
			if strings.Contains(data, held) {
				t.Errorf("%s: the tombstone still holds %q: %s", name, held, data)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var idx int
	if err := raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_federation_states_expireIn'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("no expiry index (%d, %v)", idx, err)
	}
}
