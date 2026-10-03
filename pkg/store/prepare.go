// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

// preparePage is how many rows one read of Prepare takes, and one transaction keys.
const preparePage = 500

// Prepared is what one Prepare did.
type Prepared struct {
	Keyed   int    // rows given their NameKey
	Skipped []Skip // rows it could not read the name of, left as they were
}

// Skip is one row Prepare left unkeyed, and why.
type Skip struct {
	Kind, ID, Why string
}

// keyedKind is a kind whose rows carry a NameKey, and the document field it folds:
// a user's name, or the user id ("<home>/<name>") a membership is held by.
var keyedKinds = []struct {
	kind  string
	field string
	name  func(string) string
}{
	{"users", "name", func(s string) string { return s }},
	{"memberships", "user", func(s string) string { _, name, _ := strings.Cut(s, "/"); return name }},
}

// Prepare readies an identity store for this code, and every path that opens one
// calls it before serving: Open here, and any host that opens the store its own way.
//
// It keys every user and membership stored without a NameKey: rows saved before
// the field existed, and rows saved since by a binary that does not know it (a
// rollback, then a roll forward). It runs on every open, not once per store,
// because a rollback can unkey rows a previous run keyed.
//
// An open with nothing to key costs one indexed read per kind: the indexes are built
// first (orm.Ready) and the read asks for a row without the field. When there is
// one, the kind is walked once in key order (orm After), a page at a time, so a
// write between pages cannot shift a row out of the walk.
//
// A row is read as the JSON it is stored as, and only the field its key folds is
// decoded: a row some other field of which this binary could not decode is keyed
// all the same, and one whose name it cannot read is skipped, logged and left as it
// was. One row never fails the open. The key is written into the stored document
// and nothing else in it changes, timestamps included. A page is keyed in one
// transaction that reads each row again first, so a write made since the page was
// read is kept and a row deleted since is left deleted.
func Prepare(ctx context.Context, db orm.DB) (Prepared, error) {
	var p Prepared
	kinds := make([]string, len(keyedKinds))
	for i, k := range keyedKinds {
		kinds[i] = k.kind
	}
	if err := orm.Ready(db, kinds...); err != nil {
		return p, err
	}
	for _, k := range keyedKinds {
		var probe []json.RawMessage
		keys, err := db.Query(k.kind).Filter("nameKey=", nil).Limit(1).GetAll(ctx, &probe)
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return p, fmt.Errorf("%s: %w", k.kind, err)
		}
		if len(keys) == 0 {
			continue
		}
		for last := ""; ; {
			q, err := orm.After(db.Query(k.kind), last)
			if err != nil {
				return p, fmt.Errorf("%s: %w", k.kind, err)
			}
			var docs []json.RawMessage
			keys, err := q.Limit(preparePage).GetAll(ctx, &docs)
			if err != nil && !errors.Is(err, orm.ErrNotFound) {
				return p, fmt.Errorf("%s after %q: %w", k.kind, last, err)
			}
			var unkeyed []orm.Key
			for i, key := range keys {
				last = key.Encode()
				if i < len(docs) && !hasKey(docs[i]) {
					unkeyed = append(unkeyed, key)
				}
			}
			if len(unkeyed) > 0 {
				keyed, skipped, err := keyPage(ctx, db, k.kind, k.field, k.name, unkeyed)
				if err != nil {
					return p, fmt.Errorf("%s: %w", k.kind, err)
				}
				p.Keyed += keyed
				p.Skipped = append(p.Skipped, skipped...)
			}
			if len(keys) < preparePage {
				break
			}
		}
	}
	return p, nil
}

// keyPage keys the rows at keys in one transaction, reading each again first.
func keyPage(ctx context.Context, db orm.DB, kind, field string, name func(string) string, keys []orm.Key) (int, []Skip, error) {
	var keyed int
	var skipped []Skip
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		keyed, skipped = 0, nil // a retried transaction counts again from nothing
		for _, key := range keys {
			var raw json.RawMessage
			if err := tx.Get(ctx, key, &raw); err != nil {
				if errors.Is(err, orm.ErrNotFound) {
					continue // deleted since the page was read
				}
				return err
			}
			doc, why := withKey(raw, field, name)
			if why != "" {
				skipped = append(skipped, Skip{Kind: kind, ID: key.Encode(), Why: why})
				continue
			}
			if doc == nil {
				continue // keyed since the page was read
			}
			if _, err := tx.Put(ctx, key, doc); err != nil {
				return err
			}
			keyed++
		}
		return nil
	})
	for _, s := range skipped {
		log.Printf("iam: %s %s keeps no name key: %s", s.Kind, s.ID, s.Why)
	}
	return keyed, skipped, err
}

// hasKey reports whether a stored document carries a NameKey, empty or not.
func hasKey(raw json.RawMessage) bool {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	v, ok := doc["nameKey"]
	return ok && string(v) != "null"
}

// withKey is raw with its NameKey written from field: nil when it already has one,
// or the reason it cannot be keyed. Every other field is carried as it was stored.
func withKey(raw json.RawMessage, field string, name func(string) string) (json.RawMessage, string) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "the stored document is not a JSON object: " + err.Error()
	}
	if v, ok := doc["nameKey"]; ok && string(v) != "null" {
		return nil, ""
	}
	var s string
	if v, ok := doc[field]; !ok {
		return nil, "it has no " + field
	} else if err := json.Unmarshal(v, &s); err != nil {
		return nil, "its " + field + " is not a string"
	}
	key, err := json.Marshal(schema.Fold(name(s)))
	if err != nil {
		return nil, err.Error()
	}
	doc["nameKey"] = key
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err.Error()
	}
	return out, ""
}
