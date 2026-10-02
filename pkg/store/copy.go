// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

// copy.go moves an identity store from one backend to another — the embedded
// SQLite file to hanzoai/sql, or back — and proves the two hold the same records.
//
// Every entity is copied as the JSON document it is stored as, so nothing is
// reinterpreted on the way through. Two records are the same when their
// documents are the same document: keys in any order, numbers as written
// (copyHash). A copy is idempotent — a record the target already holds unchanged
// is not written again — so it can be run while the source still serves, and
// again, and each later pass moves only what changed. With prune it also removes
// target records the source no longer has, so the last pass, run with writes
// frozen, leaves the target an exact copy. Verify then compares every record.

// copyPage is how many records one read takes. Records are read in id order with
// a keyset filter (id > the last one seen), never by offset, so a write that
// lands mid-copy cannot shift a page and skip a record.
const copyPage = 5000

// CopyReport is what one kind's copy did.
type CopyReport struct {
	Kind    string
	Source  int // records the source holds
	Written int // records written to the target
	Same    int // records the target already held unchanged
	Removed int // target records the source does not hold (prune only)
}

// Diff is one record that differs between two stores.
type Diff struct {
	Kind string
	ID   string
	What string // "missing" (source only), "extra" (target only) or "differs"
}

// Copy copies every identity kind (schema.Kinds) from src to dst. With prune,
// dst records src does not hold are removed.
func Copy(ctx context.Context, src, dst orm.DB, prune bool) ([]CopyReport, error) {
	var reports []CopyReport
	for _, kind := range schema.Kinds() {
		r, err := copyKind(ctx, src, dst, kind, prune)
		if err != nil {
			return reports, fmt.Errorf("copy %s: %w", kind, err)
		}
		reports = append(reports, r)
	}
	return reports, nil
}

func copyKind(ctx context.Context, src, dst orm.DB, kind string, prune bool) (CopyReport, error) {
	r := CopyReport{Kind: kind}
	have, err := hashes(ctx, dst, kind)
	if err != nil {
		return r, err
	}
	seen := make(map[string]bool, len(have))
	err = each(ctx, src, kind, func(id string, doc json.RawMessage) error {
		r.Source++
		seen[id] = true
		if h, ok := have[id]; ok && h == copyHash(doc) {
			r.Same++
			return nil
		}
		if _, err := dst.Put(ctx, dst.NewKey(kind, id, 0, nil), doc); err != nil {
			return fmt.Errorf("write %s: %w", id, err)
		}
		r.Written++
		return nil
	})
	if err != nil {
		return r, err
	}
	if prune {
		for id := range have {
			if seen[id] {
				continue
			}
			if err := dst.Delete(ctx, dst.NewKey(kind, id, 0, nil)); err != nil {
				return r, fmt.Errorf("remove %s: %w", id, err)
			}
			r.Removed++
		}
	}
	return r, nil
}

// Verify compares every identity record in a and b and returns each one that is
// not the same in both. An empty result is the proof a cutover waits for.
func Verify(ctx context.Context, a, b orm.DB) ([]Diff, error) {
	var diffs []Diff
	for _, kind := range schema.Kinds() {
		ha, err := hashes(ctx, a, kind)
		if err != nil {
			return diffs, fmt.Errorf("verify %s: %w", kind, err)
		}
		hb, err := hashes(ctx, b, kind)
		if err != nil {
			return diffs, fmt.Errorf("verify %s: %w", kind, err)
		}
		for id, h := range ha {
			switch hb2, ok := hb[id]; {
			case !ok:
				diffs = append(diffs, Diff{Kind: kind, ID: id, What: "missing"})
			case hb2 != h:
				diffs = append(diffs, Diff{Kind: kind, ID: id, What: "differs"})
			}
		}
		for id := range hb {
			if _, ok := ha[id]; !ok {
				diffs = append(diffs, Diff{Kind: kind, ID: id, What: "extra"})
			}
		}
	}
	return diffs, nil
}

// hashes is every record of kind in db, by id.
func hashes(ctx context.Context, db orm.DB, kind string) (map[string][32]byte, error) {
	out := map[string][32]byte{}
	err := each(ctx, db, kind, func(id string, doc json.RawMessage) error {
		out[id] = copyHash(doc)
		return nil
	})
	return out, err
}

// each calls fn with every record of kind in db, in id order. A record whose
// document does not carry its own id cannot be paged by it; it is counted and
// the walk fails rather than copying a store with a hole in it.
func each(ctx context.Context, db orm.DB, kind string, fn func(id string, doc json.RawMessage) error) error {
	total, err := db.Query(kind).Count(ctx)
	if err != nil {
		return fmt.Errorf("count: %w", err)
	}
	walked, last := 0, ""
	for {
		q := db.Query(kind).Order("id").Limit(copyPage)
		if last != "" {
			q = q.Filter("id>", last)
		}
		var docs []json.RawMessage
		keys, err := q.GetAll(ctx, &docs)
		if err != nil {
			return fmt.Errorf("read after %q: %w", last, err)
		}
		if len(keys) != len(docs) {
			return fmt.Errorf("read after %q: %d keys for %d records", last, len(keys), len(docs))
		}
		for i, k := range keys {
			id := k.Encode()
			if err := fn(id, docs[i]); err != nil {
				return err
			}
			last = id
		}
		walked += len(keys)
		if len(keys) < copyPage {
			break
		}
	}
	if walked != total {
		return fmt.Errorf("%d of %d records were reached by id: the rest carry no id in their document", walked, total)
	}
	return nil
}

// copyHash is the identity of a document: its JSON decoded and encoded again with
// object keys sorted and numbers kept as written, so the same record hashes the
// same whichever store wrote it out.
func copyHash(doc json.RawMessage) [32]byte {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return sha256.Sum256(doc)
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return sha256.Sum256(doc)
	}
	return sha256.Sum256(canon)
}
