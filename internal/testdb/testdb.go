// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package testdb is the ONE store double a test degrades a read with: every query
// of one kind fails, every other read and every write is the real store's. It is
// how a suite asks what a gate does when the set it decides on cannot be read.
package testdb

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
)

// ErrUnreadable is what a degraded query answers.
var ErrUnreadable = errors.New("testdb: unreadable")

// Unreadable wraps db so that every query of kind fails with ErrUnreadable.
func Unreadable(db orm.DB, kind string) orm.DB { return unreadable{DB: db, kind: kind} }

type unreadable struct {
	orm.DB
	kind string
}

func (d unreadable) Query(kind string) orm.Query {
	if kind == d.kind {
		return failing{d.DB.Query(kind)}
	}
	return d.DB.Query(kind)
}

type failing struct{ orm.Query }

func (q failing) Filter(string, interface{}) orm.Query     { return q }
func (q failing) Order(string) orm.Query                   { return q }
func (q failing) Limit(int) orm.Query                      { return q }
func (q failing) Offset(int) orm.Query                     { return q }
func (q failing) First(interface{}) (orm.Key, bool, error) { return nil, false, ErrUnreadable }
func (q failing) Count(context.Context) (int, error)       { return 0, ErrUnreadable }
func (q failing) GetAll(context.Context, interface{}) ([]orm.Key, error) {
	return nil, ErrUnreadable
}
