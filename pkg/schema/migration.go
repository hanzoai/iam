// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Migration records a one-time change a store has had applied to its existing
// rows, so the work runs once per store and not on every open. Name is the
// migration's own name (for example "namekey-v1"), unique within a store.
type Migration struct {
	orm.Model[Migration]

	Name     string `json:"name" orm:"index"`
	DoneTime string `json:"doneTime"`
}
