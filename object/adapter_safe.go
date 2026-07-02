// Copyright 2025 Hanzo AI, Inc.
// Portions Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"github.com/hanzoai/xorm"

	"github.com/hanzoai/authzstore"
	"github.com/hanzoai/iam/util"
)

// SafeAdapter wraps an authzstore.Adapter and overrides RemovePolicy /
// RemovePolicies with versions that force-include the zero-valued V
// columns in the WHERE clause via MustCols. The base adapter already
// does this for single-row deletes; SafeAdapter exists because the
// authz library's bulk remove path used to call RemovePolicies, which
// the original xorm-adapter did NOT MustCols, leading to over-broad
// deletes in production. We keep the override here for parity with
// historical behavior.
type SafeAdapter struct {
	*authzstore.Adapter
	engine    *xorm.Engine
	tableName string
}

func NewSafeAdapter(a *Adapter) *SafeAdapter {
	if a == nil || a.Adapter == nil || a.engine == nil {
		return nil
	}

	return &SafeAdapter{
		Adapter:   a.Adapter,
		engine:    a.engine,
		tableName: a.Table,
	}
}

func (a *SafeAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := a.buildAuthzRule(ptype, rule)

	session := a.engine.NewSession()
	defer session.Close()

	if a.tableName != "" {
		session = session.Table(a.tableName)
	}

	_, err := session.
		MustCols("ptype", "v0", "v1", "v2", "v3", "v4", "v5").
		Delete(line)

	return err
}

func (a *SafeAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		for _, rule := range rules {
			line := a.buildAuthzRule(ptype, rule)

			var session *xorm.Session
			if a.tableName != "" {
				session = tx.Table(a.tableName)
			} else {
				session = tx
			}

			_, err := session.
				MustCols("ptype", "v0", "v1", "v2", "v3", "v4", "v5").
				Delete(line)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (a *SafeAdapter) buildAuthzRule(ptype string, rule []string) *util.AuthzRule {
	line := util.AuthzRule{Ptype: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	return &line
}
