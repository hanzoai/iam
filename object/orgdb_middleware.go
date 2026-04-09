// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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
	"context"

	"github.com/hanzoai/xorm"
)

type orgEngineContextKey struct{}

// ContextWithOrgEngine stores an org-scoped engine in the context.
func ContextWithOrgEngine(ctx context.Context, owner string) context.Context {
	eng := orgEngine(owner)
	return context.WithValue(ctx, orgEngineContextKey{}, eng)
}

// GetOrgEngineFromContext retrieves the org-scoped engine from context.
// Falls back to the global engine if not set.
func GetOrgEngineFromContext(ctx context.Context) *xorm.Engine {
	if eng, ok := ctx.Value(orgEngineContextKey{}).(*xorm.Engine); ok && eng != nil {
		return eng
	}
	return ormer.Engine
}
