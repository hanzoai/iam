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

package controllers

import (
	_ "embed"
)

// iamDescriptor is the federation discovery payload published at
// /.well-known/iam.json per IETF RFC 8615 (HIP-0303 — Brand Sovereignty
// and Federation Discovery). The file lives at
// web/public/.well-known/iam.json and is embedded into the binary so
// the endpoint serves correctly regardless of how the binary is invoked
// (no working-directory dependency, no Beego static-path config required).
//
//go:embed wellknown_iam.json
var iamDescriptor []byte

// GetIamDescriptor serves the embedded /.well-known/iam.json payload.
// Bound at both /.well-known/iam.json (legacy/root) and
// /v1/iam/.well-known/iam.json (canonical per Hanzo policy).
func (c *RootController) GetIamDescriptor() {
	c.Ctx.Output.Header("Content-Type", "application/json; charset=utf-8")
	c.Ctx.Output.Header("Cache-Control", "public, max-age=3600")
	_, _ = c.Ctx.ResponseWriter.Write(iamDescriptor)
}
