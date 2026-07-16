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

// Client-credentials confidential-client discriminator.
//
// A confidential client authenticates in TWO transports that MUST resolve to
// the SAME principal:
//
//   - Basic-auth / clientId+clientSecret query (routers/base.go
//     getUsernameByClientIdSecret) → resolves directly to "app/<name>".
//   - a client_credentials Bearer JWT (this file's discriminator, called by
//     routers/authz_filter.go getUsernameFromBearerToken) → verified here, then
//     normalized to the SAME "app/<name>" subject.
//
// Before this discriminator existed, the JWT transport resolved a confidential
// client to "<org>/<app>" (claims.User.Owner/Name) instead of "app/<name>".
// That divergence — two subjects for one principal — made the confidential
// client ESCAPE every "app/<name>"-keyed control: the authz enforcer app
// short-circuit, IsAppUser, every AppAllowedForCapability gate, and the R-1
// "an app is never a global admin" downgrade. Collapsing both transports onto
// "app/<name>" is the one-way-to-do-everything fix and is strictly fail-SAFE:
// the JWT confidential client is now subject to the exact same capability gates
// as the Basic-auth confidential client, never more privilege.
//
// The check is the discriminator proven in controllers/users_by_attribute.go
// (defaultResolveServiceClaims): User.Type=="application" ALONE is forgeable
// (AddUser/UpdateUser persist arbitrary Type), so all four fields are required.
// The strongest is User.Name==application.Name — a tenant-admin-promoted user
// can never carry name==app.name without already owning the matching
// application (== already holding the client_credentials secret).

package object

// IsClientCredentialsClaim reports whether verified `claims` (already
// signature-checked against `application`'s cert) is a genuine
// client_credentials confidential-client token — i.e. the synthetic
// application-user minted by GetClientCredentialsToken, not a human user JWT
// (authorization_code / password) that merely carries Type="application".
//
// Pure: no DB, no session. `claims` MUST already be signature-verified by the
// caller; this only inspects the claim shape.
func IsClientCredentialsClaim(claims *Claims, application *Application) bool {
	if claims == nil || claims.User == nil || application == nil {
		return false
	}
	// The four-field shape lives in ONE place (isClientCredentialsShape): Type
	// alone is forgeable (AddUser/UpdateUser persist arbitrary Type), so it also
	// requires name==app.Name (the strongest — a promoted user cannot carry it
	// without already owning the app) plus provider=="" and signinMethod=="" (a
	// client_credentials grant involves no IdP and is not a sign-in). The
	// billing_account producer resolves machine-ness at MINT time through the same
	// predicate, so the inbound check and the mint decision can never disagree.
	return isClientCredentialsShape(claims.User, application, claims.Provider, claims.SigninMethod)
}
