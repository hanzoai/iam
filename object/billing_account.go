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

import "strings"

// The billing_account claim — IAM's signed, authoritative statement of WHO PAYS
// for a credential, decided HERE at the identity boundary from the real auth
// context (the grant that minted the token), never from a user-writable field.
//
// It is the producer half of a wire contract that ai/object.Payer consumes: the
// string emitted here, `<kind>:<subject>`, is exactly what ParseAccount there
// reads back into an Account. The two repos share NO code, so this grammar IS the
// contract and must stay stable:
//
//	billing_account := kind ":" subject
//	kind            := "person" | "org" | "project"
//	subject         := owner                 ; for kind=org
//	                 | owner "/" name         ; for kind=person or kind=project
//
// e.g. "org:acme", "person:hanzo/alice", "project:acme/website". owner and name
// are folded (lower-cased, trimmed) so the string the gateway mints into
// X-Billing-Account-Id matches the folded ledger key ai keys its balance on.
//
// The `<kind>:` prefixes MUST match ai/object's Kind constants byte-for-byte.
const (
	accountPerson  = "person"
	accountOrg     = "org"
	accountProject = "project"
)

// billingAccountClaim returns the billing_account claim for a token being minted
// from (user, application) under a given grant (provider/signinMethod) and project
// scope. It is the ONE mint-site for the claim.
//
// The rule mirrors ai/object.Payer, with the ONE difference that is the whole
// point of this producer: machine-ness is resolved from the client_credentials
// GRANT SHAPE (isClientCredentialsShape — the four correlated fields), not the
// lone User.Type, which IAM's own UpdateUser lets a user set. So a member of the
// shared signup org who forges Type="application" can no longer be minted as a
// machine and reach the org pool: IAM states, over its signature, that they pay
// from their own person account.
//
//	client_credentials (a machine)  → org:<owner>            (it IS the org)
//	a non-default project scope     → project:<owner>/<proj>
//	a person in the signup org      → person:<owner>/<name>
//	anyone else (a real-org member) → org:<owner>
//
// Empty owner ⟹ "" (unattributable — the token carries no payer, and Payer's
// legacy fallback also refuses to bill it, so the claim is simply omitted).
func billingAccountClaim(user *User, application *Application, provider, signinMethod, project string) string {
	if user == nil {
		return ""
	}
	owner := strings.ToLower(strings.TrimSpace(user.Owner))
	if owner == "" {
		return ""
	}
	// A non-default project scope pays from the project account. Dormant until a
	// project-scoped grant mints a non-default `project`: today every token carries
	// the org's DEFAULT project, which falls through to the org/person rule below.
	if p := strings.ToLower(strings.TrimSpace(project)); p != "" && p != DefaultProjectName {
		return accountProject + ":" + owner + "/" + p
	}
	// A genuine client_credentials confidential client pays from its org — resolved
	// from the grant shape, not the forgeable Type alone.
	if isClientCredentialsShape(user, application, provider, signinMethod) {
		return accountOrg + ":" + owner
	}
	// A person in the shared signup org pays from their OWN account (its members are
	// strangers, not a team). Everyone else pools on their org.
	if owner == strings.ToLower(DefaultOrganization) {
		if name := strings.ToLower(strings.TrimSpace(user.Name)); name != "" {
			return accountPerson + ":" + owner + "/" + name
		}
	}
	return accountOrg + ":" + owner
}

// isClientCredentialsShape is the four-field client_credentials discriminator
// evaluated at MINT time from the raw grant inputs: Type=="application" AND
// name==app.Name AND provider=="" AND signinMethod=="". It is the SAME shape
// IsClientCredentialsClaim enforces on an INBOUND token, factored to one place so
// the mint decision and the inbound check can never disagree — Type alone is
// forgeable (AddUser/UpdateUser persist arbitrary Type), so all four are required.
func isClientCredentialsShape(user *User, application *Application, provider, signinMethod string) bool {
	if user == nil || application == nil {
		return false
	}
	return user.Type == "application" &&
		user.Name == application.Name &&
		provider == "" &&
		signinMethod == ""
}
