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

// Internal machine identities — the confidential "<org>-iam" clients IAM
// provisions for authenticating to downstream Hanzo services (first consumer:
// OTP delivery to cloud's notify over ZAP). Their client_credentials token is
// minted ONLY IN-PROCESS by object.serviceTokenSource (IAM is the issuer). The
// PUBLIC /oauth/token endpoint must REFUSE client_credentials for them, so a
// leaked or guessed app secret cannot mint the token from outside the cluster.
//
// This is the security boundary that makes the app secret non-load-bearing: even
// with the secret, an external caller cannot obtain the token, because the only
// grant path (the public endpoint) rejects the identity and the in-process minter
// is unreachable off-process.

// InternalServiceAppMarker is the sentinel written to an internal machine app's
// Description at provisioning (cmd/iam/cli init-apps buildIAMServiceApp). It is the
// explicit, greppable predicate the public token endpoint gates on.
const InternalServiceAppMarker = "hanzo:internal-service-identity"

// IsInternalServiceApplication reports whether app is an IAM-provisioned internal
// machine identity whose client_credentials grant must be refused on the PUBLIC
// token endpoint (minted in-process only).
//
// It is TRUE when EITHER the explicit marker is present (primary) OR the app
// follows the reserved "<org>-iam" naming (fallback, so stripping the Description
// cannot re-open the public grant). Admin-only app creation owns this namespace.
func IsInternalServiceApplication(app *Application) bool {
	if app == nil {
		return false
	}
	if app.Description == InternalServiceAppMarker {
		return true
	}
	return app.Organization != "" && app.Name == app.Organization+"-iam"
}
