// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package bootstrap serves the operator-driven service-account provisioning
// endpoints — `POST /v1/iam/admin/{applications,users}/upsert`. The Hanzo K8s
// operator (operator-core) reconciles an IAM CR's spec.applications[]/users[] here,
// binding the service-account OAuth apps that KMS/signers authenticate with, with NO
// human admin in the loop. It is idempotent (create OR update by the natural key)
// so a ~30s reconcile is a no-op once converged.
//
// Auth is a UNIFIED SERVICE TOKEN presented as `Authorization: Bearer <token>`,
// validated constant-time against the first non-empty of HANZO_API_KEY /
// KMS_SERVICE_TOKEN / IAM_SERVICE_TOKEN — the same pipeline the old iam used. The
// token is system-level (bypasses the org-membership gate), so these routes live in
// the PUBLIC group (before the Guard) and self-authenticate here. An unset token
// fails closed: no service token configured → no bootstrap.
//
// Both are TYPED ops, so the credential is DECLARED — `header:"Authorization"` on
// the input — rather than read out of a request the op cannot see. That is what
// makes them ops at all: a fact no projection can read is not a fact the API has,
// and the document, the tool schema and the command now all name the header the
// call needs. It carries `json:"-"`, so the body and the query string cannot
// supply it; a transport with no headers (MCP, the call plane) presents nothing
// and is refused, which is the same fail-closed answer an unset token gets.
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/httpx"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the bootstrap upsert endpoints on the PUBLIC group r (they
// self-authenticate via the service token, not a bearer principal).
//
// r is the CONCRETE *zip.App a group already is: zipdoc resolves an op's path
// prefix STATICALLY and cannot see through a zip.Router parameter, so a typed op
// registered on one would have its doc comment filed under the wrong path and
// dropped from both the document and the MCP tool. The prefix is empty either
// way; nothing about the mount changes.
//
// Every status each op can answer is DECLARED, because zip refuses one that is
// not — and because the document publishes exactly this set, so a generated
// client has a branch for each. These two answer their refusals in their own
// envelope (see reply), which is what a declared non-2xx is for.
func Route(r *zip.App, db orm.DB) {
	zip.Post[registration, reply](r, "/v1/iam/admin/applications/upsert", upsertApplication(db),
		zip.WithOperationID("upsertApplication"),
		zip.WithStatus(200, 400, 401, 500),
		zip.WithTags("bootstrap"))

	zip.Post[person, reply](r, "/v1/iam/admin/users/upsert", upsertUser(db),
		zip.WithOperationID("upsertUser"),
		zip.WithStatus(200, 400, 401, 500),
		zip.WithTags("bootstrap"))
}

// reply is what both upserts answer, and the STATUS it rides on — this surface's
// envelope as a VALUE, because a typed op returns its answer instead of writing
// one. It is NOT httpx.Answer: these two predate that envelope and say `action`
// (created or updated) where it says `code`, and carry no `data` at all on a
// refusal. The operator parses this shape, so it is the shape that stays.
//
// The fields are in alphabetical order deliberately. Each of these bodies used to
// be a map[string]any, encoding/json sorts a map's keys, and the wire may not move
// under an operator that is already parsing it — so the struct emits the same
// bytes in the same order.
type reply struct {
	Action string `json:"action,omitempty"`
	Data   any    `json:"data,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Status string `json:"status"`

	code int
}

// StatusCode is [zip.StatusCoder]: the status this answer rides on. Zero means
// the answer never named one, and 200 is what an unnamed answer has always been.
func (r *reply) StatusCode() int {
	if r.code == 0 {
		return 200
	}
	return r.code
}

// done is the 200 {status:"ok", action, data} answer — created or updated, and
// what the upsert left behind.
func done(action string, data any) *reply {
	return &reply{Action: action, Data: data, Status: "ok", code: 200}
}

// refuse is the {status:"error", msg} answer under the status that matches it.
// ONE function writes a refusal here; every one below names its status.
//
// It returns a VALUE rather than an error, and that is the whole contract: a
// non-nil error renders zip's own {status,error} envelope, which is not what this
// surface has ever answered.
func refuse(status int, msg string) *reply {
	return &reply{Msg: msg, Status: "error", code: status}
}

// credential is what an application upsert answers with: the registration as it
// now stands, including the client secret — the operator is the caller, and this
// is where it learns a secret it did not send. Alphabetical, per reply.
type credential struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
}

// account is what a user upsert answers with: the natural key of the row it
// created or updated — the name as STORED, which the username rule may have
// rewritten. Alphabetical, per reply.
type account struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

// decoded is what happened when the request body was read, carried on the input
// because the handler is the only thing that may answer for it.
//
// zip renders a decode failure as its own {status,error} envelope and skips the
// decoder entirely when there is no body — so an op that does neither has to learn
// both facts itself. Unexported, so it is on no wire and in no schema.
type decoded struct {
	sent bool
	err  error
}

// check is the refusal a body earns before a handler looks at it, or nil when it
// arrived and parsed. The two sentences are the ones this surface has always
// answered.
func (d decoded) check() *reply {
	switch {
	case !d.sent:
		return refuse(400, "invalid body: empty request body")
	case d.err != nil:
		return refuse(400, "invalid body: "+d.err.Error())
	}
	return nil
}

// registration is the application an operator declares (operator-core's
// UpsertRequest), plus the service credential it presents.
type registration struct {
	Organization string   `json:"organization"`
	Name         string   `json:"name"`
	ClientId     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	GrantTypes   []string `json:"grantTypes"`
	RedirectUris []string `json:"redirectUris"`
	DisplayName  string   `json:"displayName"`
	Cert         string   `json:"cert"`
	// Public declares a client that CANNOT hold a credential — a browser SPA,
	// a CLI, a desktop app. It proves itself with PKCE instead, and the token
	// endpoint treats "no stored secret" as exactly that (token.go: a secret is
	// verified only when one is stored). Without this flag every upsert minted
	// a secret, so a public client could never be registered at all and its
	// browser code->token exchange 401'd `invalid_client` forever.
	Public bool `json:"public"`
	// IsShared declares that this application serves EVERY organization, not only
	// the one named in Organization. It is the honest description of a brand app —
	// hanzo-id, hanzo-chat, a brand console — whose customers each live in their own
	// tenant: self-service onboarding moves a founder OUT of the brand org, so
	// `user.Owner != app.Organization` is the steady state and the app really does
	// serve every org. Application.ServesOrg reads it as one of the three ways to
	// say yes.
	//
	// A POINTER because omission must PRESERVE. This upsert is the operator's
	// steady-state reconcile and most callers say nothing about sharing; a plain
	// bool would read as false on every one of them and silently un-share an app —
	// the same shape of accident that de-secreted apps through update-application.
	// Nil means "not stated, leave it"; only an explicit true or false moves it.
	IsShared *bool `json:"isShared"`
	// ExpireInHours and RefreshExpireInHours are the application's token
	// lifetimes. They are the ONLY declarative way to say that a refresh token
	// must OUTLIVE its access token: with neither stated, oidc.refreshTTL clamps
	// the refresh lifetime to the access lifetime, so the refresh_token grant the
	// registration advertises expires at the same instant as the token it was
	// meant to renew and can never be exercised. `hanzo-cli` sat in exactly that
	// state — a browser re-login every hour, and a live refresh returning 401.
	//
	// POINTERS, for the same reason as IsShared: a plain float would read as 0 on
	// every reconcile that says nothing and reset a deliberate lifetime back to
	// the default. Nil means "not stated, leave it".
	ExpireInHours        *float64 `json:"expireInHours"`
	RefreshExpireInHours *float64 `json:"refreshExpireInHours"`
	// EnableCodeSignin offers sign-in by an emailed or texted one-time code
	// beside the password. A POINTER for the same reason as IsShared: a plain
	// bool reads as false on every reconcile that says nothing and would switch
	// the method off for every app whose caller never mentioned it.
	EnableCodeSignin *bool `json:"enableCodeSignin"`
	// Auth is the `Authorization: Bearer <token>` header, the unified service
	// token this surface authenticates on. `json:"-"` keeps it off the body and
	// out of the query string, so the header is the only way to present it.
	Auth string `json:"-" header:"Authorization"`

	decoded
}

// UnmarshalJSON decodes the body and RECORDS the outcome instead of failing on it,
// so the handler stays the only thing that answers — see decoded.
//
// `body` is the same fields with none of the methods, which is what keeps this
// from calling itself. It is also what a mismatched field is reported against, so
// the message names the body rather than a Go type the caller has never heard of.
func (r *registration) UnmarshalJSON(b []byte) error {
	type body registration
	var v body
	err := json.Unmarshal(b, &v)
	*r = registration(v)
	r.decoded = decoded{sent: true, err: err}
	return nil
}

// upsertApplication creates an application or updates it in place, so a
// deployment can declare the applications it needs and run the same declaration
// on every environment and on every redeploy.
//
// It says which of the two it did. Leave the client secret out and the existing
// one is kept — so re-running your deployment does not rotate a credential your
// running services are holding.
func upsertApplication(db orm.DB) zip.TypedHandler[registration, reply] {
	return func(ctx context.Context, in *registration) (*reply, error) {
		if !httpx.ServiceAuth(in.Auth) {
			return refuse(401, "a valid service token is required"), nil
		}
		if bad := in.check(); bad != nil {
			return bad, nil
		}
		if strings.TrimSpace(in.Name) == "" {
			return refuse(400, "name is required"), nil
		}
		// Both names are stored as they arrive — see verbatim. The organization is
		// not decoration on a registration: resolveCert derives this app's signing
		// identity from it, so a spelling that is only a reserved org once it has
		// been stored signs with that org's cert.
		if bad := verbatim("name", in.Name); bad != nil {
			return bad, nil
		}
		if bad := verbatim("organization", in.Organization); bad != nil {
			return bad, nil
		}

		existing, err := store.GetApplicationByName(ctx, db, "admin", in.Name)
		if err != nil {
			return refuse(500, "server_error"), nil
		}
		var existingSecret string
		if existing != nil {
			existingSecret = existing.ClientSecret
		}
		in.ClientSecret = resolveSecret(in.Public, in.ClientSecret, existing != nil, existingSecret)
		if in.ClientId == "" {
			in.ClientId = in.Name // <org>-<app> convention: clientId == name
		}

		action := "created"
		if existing != nil {
			action = "updated"
			existing.ClientId = in.ClientId
			existing.ClientSecret = in.ClientSecret
			existing.Organization = pick(in.Organization, existing.Organization)
			if in.DisplayName != "" {
				existing.DisplayName = in.DisplayName
			}
			if len(in.GrantTypes) > 0 {
				existing.GrantTypes = in.GrantTypes
			}
			if len(in.RedirectUris) > 0 {
				existing.RedirectUris = in.RedirectUris
			}
			if in.Cert != "" {
				existing.Cert = in.Cert
			}
			if in.IsShared != nil {
				existing.IsShared = *in.IsShared
			}
			if in.EnableCodeSignin != nil {
				existing.EnableCodeSignin = *in.EnableCodeSignin
			}
			existing.ExpireInHours = ttl(in.ExpireInHours, existing.ExpireInHours)
			existing.RefreshExpireInHours = ttl(in.RefreshExpireInHours, existing.RefreshExpireInHours)
			existing.EnablePassword = true
			if err := existing.UpdateCtx(ctx); err != nil {
				return refuse(500, "server_error"), nil
			}
		} else {
			// A new application must NAME a signing cert, or it is not a
			// registration — it is a login that fails after the user has already
			// authenticated. Resolved here, where "brand new" is known, rather
			// than left to be discovered at the token endpoint.
			//
			// The cert ROW is deliberately not required to exist yet: an app that
			// records `cert-hanzo` signs correctly the moment that cert does,
			// whereas demanding it up front would order application creation
			// behind cert seeding and break a first-boot reconcile that has not
			// reached the certs. The name is the durable fact; its resolution is
			// the token endpoint's job.
			if in.Cert = resolveCert(in.Cert, in.Organization); in.Cert == "" {
				return refuse(400, fmt.Sprintf(
					"application %q would have no signing cert and no organization to "+
						"derive one from, so it could never issue a token: state `cert`",
					in.Name)), nil
			}
			a := orm.New[schema.Application](db)
			model := a.Model
			a.Owner, a.Name = "admin", in.Name
			a.ClientId, a.ClientSecret = in.ClientId, in.ClientSecret
			a.Organization, a.DisplayName = in.Organization, pick(in.DisplayName, in.Name)
			a.GrantTypes, a.RedirectUris, a.Cert = in.GrantTypes, in.RedirectUris, in.Cert
			a.EnablePassword = true
			a.ExpireInHours = ttl(in.ExpireInHours, schema.DefaultExpireInHours)
			a.RefreshExpireInHours = ttl(in.RefreshExpireInHours, 0)
			// A new app is single-tenant unless it says otherwise — fail closed.
			a.IsShared = in.IsShared != nil && *in.IsShared
			// Same rule for code sign-in: a new app offers only the password until
			// it asks for more, so an unstated setting is off rather than inherited
			// from a default nobody wrote down.
			a.EnableCodeSignin = in.EnableCodeSignin != nil && *in.EnableCodeSignin
			a.Model = model
			a.SetId("admin/" + in.Name)
			if err := a.CreateCtx(ctx); err != nil {
				return refuse(500, "server_error"), nil
			}
		}
		return done(action, &credential{
			ClientId: in.ClientId, ClientSecret: in.ClientSecret,
			Name: in.Name, Organization: in.Organization,
		}), nil
	}
}

// person is the user an operator declares, plus the service credential it
// presents.
type person struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Password     string `json:"password"`
	PasswordType string `json:"passwordType"`
	IsAdmin      bool   `json:"isAdmin"`
	// Auth is the `Authorization: Bearer <token>` header — see registration.Auth.
	Auth string `json:"-" header:"Authorization"`

	decoded
}

// UnmarshalJSON decodes the body and RECORDS the outcome — see registration's.
func (p *person) UnmarshalJSON(b []byte) error {
	type body person
	var v body
	err := json.Unmarshal(b, &v)
	*p = person(v)
	p.decoded = decoded{sent: true, err: err}
	return nil
}

// upsertUser creates a person or updates them in place, so a deployment can
// declare the accounts it needs and re-run that declaration safely.
//
// It DESCRIBES an account it meets and GRANTS only to one it creates: org-admin is
// never raised on a row that already exists, and a machine identity is answered by
// name rather than adopted. Both are properties of the update itself, so a
// steady-state reconcile — which changes neither — is unaffected.
//
// Passwords are hashed before they are stored. Leave the password out and their
// current one is kept, so a redeploy never locks somebody out; send the same one
// again and it is kept too, so a steady-state re-run is not a rotation.
func upsertUser(db orm.DB) zip.TypedHandler[person, reply] {
	return func(ctx context.Context, in *person) (*reply, error) {
		if !httpx.ServiceAuth(in.Auth) {
			return refuse(401, "a valid service token is required"), nil
		}
		if bad := in.check(); bad != nil {
			return bad, nil
		}
		if strings.TrimSpace(in.Owner) == "" || strings.TrimSpace(in.Name) == "" {
			return refuse(400, "owner and name are required"), nil
		}
		// The row is filed under both names, so both are stored as they arrive —
		// see verbatim. The owner is the account's TENANCY, and belonging to the
		// reserved org is SuperAdmin (store.IsSuperAdmin), so the tenant a name
		// resolves to is the whole of what this account is.
		if bad := verbatim("owner", in.Owner); bad != nil {
			return bad, nil
		}
		if bad := verbatim("name", in.Name); bad != nil {
			return bad, nil
		}

		existing, err := store.GetUserByName(ctx, db, in.Owner, in.Name)
		if err != nil {
			return refuse(500, "server_error"), nil
		}
		action := "created"
		if existing != nil {
			action = "updated"
			// A machine identity is not declarable. internal/serviceaccounts mints
			// one whole: it derives the canonical <org>-<agent> name, binds the agent
			// and issues the KEY the machine authenticates with — and refuses a
			// collision with any principal, so nothing this endpoint created can be
			// taken over from that side either. A declaration carries a password,
			// which is how a PERSON proves themselves; writing one onto a machine row
			// gives it a second kind of credential nobody minted. So a machine row is
			// answered by name, and this endpoint stamps no machine class on a row it
			// creates — the two surfaces make different things and neither writes the
			// other's.
			if existing.Machine() {
				return refuse(400, fmt.Sprintf(
					"account %s/%s is a machine identity, which is minted with its key by the "+
						"service-account surface: a password declaration does not describe one",
					in.Owner, in.Name)), nil
			}
			// A declaration GRANTS org-admin only to an account it creates. Raising
			// the bit is the one thing an update does that hands a principal authority
			// it did not have, and this endpoint has no fact that says which rows are
			// its own: every account it has ever created carries no class at all, so
			// "did I make this?" is unanswerable. The TRANSITION is answerable, and it
			// is the half that matters — leaving the bit where it was found grants
			// nothing, which is exactly what every steady-state reconcile does.
			// Lowering it stays open: a revocation is safe from any caller.
			if in.IsAdmin && !existing.IsAdmin {
				return refuse(400, fmt.Sprintf(
					"account %s/%s already exists without org-admin, and a declaration grants "+
						"it only to an account it creates", in.Owner, in.Name)), nil
			}
			display, email := pick(in.DisplayName, existing.DisplayName), store.NormalizeEmail(pick(in.Email, existing.Email))
			phone := store.NormalizePhone(pick(in.Phone, existing.Phone))
			// A declaration presents the same credential on every run, so an unchanged
			// one is recognised by VERIFYING the material against the stored digest
			// rather than by its absence. A digest carries a fresh random salt, so
			// re-hashing what is already there yields a different string and turns
			// every steady-state reconcile into a rotation of a credential the running
			// services still hold. Material that does not verify is new, and rotates.
			hash, kind := existing.PasswordHash, existing.PasswordType
			if in.Password != "" && !cred.Verify(kind, in.Password, hash) {
				h, err := cred.Hash(in.Password)
				if err != nil {
					return refuse(500, "server_error"), nil
				}
				hash, kind = h, cred.TypeArgon2id
			}
			// Nothing moved, so nothing is written: a converge that rewrites an
			// unchanged row makes `updatedTime` say when the reconciler last ran
			// rather than when the account last changed.
			if display != existing.DisplayName || email != existing.Email || phone != existing.Phone ||
				in.IsAdmin != existing.IsAdmin || hash != existing.PasswordHash {
				existing.DisplayName, existing.Email, existing.Phone = display, email, phone
				existing.IsAdmin = in.IsAdmin
				existing.PasswordHash, existing.PasswordType, existing.PasswordSalt = hash, kind, ""
				existing.UpdatedTime = now()
				if err := existing.UpdateCtx(ctx); err != nil {
					return refuse(500, "server_error"), nil
				}
			}
		} else {
			var hash string
			if in.Password != "" {
				h, err := cred.Hash(in.Password)
				if err != nil {
					return refuse(500, "server_error"), nil
				}
				hash = h
			}
			// A new row obeys THE username rule; an existing one is found above and
			// merely updated, so a legacy name is never rewritten by an upsert that
			// happened to touch it. This path writes through orm directly rather than
			// users.Create (it seeds the first admin, before any principal exists), so
			// it states the rule itself — the one place that has to.
			name, err := schema.Username(in.Name)
			if err != nil {
				return refuse(400, err.Error()), nil
			}
			in.Name = name // the id and the response report what was STORED
			u := orm.New[schema.User](db)
			model := u.Model
			u.Owner, u.Name = in.Owner, name
			u.DisplayName, u.Email, u.Phone, u.IsAdmin = in.DisplayName, store.NormalizeEmail(in.Email), store.NormalizePhone(in.Phone), in.IsAdmin
			if hash != "" {
				u.PasswordHash, u.PasswordType = hash, cred.TypeArgon2id
			}
			u.CreatedTime, u.UpdatedTime = now(), now()
			u.Model = model
			u.SetId(in.Owner + "/" + in.Name)
			if err := u.CreateCtx(ctx); err != nil {
				return refuse(500, "server_error"), nil
			}
		}
		return done(action, &account{Name: in.Name, Owner: in.Owner}), nil
	}
}

// ---- helpers ----

// verbatim refuses a name that is not the name it would be STORED under: what the
// caller sent, what a reviewer reads in the plan, and what the row is filed as are
// one string or the request is answered.
//
// A trim is not a courtesy here, it is a second spelling. The predicates that
// decide what an identity IS ask by name — policy.IsReservedOrg("admin ") is false
// and store.IsSuperAdmin("admin") is true — so a padded name passes the boundary
// as one tenant and lands in another, and the declaration that reached the
// reserved org never spells it. Refused rather than normalized: silently
// rewriting a name into a tenant nobody wrote down is the outcome being avoided,
// not a convenience, and there is nothing here to be tolerant about — every
// caller composes these names from its own configuration.
//
// It is stated at the ENDPOINT because that is the boundary both callers cross.
// The CLI parses a document; the K8s operator reconciles an IAM CR's spec.users[]
// straight to this route and crosses no parser at all, so a rule kept in the
// document's own validator answers for only one of the two.
func verbatim(field, raw string) *reply {
	if name := strings.TrimSpace(raw); name != raw {
		return refuse(400, fmt.Sprintf(
			"%s %q is not the name it would be stored under (%q)", field, raw, name))
	}
	return nil
}

// resolveSecret decides the credential an upsert stores. It is the ONE place
// public-vs-confidential is settled, split out so the rule is testable without
// a store:
//
//   - public       -> NO secret. That absence is exactly what the token endpoint
//     reads as "PKCE, do not demand client auth", so it must also
//     CLEAR one left by an earlier confidential registration.
//   - explicit     -> honour it; rotation is deliberate.
//   - existing app -> preserve what it has, INCLUDING an empty secret. Minting
//     one because "the stored secret is empty" would silently
//     turn a public client confidential on the next reconcile.
//   - brand new    -> mint one.
func resolveSecret(public bool, requested string, hasExisting bool, existing string) string {
	switch {
	case public:
		return ""
	case requested != "":
		return requested
	case hasExisting:
		return existing
	default:
		return randomSecret()
	}
}

// resolveCert decides the signing cert a NEW application is created with. Same
// shape as resolveSecret, and split out for the same reason: it is the ONE place
// the rule lives.
//
// It is not cosmetic, and it fails LATE if it is wrong. issueTokens resolves
// app.Cert to sign, so an application created without one authenticates the user,
// mints an authorization code, redeems it — and only then discovers it has
// nothing to sign with, answering the token exchange `500 server_error`. From the
// browser that is indistinguishable from an outage, which is why a new application
// is created able to sign rather than left to fail at the exchange.
//
//   - requested -> honour it.
//   - otherwise -> the organization's own cert. Every application here already
//     follows one signing identity per org (`cert-hanzo`, `cert-lux`,
//     `cert-adnexus`…), so the default is that convention, not an invention.
//
// The caller VERIFIES the result resolves to a real cert and refuses the
// registration otherwise. Only the create path consults this: on an existing
// application a blank request means "not stated", never "clear it", which is what
// lets a document add the field without rotating anything.
func resolveCert(requested, org string) string {
	if r := strings.TrimSpace(requested); r != "" {
		return r
	}
	if org = strings.TrimSpace(org); org != "" {
		return "cert-" + org
	}
	return ""
}

// ttl applies an optionally-declared token lifetime: nil PRESERVES cur (an
// omitted field never resets a deliberate lifetime on a steady-state reconcile),
// a stated value wins — including an explicit 0, which is how a document says
// "back to the default".
func ttl(declared *float64, cur float64) float64 {
	if declared == nil {
		return cur
	}
	return *declared
}

// pick returns a if non-empty (trimmed), else b.
func pick(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// randomSecret returns a 32-byte URL-safe random client secret.
func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
