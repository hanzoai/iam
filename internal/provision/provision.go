// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package provision converges an IAM instance onto a declarative org+app
// document. It is the MECHANISM half of provisioning and ships ZERO brands:
// every org, app and host is DATA, owned by that org's own universe repo and
// handed in as --config. One implementation, N org documents.
//
// The convergence primitive already exists — POST /v1/iam/admin/applications/
// upsert (package bootstrap) is idempotent by natural key and PRESERVES an
// existing clientSecret when the request omits it. That is what makes a re-run
// a no-op instead of a credential rotation, and it is why this package never
// sends a secret: the server owns secret lifecycle, the document owns shape.
//
// Everything an OAuth client needs is DERIVED from two fields — the app's name
// and its type — so a document line stays one line:
//
//	clientId  ALWAYS <org>-<app>   (HIP-0111; the upsert keys Name==ClientId)
//	redirects per type, per host, from the table in Derive
//
// Deriving rather than spelling out redirect URIs is the point: hand-written
// URI lists are how registrations drift from the app that actually calls them,
// which presents as `invalid_client`/`redirect_uri_mismatch` long after the
// change that caused it.
//
// Derivation is the default, not the whole vocabulary. A real client can hold
// a URI no rule can produce — a desktop deep link, a loopback dev port, a
// second callback path on a host that already has one — and the upsert
// REPLACES the URI list rather than merging it. A document that cannot say
// those URIs therefore deletes them on the next converge. App.Redirects and
// App.Grants are the additive escape hatch for exactly that: the derived set
// plus the declared exceptions, each one visible in review.
package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/hanzoai/iam/pkg/schema"
)

// Doc is a provision document: the complete app graph for one or more orgs.
type Doc struct {
	Orgs []Org `yaml:"orgs"`
}

// Org is one tenant and the apps that authenticate against it.
type Org struct {
	Name           string `yaml:"name"`
	DisplayName    string `yaml:"displayName"`
	Homepage       string `yaml:"homepage"`
	DeepLinkScheme string `yaml:"deepLinkScheme"`
	// Accounts are the org's USER rows — the humans and the machines that hold an
	// identity in this org, as opposed to `apps`, which are the OAuth clients an
	// identity authenticates THROUGH. They are declared here beside the org, not
	// inside `apps`, because an account belongs to the ORG and never to an app.
	// Optional so an org that manages its accounts elsewhere parses unchanged
	// (the document is decoded with yaml.Strict(), so an undeclared field is a
	// hard error, not a silent skip).
	Accounts []Account `yaml:"accounts"`
	Apps     []App     `yaml:"apps"`
}

// Account is one user row, declared as data so it converges like every client
// does. There is ONE vocabulary for an account and `type` says what it IS —
// exactly as `type` does for an app — so the human superuser and the machine
// identity are one declaration shape with one validator, one derivation and one
// apply loop, rather than two that can drift apart.
//
// The password is NEVER in the document. PasswordRef names where it lives
// (`kms://<path>`), the reconciler resolves it at apply time from the credential
// material the KMS→KMSSecret→Secret sync has already delivered, and IAM stores
// only an argon2id hash. A converge that resolves no secret PRESERVES the
// existing credential rather than clearing it, so re-running never locks an
// account out of a live tenant.
type Account struct {
	// Name is the IAM username — the `name` half of <owner>/<name>. It is stated,
	// never derived from the email, because a service account has no email to
	// derive one from and one rule for both is the point of this type.
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	// Email is the human's login identifier and recovery address. A `service`
	// account must NOT declare one: see Validate.
	Email       string `yaml:"email"`
	DisplayName string `yaml:"displayName"`
	// PasswordRef is a `kms://<path>` locator, never a literal password. A
	// literal is rejected: a credential in a git-tracked file is a leak the
	// moment it is written, and this file is git-tracked by design.
	PasswordRef string `yaml:"passwordRef"`
}

// Account types. `owner` is the org's ONE human superuser — there is no built-in
// admin, the seeded owner IS the admin. `service` is a non-interactive machine
// identity for privileged automation.
const (
	AccountOwner   = "owner"
	AccountService = "service"
)

// isAdminByAccountType is the IAM `isAdmin` bit each type is provisioned with.
//
// A `service` account gets FALSE, and that is least privilege rather than an
// oversight: platform authority is MEMBERSHIP of the reserved admin org
// (authz.Claims.PlatformSudo walks the signed `orgs` set and never reads
// isAdmin), so a service account declared under the admin org holds full
// platform sudo with the bit clear. The bit is a strictly ADDITIONAL grant —
// authz.Claims.OrgAdmin reads `IsAdmin && org == Home()` — so setting it on a
// machine would hand it org-admin self-service it has no use for.
var isAdminByAccountType = map[string]bool{
	AccountOwner:   true,
	AccountService: false,
}

// Validate rejects an account that is unusable or unsafe to apply. It runs at
// PARSE time so a malformed account fails the plan a reviewer reads, rather than
// halfway through mutating a live tenant.
func (a *Account) Validate(org string) error {
	where := fmt.Sprintf("provision: org %s: account %q", org, a.Name)
	if _, ok := isAdminByAccountType[a.Type]; !ok {
		return fmt.Errorf("%s has unknown type %q (want %s or %s)", where, a.Type, AccountOwner, AccountService)
	}
	// THE username rule, asked of the document rather than discovered on the
	// server: a name the store would rewrite is a name this document no longer
	// describes, and the next converge would create a second account beside it.
	if name, err := schema.Username(a.Name); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	} else if name != a.Name {
		return fmt.Errorf("%s is not the name it would be stored under (%q)", where, name)
	}
	switch a.Type {
	case AccountOwner:
		if !strings.Contains(a.Email, "@") {
			return fmt.Errorf("%s: email %q is not an email address", where, a.Email)
		}
	case AccountService:
		// A machine has no mailbox, so an email on one is attack surface with no
		// benefit. Email is an IDENTIFIER that resolves to an account —
		// store.GetUserByEmail backs the email login identifier (oidc/login.go),
		// the emailed verification code (oidc/sendverificationcode.go) and the
		// federated-identity link (oidc/federation.go step 2) — so an address on a
		// platform-sudo account is a second, mailbox-shaped way to become it.
		// Reserved orgs already refuse federation (federationOrgAllowed →
		// store.IsReservedOrg), which is why this is defence in depth and not the
		// only control; a service account simply has nothing to gain by carrying
		// one, and the cheapest time to say so is here.
		if a.Email != "" {
			return fmt.Errorf("%s is a machine identity and must not declare an email — "+
				"an address is a second way to resolve this account (login identifier, "+
				"emailed code, federated link) and a machine has no mailbox to defend", where)
		}
	}
	return credentialRef(a.PasswordRef, where)
}

// credentialRef validates a `kms://<path>` locator and returns the bare path.
//
// The path is what the reconciler joins onto its credential directory, so a
// traversing or absolute ref would read a file the document never named — which
// is how a credential locator becomes an arbitrary-file-read. Rejected at parse
// time, in the ONE place a ref is understood.
func credentialRef(ref, where string) error {
	_, err := credentialPath(ref, where)
	return err
}

func credentialPath(ref, where string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("%s: passwordRef is required (kms://<path>)", where)
	}
	if !strings.HasPrefix(ref, "kms://") {
		return "", fmt.Errorf(
			"%s: passwordRef must be a kms:// locator, got %q — a password literal must never live in this document",
			where, ref)
	}
	p := strings.TrimPrefix(ref, "kms://")
	if p == "" || p != path.Clean(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("%s: passwordRef %q is not a clean relative KMS path", where, ref)
	}
	return p, nil
}

// App is one OAuth client, declared by name + type + the hosts it is served on.
type App struct {
	App   string   `yaml:"app"`
	Type  string   `yaml:"type"`
	Hosts []string `yaml:"hosts"`
	// Cert names the signing cert this app's tokens are issued under. It is not
	// cosmetic: issueTokens resolves app.Cert to sign, so a client registered
	// without one cannot mint an id_token, and an OIDC library that needs the
	// id_token to identify the user fails AFTER a successful code exchange —
	// the confusing "cannot get user information without id_token" class. Empty
	// leaves whatever the app already has, so adding this field rotates nothing.
	Cert string `yaml:"cert"`
	// Callback overrides the standard browser callback path for a server whose
	// redirect URI is not ours to choose (Hanzo Git serves
	// /user/oauth2/<source>/callback). Still derived per host, so one host set
	// stays the single source of the URI list.
	Callback string `yaml:"callback"`
	// Redirects are literal redirect URIs APPENDED to the derived set, for the
	// ones derivation cannot know: a desktop deep link whose path is not the
	// app slug, a loopback dev port, a second callback path on a host that
	// already has one. They are additive on purpose — hosts+type stay the
	// default so a document line stays one line, and this field carries only
	// the exceptions, where each URI is visible in review instead of hiding
	// inside a live registration nobody reads.
	//
	// Without it the upsert, which REPLACES redirectUris, silently deletes
	// every live URI a document cannot express — a converge that reports
	// success and takes the logins down with it.
	Redirects []string `yaml:"redirects"`
	// Grants are extra OAuth grants APPENDED to the type's default set, for an
	// app that is genuinely two clients behind one client_id: a browser PKCE
	// surface AND the backend machine identity that authenticates with the same
	// registration (client_credentials), or a device flow. Additive for the
	// same reason as Redirects — the upsert replaces grantTypes wholesale, so a
	// type-derived set is a silent revocation of every grant the type does not
	// name.
	Grants []string `yaml:"grants"`
	// CodeSignin offers sign-in by an emailed or texted one-time code beside the
	// password. A POINTER so saying nothing preserves the app's current setting
	// rather than turning the method off — see Client.EnableCodeSignin.
	CodeSignin *bool `yaml:"codeSignin"`
	// ExpireInHours and RefreshExpireInHours are this client's token lifetimes.
	// Same names as the wire and the stored model, so one value has one name from
	// document to registration.
	//
	// RefreshExpireInHours is the ONLY way to say that a refresh token must
	// OUTLIVE its access token, and saying nothing is not neutral: with it unset
	// the token endpoint clamps the refresh lifetime to the ACCESS lifetime, so
	// the refresh_token grant every interactive type derives expires at the same
	// instant as the token it exists to renew. That is not a short session, it is
	// a dead grant — `hanzo-cli` sat in it, and every command an hour after login
	// reopened a browser. Undeclared (0) is OMITTED from the upsert so a converge
	// preserves whatever the app already has.
	ExpireInHours        float64 `yaml:"expireInHours"`
	RefreshExpireInHours float64 `yaml:"refreshExpireInHours"`
}

// Client is the derived, serialized registration — the body of an upsert call.
// It is deliberately the shape bootstrap.registration accepts, minus the
// secret: see the package comment for why the secret is never sent.
type Client struct {
	Organization string   `json:"organization"`
	Name         string   `json:"name"`
	ClientId     string   `json:"clientId"`
	DisplayName  string   `json:"displayName"`
	GrantTypes   []string `json:"grantTypes"`
	RedirectUris []string `json:"redirectUris"`
	// Public is the whole point of `type`: a browser, CLI or desktop client
	// ships to the user, so it cannot keep a secret and must prove itself with
	// PKCE. IAM reads "no stored secret" as exactly that, so declaring it here
	// is what stops the token endpoint demanding a credential the client could
	// never hold — the `invalid_client` a browser login otherwise dies on.
	Public bool `json:"public"`
	// Cert is the signing cert name. Omitted from the body when empty so the
	// upsert preserves the app's current cert (it assigns only a non-empty one).
	Cert string `json:"cert,omitempty"`
	// Token lifetimes, in hours. POINTERS so an undeclared lifetime is OMITTED
	// and the upsert preserves what the app has — a plain float would send 0 on
	// every converge and reset every app's lifetimes to the default.
	ExpireInHours        *float64 `json:"expireInHours,omitempty"`
	RefreshExpireInHours *float64 `json:"refreshExpireInHours,omitempty"`
	// EnableCodeSignin offers sign-in by an emailed or texted one-time code
	// alongside the password. A POINTER for the same reason the lifetimes are:
	// an undeclared setting is OMITTED and the upsert preserves what the app has,
	// where a plain bool would send false on every converge and silently switch
	// the method off for every app whose document does not mention it.
	//
	// Declaring it true is a request, not a guarantee: the login descriptor also
	// requires the server to have a delivery transport bound, so an app that asks
	// for code sign-in on a deployment that cannot send one still advertises only
	// what it can finish.
	EnableCodeSignin *bool `json:"enableCodeSignin,omitempty"`
}

// App types. A document that names anything else is rejected at Derive rather
// than silently registering a client with no redirects — a client that cannot
// complete a login is worse than a loud parse error.
const (
	TypeSPA          = "spa"
	TypeConfidential = "confidential"
	TypeCLI          = "cli"
	TypeDesktop      = "desktop"
	TypeService      = "service"
)

// callbackPath is the ONE browser redirect path every surface serves. Observed
// uniformly in production across brands (lux.cloud, zoo.cloud,
// platform.hanzo.ai all send exactly https://<host>/auth/callback), so it is
// stated once here instead of per-app in every document.
const callbackPath = "/auth/callback"

// grantsByType is the OAuth grant set each type is allowed to use. Browser
// clients never get client_credentials, and service clients never get an
// interactive grant — that separation is the whole reason `type` exists.
var grantsByType = map[string][]string{
	TypeSPA:          {"authorization_code", "refresh_token"},
	TypeConfidential: {"authorization_code", "refresh_token"},
	TypeCLI:          {"authorization_code", "refresh_token"},
	TypeDesktop:      {"authorization_code", "refresh_token"},
	TypeService:      {"client_credentials"},
}

// publicByType: a client that SHIPS TO THE USER cannot keep a secret. Browser,
// CLI and desktop clients therefore hold none and use PKCE; only a server-side
// app (confidential) or a machine identity (service) can be trusted with one.
var publicByType = map[string]bool{
	TypeSPA:          true,
	TypeCLI:          true,
	TypeDesktop:      true,
	TypeConfidential: false,
	TypeService:      false,
}

// Parse reads a provision document. Unknown fields are an error: a typo'd key
// in a document that silently parses is a client that silently never converges.
func Parse(b []byte) (*Doc, error) {
	var d Doc
	if err := yaml.UnmarshalWithOptions(b, &d, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("provision: parse: %w", err)
	}
	if len(d.Orgs) == 0 {
		return nil, errors.New("provision: document declares no orgs")
	}
	// Validate accounts at PARSE time, not apply time: a malformed account should
	// fail the plan a reviewer reads, not halfway through mutating a live tenant.
	for _, org := range d.Orgs {
		owners, seen := 0, map[string]bool{}
		for i := range org.Accounts {
			a := &org.Accounts[i]
			if err := a.Validate(org.Name); err != nil {
				return nil, err
			}
			if seen[a.Name] {
				return nil, fmt.Errorf("provision: org %s declares account %q twice", org.Name, a.Name)
			}
			seen[a.Name] = true
			if a.Type == AccountOwner {
				owners++
			}
		}
		// ONE human superuser per org. Two would make "the org's owner" ambiguous
		// in a document whose whole job is to be unambiguous, and a second one is
		// far more likely a copy-paste than an intent.
		if owners > 1 {
			return nil, fmt.Errorf("provision: org %s declares %d owners; an org has at most one", org.Name, owners)
		}
	}
	return &d, nil
}

// Accounts returns every declared account paired with its org, in document
// order. Separate from Derive because an account is NOT a client: it is a user
// row, applied through a different endpoint. Keeping the two derivations apart
// is what stops an account from being registered as an OAuth client — an app
// that could then be used to authenticate AS that account.
//
// It carries NO credential. The plan a reviewer reads and --dry-run prints is
// secret-free by construction; the password is resolved only at the wire
// boundary, by Reconciler.ApplyAccounts.
func Accounts(d *Doc) []OrgAccount {
	var out []OrgAccount
	for _, org := range d.Orgs {
		for _, a := range org.Accounts {
			out = append(out, OrgAccount{Org: org.Name, Account: a})
		}
	}
	return out
}

// OrgAccount pairs an org with one of its declared accounts.
type OrgAccount struct {
	Org     string
	Account Account
}

// User is the wire shape of POST /v1/iam/admin/users/upsert (package bootstrap's
// userUpsertReq). Password is omitted when the reconciler resolved none, which
// the endpoint reads as "keep the credential this account already has".
type User struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	Password    string `json:"password,omitempty"`
	IsAdmin     bool   `json:"isAdmin"`
}

// Derive turns a document into the full set of client registrations, in a
// stable order so two runs over the same document produce byte-identical plans
// — that determinism is what makes --dry-run reviewable in a diff.
func Derive(d *Doc) ([]Client, error) {
	var out []Client
	for _, org := range d.Orgs {
		if strings.TrimSpace(org.Name) == "" {
			return nil, errors.New("provision: an org has no name")
		}
		for _, a := range org.Apps {
			c, err := deriveApp(org, a)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func deriveApp(org Org, a App) (Client, error) {
	name := strings.TrimSpace(a.App)
	if name == "" {
		return Client{}, fmt.Errorf("provision: org %q has an app with no name", org.Name)
	}
	grants, ok := grantsByType[a.Type]
	if !ok {
		return Client{}, fmt.Errorf("provision: app %s/%s has unknown type %q", org.Name, name, a.Type)
	}
	// A callback is a path, and never the /api/ prefix we retired everywhere
	// else. Rejected here rather than in review, because a malformed redirect
	// converges silently and then every login dies redirect_uri_mismatch.
	if cb := strings.TrimSpace(a.Callback); cb != "" {
		if !strings.HasPrefix(cb, "/") {
			return Client{}, fmt.Errorf("provision: app %s/%s callback %q must start with /", org.Name, name, cb)
		}
		if strings.Contains(cb, "/api/") {
			return Client{}, fmt.Errorf("provision: app %s/%s callback %q uses the forbidden /api/ prefix", org.Name, name, cb)
		}
	}

	// clientId == name == <org>-<app>. The upsert keys on Name and defaults
	// ClientId to it, so stating both keeps the record self-describing even if
	// that default ever changes.
	id := org.Name + "-" + name

	// Literal extras are URIs, not paths: a bare path here would register a
	// relative redirect that no authorize request can ever match.
	for _, u := range a.Redirects {
		if u = strings.TrimSpace(u); u == "" {
			continue // union drops blanks; a trailing comma is not a defect
		}
		if !strings.Contains(u, "://") {
			return Client{}, fmt.Errorf("provision: app %s/%s redirect %q must be an absolute URI", org.Name, name, u)
		}
	}

	if err := checkLifetimes(org, name, a); err != nil {
		return Client{}, err
	}

	c := Client{
		Organization:         org.Name,
		Name:                 id,
		ClientId:             id,
		DisplayName:          displayName(org, name),
		GrantTypes:           union(grants, a.Grants),
		RedirectUris:         union(redirects(org, a), a.Redirects),
		Public:               publicByType[a.Type],
		Cert:                 strings.TrimSpace(a.Cert),
		ExpireInHours:        stated(a.ExpireInHours),
		RefreshExpireInHours: stated(a.RefreshExpireInHours),
		EnableCodeSignin:     a.CodeSignin,
	}
	if c.RedirectUris == nil && a.Type != TypeService {
		return Client{}, fmt.Errorf("provision: app %s declares no hosts and type %q needs a redirect", id, a.Type)
	}
	return c, nil
}

// checkLifetimes rejects a token-lifetime pair that cannot work, so the defect
// is a loud parse error instead of a converged registration whose advertised
// refresh_token grant is dead on arrival. A refresh token that expires no later
// than the access token it renews is not a short session — it is a grant that
// can never be exercised once, which is exactly the state `hanzo-cli` shipped
// in. Measured against the effective access lifetime, so the rule is total: an
// undeclared access lifetime is the server's default, not zero.
func checkLifetimes(org Org, name string, a App) error {
	if a.ExpireInHours < 0 || a.RefreshExpireInHours < 0 {
		return fmt.Errorf("provision: app %s/%s declares a negative token lifetime", org.Name, name)
	}
	access := a.ExpireInHours
	if access == 0 {
		access = schema.DefaultExpireInHours
	}
	if a.RefreshExpireInHours > 0 && a.RefreshExpireInHours <= access {
		return fmt.Errorf("provision: app %s/%s refreshExpireInHours %g must outlive expireInHours %g "+
			"— a refresh token that dies with its access token can never be exchanged",
			org.Name, name, a.RefreshExpireInHours, access)
	}
	return nil
}

// stated turns a declared lifetime into the wire's optional field. 0 means
// UNDECLARED and is omitted, so a converge preserves the lifetime the app
// already has rather than resetting every unstated app on every run.
func stated(hours float64) *float64 {
	if hours <= 0 {
		return nil
	}
	return &hours
}

// redirects builds the callback set for one app. Hosts are only meaningful for
// the browser types; cli and desktop derive from the transport they can
// actually receive a code on, and service has no redirect at all.
func redirects(org Org, a App) []string {
	switch a.Type {
	case TypeService:
		return nil

	case TypeCLI:
		// Loopback, per RFC 8252 §7.3 — the port is assigned at runtime, so
		// both the literal IP and the name are registered.
		//
		// Registering these PORTLESS only works because the matcher ignores the
		// port for loopback IP literals (schema.Application.IsRedirectUriValid →
		// loopbackPortAgnosticMatch). The two halves are one contract: when the
		// matcher was exact-only, every CLI login died redirect_uri_mismatch and
		// hung the client on accept(). Change one, change the other.
		return []string{"http://127.0.0.1/callback", "http://localhost/callback"}

	case TypeDesktop:
		scheme := strings.TrimSpace(org.DeepLinkScheme)
		if scheme == "" {
			scheme = org.Name
		}
		return []string{scheme + "://oauth/" + a.App}

	default: // spa, confidential
		path := callbackPath
		if p := strings.TrimSpace(a.Callback); p != "" {
			path = p
		}
		var uris []string
		for _, h := range a.Hosts {
			if h = strings.TrimSpace(h); h != "" {
				uris = append(uris, "https://"+h+path)
			}
		}
		return uris
	}
}

// union appends extras to base, dropping blanks and repeats and keeping the
// order they were declared in. Order-stable and duplicate-free is what makes
// two runs over one document produce byte-identical bodies — the property
// --dry-run is reviewed on, and the reason a re-run is a no-op.
func union(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, s := range append(append([]string{}, base...), extra...) {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func displayName(org Org, app string) string {
	brand := strings.TrimSpace(org.DisplayName)
	if brand == "" {
		brand = org.Name
	}
	return brand + " " + strings.Title(app) //nolint:staticcheck // ASCII app slugs only
}

// Result is what one upsert did, for the run report.
type Result struct {
	Client Client
	Action string // "created" | "updated" | "would-create" (dry run)
	Err    error
}

// AccountResult is what one account upsert did, for the run report. It carries
// the account, never its credential.
type AccountResult struct {
	Account OrgAccount
	Action  string // "created" | "updated" | "would-upsert" (dry run)
	// Credential says whether a secret was resolved and SENT. False means the
	// endpoint preserved whatever the account already had — which for a brand-new
	// account is NO credential at all, and therefore no way to log in. It is in
	// the report because "converged" and "usable" are different facts and the
	// operator must be able to tell them apart.
	Credential bool
	Err        error
}

// Reconciler converges a live IAM onto derived clients over the admin upsert
// endpoint.
type Reconciler struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	DryRun  bool
	// Credentials resolves an account's `kms://<path>` passwordRef to a plaintext
	// password. Nil, or a resolver that reports os.ErrNotExist, means NO password
	// is sent and the upsert PRESERVES the credential the account already has.
	//
	// It is a seam, not a KMS client. IAM does not fetch its own secrets at run
	// time anywhere else — the estate's ONE secret path is KMS → KMSSecret CR →
	// K8s Secret → mounted material (see internal/registry/signkey.go), and this
	// reads what that path already delivered. DirCredentials is the one
	// implementation; a test supplies its own.
	Credentials func(kmsPath string) (string, error)
}

// DirCredentials resolves a KMS path against a directory of mounted credential
// material: `kms://hanzo/iam/owner` reads `<dir>/hanzo/iam/owner`. One rule, no
// name mangling, and it is exactly the shape a projected Secret volume presents.
//
// A missing file is os.ErrNotExist and means "no credential to set" — the
// PRESERVING case, not a failure, so a converge run without the credential
// volume mounted still converges every account's shape.
//
// The path is already proven clean by credentialPath at parse time; this joins
// it and re-checks containment anyway, because a resolver that trusts its input
// is one document typo away from reading an arbitrary file.
func DirCredentials(dir string) func(string) (string, error) {
	return func(p string) (string, error) {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if rel, err := filepath.Rel(dir, full); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("credential %q escapes %s", p, dir)
		}
		b, err := os.ReadFile(full)
		if err != nil {
			return "", err
		}
		// Mounted secret material routinely carries a trailing newline (an editor,
		// `kubectl create secret --from-file`, a heredoc). Sending it would hash a
		// password nobody can type back.
		return strings.TrimRight(string(b), "\r\n"), nil
	}
}

// ApplyAccounts upserts every declared account, continuing past a failure so one
// bad account cannot mask the state of the rest.
//
// Ordering is the document's, and the document puts the org owner before the
// machines by convention — but nothing here depends on that, because each upsert
// is independent and idempotent by (owner, name).
func (r *Reconciler) ApplyAccounts(ctx context.Context, accts []OrgAccount) []AccountResult {
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	out := make([]AccountResult, 0, len(accts))
	for _, a := range accts {
		u, err := r.user(a)
		if err != nil {
			out = append(out, AccountResult{Account: a, Err: err})
			continue
		}
		res := AccountResult{Account: a, Credential: u.Password != ""}
		if r.DryRun {
			res.Action = "would-upsert"
			out = append(out, res)
			continue
		}
		res.Action, res.Err = r.upsertUser(ctx, u)
		out = append(out, res)
	}
	return out
}

// user builds the wire body for one account, resolving its credential.
func (r *Reconciler) user(a OrgAccount) (User, error) {
	u := User{
		Owner: a.Org, Name: a.Account.Name,
		DisplayName: a.Account.DisplayName, Email: a.Account.Email,
		IsAdmin: isAdminByAccountType[a.Account.Type],
	}
	if r.Credentials == nil {
		return u, nil
	}
	p, err := credentialPath(a.Account.PasswordRef, "provision: org "+a.Org+": account "+a.Account.Name)
	if err != nil {
		return User{}, err
	}
	secret, err := r.Credentials(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Not delivered on this run. PRESERVE — never clear.
		return u, nil
	case err != nil:
		// The error is reported WITHOUT the ref's resolved value; a credential must
		// not reach a log through an error string.
		return User{}, fmt.Errorf("provision: org %s: account %s: resolve credential: %w", a.Org, a.Account.Name, err)
	case secret == "":
		// Present but empty. Sending it would store a hash of "" — and while
		// users.VerifyPassword refuses an empty digest, an empty PASSWORD hashes to
		// a real digest that an empty password then verifies against. Refuse.
		return User{}, fmt.Errorf("provision: org %s: account %s: credential %s is empty",
			a.Org, a.Account.Name, a.Account.PasswordRef)
	}
	u.Password = secret
	return u, nil
}

func (r *Reconciler) upsertUser(ctx context.Context, u User) (string, error) {
	var out struct {
		Status string `json:"status"`
		Action string `json:"action"`
		Msg    string `json:"msg"`
	}
	if err := r.post(ctx, "/v1/iam/admin/users/upsert", u, &out); err != nil {
		return "", fmt.Errorf("upsert account %s/%s: %w", u.Owner, u.Name, err)
	}
	if out.Status != "ok" {
		return "", fmt.Errorf("upsert account %s/%s: %s", u.Owner, u.Name, out.Msg)
	}
	return out.Action, nil
}

// Apply upserts every client, continuing past a failure so one bad app cannot
// mask the state of the rest — the report is the point of the run.
func (r *Reconciler) Apply(ctx context.Context, clients []Client) []Result {
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	out := make([]Result, 0, len(clients))
	for _, c := range clients {
		if r.DryRun {
			out = append(out, Result{Client: c, Action: "would-upsert"})
			continue
		}
		action, err := r.upsert(ctx, c)
		out = append(out, Result{Client: c, Action: action, Err: err})
	}
	return out
}

func (r *Reconciler) upsert(ctx context.Context, c Client) (string, error) {
	var out struct {
		Status string `json:"status"`
		Action string `json:"action"`
		Msg    string `json:"msg"`
	}
	if err := r.post(ctx, "/v1/iam/admin/applications/upsert", c, &out); err != nil {
		return "", fmt.Errorf("upsert %s: %w", c.Name, err)
	}
	if out.Status != "ok" {
		return "", fmt.Errorf("upsert %s: %s", c.Name, out.Msg)
	}
	return out.Action, nil
}

// post is the ONE authed JSON call to an admin upsert endpoint — the applications
// one and the accounts one differ by path and body, and by nothing else. Sharing
// it is what keeps the service-token header, the body limit and the non-200
// handling from drifting between the two.
//
// The request body is never logged or wrapped into an error: the account body
// carries a password.
func (r *Reconciler) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Token)

	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respRaw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respRaw)))
	}
	if err := json.Unmarshal(respRaw, out); err != nil {
		return fmt.Errorf("undecodable response: %w", err)
	}
	return nil
}
