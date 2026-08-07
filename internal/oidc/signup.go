// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The native front-door signup: POST /v1/iam/signup. The @hanzo/iam SDK + the
// hanzo.id portal post the sign-up form here to create a new account. It mirrors
// the v1 the legacy surface Signup contract (controllers/account.go): the casibase
// {status,msg,data} envelope, resolve-app → enforce-policy → create-user, with
// the password hashed (never stored plaintext) and the created row returned
// REDACTED.
//
// Password sign-up only in this increment (the enabled-method the portal drives);
// the email/phone-OTP-gated sign-up variant plugs its verification check
// (CheckVerificationCode) in ahead of the create at cutover.

// PathSignup is the canonical front-door signup endpoint.
const PathSignup = "/v1/iam/signup"

// signupForm is the sign-up request the SDK/portal posts — the signup-relevant
// subset of v1's form.AuthForm.
type signupForm struct {
	Application  string `json:"application"`
	ClientId     string `json:"clientId"`
	Organization string `json:"organization"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Name         string `json:"name"` // display name
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	CountryCode  string `json:"countryCode"`
	Affiliation  string `json:"affiliation"`

	// Training is the answer to the AI-training question the signup screen asks,
	// recorded with the account rather than left for a later prompt. Absent means
	// unanswered — which reads as refusal everywhere — so a client that does not
	// ask cannot accidentally grant, and the screen is what turns silence into an
	// explicit answer. A non-empty value that is not a known answer is refused
	// outright rather than coerced.
	Training string `json:"training"`
}

// signupHandler creates an account from the sign-up form and applies the
// application's own sign-up rules — whether self-service registration is open at
// all, and which fields it requires.
//
// The password is hashed before it is stored and is never returned.
func signupHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f signupForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()

		f.Organization = strings.TrimSpace(f.Organization)
		f.Username = strings.TrimSpace(f.Username)
		if f.Organization == "" || f.Username == "" || f.Password == "" {
			return httpx.Err(c, "organization, username and password are required")
		}

		// Resolve the training answer before anything is created, so an account is
		// never persisted alongside an answer this version cannot interpret.
		consent := schema.Consent{Insights: true, Training: schema.Answer(f.Training)}
		if !consent.Training.Valid() {
			return httpx.Err(c, "training must be one of: \"\", granted, refused")
		}

		// Resolve the application (by clientId when present, else by name under the
		// admin owner — the iam storage convention), then enforce its policy.
		app, err := resolveSignupApp(ctx, db, f)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "the application: "+f.Application+" does not exist")
		}
		if !app.EnableSignUp {
			return httpx.Err(c, "the application does not allow to sign up new account")
		}
		if !app.EnablePassword {
			return httpx.Err(c, "the application does not allow password sign-up")
		}

		// A self-service signup may NEVER resolve to a reserved system org
		// (admin/built-in/app). A user created under "admin" is a SuperAdmin — authz
		// derives Super from owner == "admin" — so this is THE privilege escalation to
		// refuse, and it must hold INDEPENDENT of the app: an admin-org app, a shared
		// app, or an org-choice app would each otherwise admit `organization=admin`
		// through the tenant gate below and mint a SuperAdmin. This is the same
		// store.IsReservedOrg refusal onboarding and federated provisioning apply — the
		// ONE reserved-org predicate, so signup can never drift from them. The message
		// is byte-identical to the tenant refuse below, so a prober cannot distinguish
		// "reserved org" from "wrong tenant" (no existence/authority oracle).
		if store.IsReservedOrg(f.Organization) {
			return httpx.Err(c, "the user is not permitted to sign up to this application")
		}
		// Tenant isolation: the requested org must be the app's own org, a shared
		// app, or an app that lets users choose their org — the same gate login
		// enforces, so a signup cannot land a user in an arbitrary tenant.
		if f.Organization != app.Organization && !app.IsShared && app.OrgChoiceMode == "" {
			return httpx.Err(c, "the user is not permitted to sign up to this application")
		}

		org, err := store.GetOrganizationByName(ctx, db, f.Organization)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if org == nil {
			// Self-serve org creation — the founder signs up and their org is minted
			// with them. It is OPT-IN per application (orgChoiceMode == orgChoiceCreate)
			// so an app that names one tenant can never mint another: the tenant gate
			// above already refuses a foreign org unless the app is shared or lets users
			// choose, and this narrows "choose" to the apps that mean "create".
			//
			// Safe by construction, given the two checks that already ran:
			//   - IsReservedOrg refused admin/built-in/app, so this can never mint a
			//     reserved org — and the USER below is created under f.Organization, so
			//     owner != "admin" and the row carries no SuperAdmin authority.
			//   - the name is validated here rather than trusted, so a signup cannot
			//     invent an org id containing a separator or path characters.
			if app.OrgChoiceMode != orgChoiceCreate {
				return httpx.Err(c, "the organization: "+f.Organization+" does not exist")
			}
			if msg := orgNamePolicyError(f.Organization); msg != "" {
				return httpx.Err(c, msg)
			}
			created, err := store.CreateOrganization(ctx, db, f.Organization)
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			org = created
		} else if f.Organization != app.Organization && !app.IsShared {
			// The org ALREADY EXISTS and belongs to someone else. Org choice grants the
			// right to name YOUR OWN org — to mint one above, or to land in the app's
			// own tenant — never the right to walk into a tenant that is already
			// standing. Without this arm the gate above is satisfied by a non-empty
			// OrgChoiceMode and this branch does nothing, so an unauthenticated POST
			// naming any existing org is made a member of it: hanzo-console, a hanzo
			// app, minted a user with owner "lux" on the live instance. Every brand and
			// every customer tenant in the one multi-brand registry was reachable that
			// way, which is precisely the isolation the tenant gate exists to provide.
			//
			// The refusal is byte-identical to the tenant refuse above and to the
			// reserved-org refuse, so a prober cannot distinguish "someone else's org"
			// from "wrong tenant" from "reserved name" — no authority oracle.
			//
			// A signup naming a name NOBODY holds still succeeds under orgChoiceCreate,
			// so this does leak org NON-existence to anyone willing to mint one. That is
			// inherent to self-serve creation rather than introduced here, it is
			// self-limiting (the probe leaves an org row behind), and it is a far
			// smaller thing to concede than membership in an existing tenant.
			return httpx.Err(c, "the user is not permitted to sign up to this application")
		}

		// THE username rule (schema.Username), applied at the door so the caller gets
		// the reason rather than a bare conflict — and so every check BELOW this line
		// runs against the value that will actually be stored. Probing uniqueness with
		// the raw spelling while storing the normalized one is how "Alice" gets admitted
		// next to an existing "alice".
		username, err := schema.Username(f.Username)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		f.Username = username
		// Uniqueness within the org — one opaque check per identifier.
		if taken, err := userExists(ctx, db, f.Organization, f.Username); err != nil {
			return httpx.Err(c, err.Error())
		} else if taken {
			return httpx.Err(c, "username already exists")
		}
		email := strings.ToLower(strings.TrimSpace(f.Email))
		if email != "" {
			if !isEmailValid(email) {
				return httpx.Err(c, "email is invalid")
			}
			if existing, err := store.GetUserByEmail(ctx, db, f.Organization, email); err != nil {
				return httpx.Err(c, err.Error())
			} else if existing != nil {
				return httpx.Err(c, "email already exists")
			}
		}
		// Password policy (v1 org.PasswordOptions complexity).
		if msg := passwordPolicyError(org.PasswordOptions, f.Password); msg != "" {
			return httpx.Err(c, msg)
		}

		// Create through the ONE canonical user path (users.Create): argon2id-hash the
		// password once, persist, return the REDACTED row (no plaintext, no digest ever
		// stored or returned). PasswordType is stamped "argon2id" — exactly what
		// internal/cred verifies for a new iam row.
		created, err := users.New(db).Create(ctx, &users.CreateInput{
			User: schema.User{
				Owner:             f.Organization,
				Name:              f.Username,
				Type:              "normal-user",
				DisplayName:       displayName(f),
				FirstName:         f.FirstName,
				LastName:          f.LastName,
				Email:             email,
				EmailVerified:     false,
				Phone:             store.NormalizePhone(f.Phone),
				CountryCode:       f.CountryCode,
				Affiliation:       f.Affiliation,
				Avatar:            org.DefaultAvatar,
				SignupApplication: app.Name,
				RegisterType:      "Application Signup",
				RegisterSource:    f.Organization + "/" + app.Name,
			},
			Password: f.Password,
			// The answer the screen collected, recorded WITH the account. A new
			// user therefore starts with an explicit answer instead of silence, and
			// silence — for any account created by a path that does not ask — still
			// reads as refusal. It rides the typed seam rather than a properties
			// blob assembled here, because that blob is exactly what Create drops:
			// this is the one caller entitled to state an answer, and being
			// in-process is what distinguishes it from a request that claims to be.
			Consent: &consent,
		})
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, created)
	}
}

// resolveSignupApp resolves the signup's OAuth app: by clientId when present,
// else by (admin, application name) — mirroring resolveLoginApp.
func resolveSignupApp(ctx context.Context, db orm.DB, f signupForm) (*schema.Application, error) {
	if f.ClientId != "" {
		return store.GetApplicationByClientId(ctx, db, f.ClientId)
	}
	if f.Application != "" {
		return store.GetApplicationByName(ctx, db, "admin", f.Application)
	}
	return nil, nil
}

// userExists reports whether a user (org, name) already exists.
func userExists(ctx context.Context, db orm.DB, org, name string) (bool, error) {
	u, err := store.GetUserByName(ctx, db, org, name)
	return u != nil, err
}

// displayName is the user's display name: the supplied name, a "First Last"
// composite, or the username as a last resort — v1's precedence.
func displayName(f signupForm) string {
	if f.FirstName != "" || f.LastName != "" {
		if n := strings.TrimSpace(f.FirstName + " " + f.LastName); n != "" {
			return n
		}
	}
	if f.Name != "" {
		return f.Name
	}
	return f.Username
}

// usernamePolicyError returns the first username rule a candidate violates, or
// "" when it passes — the v1 CheckUserSignup rules for the Username item.
// orgChoiceCreate is the application's opt-in to SELF-SERVE org creation: a signup
// naming an org that does not exist mints it, with the signing-up user as its first
// member. Any other orgChoiceMode still only lets a user CHOOSE among existing orgs,
// so turning on self-serve is a deliberate per-app decision rather than a side effect
// of allowing org choice at all.
const orgChoiceCreate = "create"

// orgNamePolicyError validates a self-service org name. The org name is the OWNER
// half of every (owner, name) natural key in the store, so a permissive name here
// would be a key-injection surface, not a cosmetic issue — hence the same "/" and
// whitespace refusals schema.Username applies to the name half, plus a length bound.
//
// It deliberately does NOT reject a name merely because it is taken: the caller
// reaches this only when the lookup already returned no org, and a "taken" message
// would turn signup into an org-existence oracle.
func orgNamePolicyError(org string) string {
	if len(org) <= 1 {
		return "organization name must have at least 2 characters"
	}
	if len(org) > 100 {
		return "organization name is too long"
	}
	if unicode.IsDigit(rune(org[0])) {
		return "organization name cannot start with a digit"
	}
	if strings.IndexFunc(org, unicode.IsSpace) >= 0 {
		return "organization name cannot contain white spaces"
	}
	if strings.Contains(org, "/") {
		return "organization name cannot contain '/'"
	}
	// An EMAIL is never an organization. A signup form that defaults the org field
	// to the address the person just typed mints one org per human: 56 of the 124
	// orgs on the live instance are email-shaped, so nearly half the tenant
	// registry is people and "is this a company?" has no answer.
	//
	// It is also the wrong money shape. account.Payer resolves a member of the
	// SIGNUP org to a PERSONAL wallet — Person(hanzo, name) — precisely so an
	// individual has a balance without their own tenant. Minting them an org sends
	// them down the Org() pool branch instead, making that special-case dead code
	// and costing an org row plus a membership row on every signup.
	//
	// This refuses the SHAPE, not the intent: a real company name still creates a
	// real org, and someone who typed their address lands in the signup org with a
	// personal wallet, which is where they belonged.
	if strings.ContainsRune(org, '@') {
		return "organization name cannot be an email address — sign up as a person, or name your organization"
	}
	return ""
}

// Password-complexity option matchers — the v1 object/check_password_complexity.go
// option set, driven by the organization's PasswordOptions.
var (
	pwReLower   = regexp.MustCompile(`[a-z]`)
	pwReUpper   = regexp.MustCompile(`[A-Z]`)
	pwReDigit   = regexp.MustCompile(`\d`)
	pwReSpecial = regexp.MustCompile("[!-/:-@[-`{-~]")
)

// pwFloorMinLength is the PLATFORM password floor: the minimum length every
// password must meet no matter what the organization declares. It is the same
// "AtLeast8" every seeded organization already carries (init_data.json), lifted
// out of configuration and into code so that it cannot be configured away — and
// so an organization that declares nothing is not thereby exempt.
const pwFloorMinLength = 8

// passwordPolicyError returns the first complexity rule the password violates,
// or "" when it passes: the platform floor first, then the organization's own
// options, which may only ever make the policy STRICTER.
//
// The floor exists because the option set alone is a policy an org can hold
// EMPTY. store.CreateOrganization mints a self-serve org with no PasswordOptions,
// so "no options" — which used to mean "any non-empty password" — was reachable
// by an anonymous caller: a self-serve signup was accepted with the single byte
// "a", and that account then logged in. Enforcing the floor here rather than
// stamping defaults onto each new org keeps ONE source of truth: options are
// additive strictness on top of an invariant, not the invariant itself.
func passwordPolicyError(options []string, password string) string {
	if password == "" {
		return "password cannot be empty"
	}
	// Length is counted in RUNES, once, for the floor and for the org options
	// alike — a byte count would let a handful of multi-byte characters satisfy
	// an "8 characters" rule, and would let the floor and AtLeast8 disagree about
	// what "8 characters" means.
	n := utf8.RuneCountInString(password)
	if n < pwFloorMinLength {
		return "the password must have at least 8 characters"
	}
	// A password of one repeated rune ("aaaaaaaa") is the length floor's trivial
	// evasion and cannot be a real user's choice, so refuse it outright. This is
	// deliberately narrower than the NoRepeat option below, which refuses ANY two
	// adjacent equal runes and would reject legitimate passwords.
	if isSingleRepeatedRune(password) {
		return "the password must not be a single repeated character"
	}
	for _, opt := range options {
		switch opt {
		case "AtLeast6":
			if n < 6 {
				return "the password must have at least 6 characters"
			}
		case "AtLeast8":
			if n < 8 {
				return "the password must have at least 8 characters"
			}
		case "Aa123":
			if !pwReLower.MatchString(password) || !pwReUpper.MatchString(password) || !pwReDigit.MatchString(password) {
				return "the password must contain at least one uppercase letter, one lowercase letter and one digit"
			}
		case "SpecialChar":
			if !pwReSpecial.MatchString(password) {
				return "the password must contain at least one special character"
			}
		case "NoRepeat":
			for i := 0; i+1 < len(password); i++ {
				if password[i] == password[i+1] {
					return "the password must not contain any repeated characters"
				}
			}
		}
	}
	return ""
}

// isSingleRepeatedRune reports whether s is one rune repeated — "a", "aaaaaaaa",
// "………". Used by the floor to refuse the length rule's trivial evasion.
func isSingleRepeatedRune(s string) bool {
	first, size := utf8.DecodeRuneInString(s)
	for _, r := range s[size:] {
		if r != first {
			return false
		}
	}
	return true
}

// isEmailValid reports whether s parses as an email address — v1's
// util.IsEmailValid (net/mail.ParseAddress), the single email check shared by
// signup and send-verification-code.
func isEmailValid(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}
