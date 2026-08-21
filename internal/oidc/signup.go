// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	policy "github.com/hanzoai/authz"
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
// (otp.Check) in ahead of the create at cutover.

// PathSignup is the canonical front-door signup endpoint.
const PathSignup = "/v1/iam/signup"

// signupForm is the sign-up request the SDK/portal posts — the signup-relevant
// subset of v1's form.AuthForm.
type signupForm struct {
	Application  string `json:"application"`
	ClientId     string `json:"clientId"`
	Organization string `json:"organization"`

	// Username is OPTIONAL. A caller that names one is asking for that exact name
	// and gets it or a refusal; a caller that names none — the signup screen, which
	// has no such field — gets one minted from the address. Either way the value
	// stored is IAM's to decide, never the spelling that arrived.
	Username    string `json:"username"`
	Password    string `json:"password"`
	Name        string `json:"name"` // display name
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	CountryCode string `json:"countryCode"`
	Affiliation string `json:"affiliation"`

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
		if f.Organization == "" || f.Password == "" {
			return httpx.Err(c, "organization and password are required")
		}

		// Resolve the training answer before anything is created, so an account is
		// never persisted alongside an answer this version cannot interpret.
		consent := schema.Consent{Insights: true, Training: schema.Answer(f.Training)}
		if !consent.Training.Valid() {
			return httpx.Err(c, "training must be one of: \"\", granted, refused")
		}

		// Resolve the application (by clientId when present, else by name under the
		// admin owner — the iam storage convention), then enforce its policy.
		app, err := ResolveApp(ctx, db, f.ClientId, f.Application)
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
		// policy.IsReservedOrg refusal onboarding and federated provisioning apply — the
		// ONE reserved-org predicate, so signup can never drift from them. The message
		// is byte-identical to the tenant refuse below, so a prober cannot distinguish
		// "reserved org" from "wrong tenant" (no existence/authority oracle).
		if policy.IsReservedOrg(f.Organization) {
			return httpx.Err(c, "the user is not permitted to sign up to this application")
		}
		// Tenant isolation: the requested org must be the app's own org, a shared
		// app, or an app that lets users choose their org — the same gate login
		// enforces, so a signup cannot land a user in an arbitrary tenant.
		if f.Organization != app.Organization && !app.ServesAnyOrg() {
			return httpx.Err(c, "the user is not permitted to sign up to this application")
		}

		org, err := store.GetOrganizationByName(ctx, db, f.Organization)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if org == nil {
			// Signup does not mint organizations. It used to, opt-in per app, and that
			// made an UNAUTHENTICATED request able to add a row to the tenant registry:
			// 26 of the 51 org-holding orgs on the live instance hold exactly one user,
			// among them orgs left behind by probes.
			//
			// Nothing asked for it either. The screen posts the app's own org and asks
			// for the organization in ONBOARDING, and POST /v1/iam/onboard is a better
			// answer to the same question in every respect: it authenticates the caller,
			// acts only on the caller, is idempotent, and provisions the org's metered
			// credential in the same atomic step — so it lands a person somewhere they
			// can actually work, where this landed them in an org with no billing
			// account. Two ways to create an org, one of them needing no identity and
			// producing the worse result, is one way too many.
			return httpx.Err(c, "the organization: "+f.Organization+" does not exist")
		}
		if f.Organization != app.Organization && !app.IsShared {
			// The org EXISTS and belongs to someone else. Org choice grants the right to
			// land in the app's own tenant, never the right to walk into a tenant that
			// is already standing. Without this arm the gate above is satisfied by a
			// non-empty OrgChoiceMode and this branch does nothing, so an unauthenticated
			// POST naming any existing org is made a member of it: hanzo-console, a hanzo
			// app, minted a user with owner "lux" on the live instance. Every brand and
			// every customer tenant in the one multi-brand registry was reachable that
			// way, which is precisely the isolation the tenant gate exists to provide.
			//
			// The refusal is byte-identical to the tenant refuse above and to the
			// reserved-org refuse, so a prober cannot distinguish "someone else's org"
			// from "wrong tenant" from "reserved name" — no authority oracle.
			return httpx.Err(c, "the user is not permitted to sign up to this application")
		}

		// Password policy (v1 org.PasswordOptions complexity) BEFORE either uniqueness
		// check, so no answer about who already has an account is free: a probe has to
		// bring a password this org would actually accept to learn anything. It reads
		// in the right order too — the rules that are about the request alone come
		// first, and only then does anything look at the directory.
		if msg := passwordPolicyError(org.PasswordOptions, f.Password); msg != "" {
			return httpx.Err(c, msg)
		}

		email := store.NormalizeEmail(f.Email)
		if email != "" {
			if !isEmailValid(email) {
				return httpx.Err(c, "email is invalid")
			}
			// An address that already names an account is taken, and an address that
			// names TWO is taken twice over — ErrEmailAmbiguous is a uniqueness answer
			// here, not a lookup failure, so it lands on the uniqueness message rather
			// than reporting the store's broken invariant to a stranger.
			switch existing, err := store.GetUserByEmail(ctx, db, f.Organization, email); {
			case err == store.ErrEmailAmbiguous, existing != nil:
				return httpx.Err(c, "email already exists")
			case err != nil:
				return httpx.Err(c, err.Error())
			}
			// And among the accounts this application founded orgs for, which are no
			// longer in the org just searched. Founding empties the application's org of
			// exactly the accounts this is checking against, so without this the address
			// reads as free the moment its owner moves out — the second person registers
			// it, and then NEITHER of them can sign in, because one address across two of
			// one application's accounts names nobody.
			switch existing, err := store.GetSignupByEmail(ctx, db, app.Name, email); {
			case err == store.ErrEmailAmbiguous, existing != nil:
				return httpx.Err(c, "email already exists")
			case err != nil:
				return httpx.Err(c, err.Error())
			}
		}

		// The username. A caller that NAMES one gets exactly that name or a refusal —
		// provisioning a known name is a real use, and silently substituting another
		// would hand back a different principal than the one asked for. A caller that
		// names none gets one minted from the address, through the SAME derivation
		// federated signup walks (allocateName), so the two ways an account enters this
		// store agree on what an address is worth as a name.
		//
		// The signup screen has no username field, and the portal used to fill the gap
		// in the browser with `email.split('@')[0]`. That guess cost two dead ends: a
		// plus-address — `alice+hanzo@gmail.com`, one of the commonest real address
		// forms — was refused outright, because "+" is not in the username charset and
		// nothing on that path reduced the local part to the charset; and the SECOND
		// person whose local part collided was refused "username already exists", about
		// a field they were never shown and could not change. Both are gone the moment
		// the derivation moves to the side that can see the directory: schema.Handle
		// drops the subaddress marker, and the walk that federation has always done
		// hands out `alice2`.
		if f.Username == "" {
			if email == "" {
				return httpx.Err(c, "an email address or a username is required")
			}
			name, err := allocateName(ctx, db, f.Organization, email, "")
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			f.Username = name
		} else {
			// THE username rule (schema.Username), applied at the door so the caller gets
			// the reason rather than a bare conflict — and so the uniqueness check runs
			// against the value that will actually be stored. Probing uniqueness with the
			// raw spelling while storing the normalized one is how "Alice" gets admitted
			// next to an existing "alice".
			name, err := schema.Username(f.Username)
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			f.Username = name
			if taken, err := userExists(ctx, db, f.Organization, name); err != nil {
				return httpx.Err(c, err.Error())
			} else if taken {
				return httpx.Err(c, "username already exists")
			}
		}

		// Create through the ONE canonical user path (users.Create): argon2id-hash the
		// password once, persist, return the REDACTED row (no plaintext, no digest ever
		// stored or returned). PasswordType is stamped "argon2id" — exactly what
		// internal/cred verifies for a new iam row.
		created, err := users.New(db).Create(ctx, &users.CreateInput{
			// The class is stated here, beside the create, rather than inside the user
			// body — a signup makes a PERSON, and only this code may say so.
			Type: "normal-user",
			User: schema.User{
				Owner:             f.Organization,
				Name:              f.Username,
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

		// The account is REGISTERED in the application's org — that is what every
		// check above just decided — and at a founding application it WORKS in an org
		// of its own, which this founds and moves it into.
		//
		// The two are different things. The application's org is where a username is
		// unique and where the sign-in screen looks; the tenant is what holds
		// credentials, connections and spend. An application open to strangers must
		// keep them apart, or everyone it registers is a member of whichever tenant
		// that application happens to belong to.
		//
		// Signup still does not mint an org the CALLER names — the refusal above is
		// untouched, and it is what stopped an unauthenticated POST adding a row to
		// the tenant registry. This slug is DERIVED, from an account this request has
		// just created, so nothing about it is the caller's to choose.
		//
		// It is the same converge onboarding drives, not a second one: org + founder
		// moved in as its admin + its owner membership + the org's metered credential,
		// idempotent and resumable. So a person who signs up and a person who onboards
		// arrive in the same state, and there is one place where founding an org is
		// written down.
		if app.OrgChoiceMode == orgChoiceCreate {
			org, err := charter(ctx, db, created)
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			// The move re-keyed the row, so the response must name where the account
			// actually is. Returning the pre-move owner tells the client to address an
			// identity that no longer exists.
			created.Owner = org
		}
		return httpx.Ok(c, created)
	}
}

// charter founds the organization an account works in and moves the account into
// it, returning the org's name.
//
// The name is derived from the account, never taken from a request: a signup is
// unauthenticated, and a caller that could NAME the org would be writing a row of
// its choosing into the tenant registry.
func charter(ctx context.Context, db orm.DB, user *schema.User) (string, error) {
	// personalOrgSlug caps its derivation at maxOrgSlug, and the walk appends to
	// what it returns, so the base is trimmed to leave the suffix room. A slug over
	// that bound cannot be founded at all: provision derives the org's credential
	// name from it, and that name has a bound of its own — so an account whose
	// address is merely long would otherwise be refused at the end of its signup,
	// for a rule about a name it never chose.
	base := personalOrgSlug(user.Name)
	if room := maxOrgSlug - len(strconv.Itoa(nameAttempts)); len(base) > room {
		base = base[:room]
	}
	slug, err := allocate(base, func(s string) (bool, error) { return orgSlugFree(ctx, db, s) })
	if err != nil {
		return "", err
	}
	out, err := provision(ctx, db, claim{
		owner: user.Owner, name: user.Name,
		slug: slug, display: user.Name, personal: true,
	})
	if err != nil {
		return "", err
	}
	return out.org, nil
}

// orgChoiceCreate is the application's declaration that a signup FOUNDS the
// person's own organization: they are its sole member, and they join a team org
// — hanzo, lux, zoo or any customer's — separately, by membership. An
// application that declares anything else registers its accounts in its own org
// and leaves the tenant to onboarding.
//
// It is the mode the org picker already names, read where the founding happens.
// Application.ServesAnyOrg reads the same value for the tenant exemption, which
// this makes true rather than merely permitted: a founding app's accounts really
// do live in orgs that are not its own.
const orgChoiceCreate = "create"

// orgSlugFree reports whether slug may be founded as a new organization: long
// enough to be one, not a reserved system owner, and not already standing.
//
// All three are reasons a slug is unavailable, so they are one predicate — a
// derivation that walked only past TAKEN names would hand provision a name it
// refuses, and the person's signup would fail on a rule they never saw.
func orgSlugFree(ctx context.Context, db orm.DB, slug string) (bool, error) {
	if len(slug) < minOrgSlug || len(slug) > maxOrgSlug || policy.IsReservedOrg(slug) {
		return false, nil
	}
	org, err := store.GetOrganizationByName(ctx, db, slug)
	if err != nil {
		return false, err
	}
	return org == nil, nil
}

// userExists reports whether a user (org, name) already exists.
func userExists(ctx context.Context, db orm.DB, org, name string) (bool, error) {
	u, err := store.GetUserByName(ctx, db, org, name)
	return u != nil, err
}

// nameAttempts bounds the dedupe walk: the first free suffix wins, and a name
// that is still taken after this many tries means something is wrong with the
// derivation, not that the org is full.
const nameAttempts = 32

// allocate returns base, or the first numbered variant of it that free accepts —
// alice, alice2, alice3. A person gets the name they would have chosen and the
// suffix appears only when it has to.
//
// One walk, because a signup derives two names under the same rule (the username,
// and the slug of the org it founds) and they must not drift into disagreeing
// about what the second Alice is called. What "free" means belongs to the caller:
// a username is free when the org has nobody by it, a slug when no organization
// may be, is, or already stands under it.
func allocate(base string, free func(string) (bool, error)) (string, error) {
	for attempt := 1; attempt <= nameAttempts; attempt++ {
		candidate := base
		if attempt > 1 {
			candidate += strconv.Itoa(attempt)
		}
		ok, err := free(candidate)
		if err != nil {
			return "", err
		}
		if ok {
			return candidate, nil
		}
	}
	return "", errors.New("could not allocate a unique name")
}

// allocateName mints the username a NEW account gets in org: the handle its
// address yields, or the first free variant of it. It is the ONE derivation both
// ways into this store use — a password signup with no username of its own, and a
// federated signup, which never has one.
//
// What an address yields is schema.Handle's to decide, and only the ADDRESS may
// become an identity: an IdP profile says "Zach Kelling", which is not a username
// in any spelling and must never be turned into one. fallback is the value to
// derive from when the address yields nothing — the provider TYPE ("google") for a
// federated signup, which is the only other value on that path that is not a
// human's name. Empty when the caller has no such value.
//
// The walk is [allocate]'s: alice@gmail.com becomes "alice", then "alice2",
// "alice3". That replaced a random 8-hex suffix on EVERY name ("z-3f9ab21c"),
// which made collisions impossible by making every name unrecognisable.
func allocateName(ctx context.Context, db orm.DB, org, email, fallback string) (string, error) {
	base := schema.Handle(email)
	if base == "" {
		base, _ = schema.Username(fallback)
	}
	if base == "" {
		base = "user"
	}
	return allocate(base, func(name string) (bool, error) {
		taken, err := userExists(ctx, db, org, name)
		return !taken, err
	})
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
