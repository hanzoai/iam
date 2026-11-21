// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// The native front-door signup: POST /v1/iam/signup. The @hanzo/iam SDK + the
// hanzo.id portal post the sign-up form here to create a new account. It mirrors
// the v1 Casdoor Signup contract (controllers/account.go): the casibase
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
}

// signupHandler validates the front-door signup policy and creates the account.
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

		// Resolve the application (by clientId when present, else by name under the
		// admin owner — the iam2 storage convention), then enforce its policy.
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
			// v1 auto-mints the founder's own org (TenantOrgForSignup /
			// CreatePersonalOrganization) only for a platform tenant org; that path
			// needs an org-create helper + the Org.Parent tenant-parent model, neither
			// of which iam2 has yet, so signup requires the org to exist. See report.
			return httpx.Err(c, "the organization: "+f.Organization+" does not exist")
		}

		// Username policy (v1 object/check.go CheckUserSignup).
		if msg := usernamePolicyError(f.Username); msg != "" {
			return httpx.Err(c, msg)
		}
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

		// Create through the ONE canonical user path: bcrypt-hash the password once,
		// persist, return the REDACTED row (no plaintext, no digest ever stored or
		// returned). PasswordType is stamped "bcrypt" — exactly what internal/cred
		// verifies for a new iam2 row.
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
				Phone:             f.Phone,
				CountryCode:       f.CountryCode,
				Affiliation:       f.Affiliation,
				Avatar:            org.DefaultAvatar,
				SignupApplication: app.Name,
				RegisterType:      "Application Signup",
				RegisterSource:    f.Organization + "/" + app.Name,
			},
			Password: f.Password,
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
func usernamePolicyError(username string) string {
	if len(username) <= 1 {
		return "username must have at least 2 characters"
	}
	if unicode.IsDigit(rune(username[0])) {
		return "username cannot start with a digit"
	}
	if isEmailValid(username) {
		return "username cannot be an email address"
	}
	if strings.IndexFunc(username, unicode.IsSpace) >= 0 {
		return "username cannot contain white spaces"
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

// passwordPolicyError returns the first complexity rule the password violates
// under the organization's options, or "" when it passes. With no options set,
// only the non-empty check applies (v1 parity).
func passwordPolicyError(options []string, password string) string {
	if password == "" {
		return "password cannot be empty"
	}
	for _, opt := range options {
		switch opt {
		case "AtLeast6":
			if len(password) < 6 {
				return "the password must have at least 6 characters"
			}
		case "AtLeast8":
			if len(password) < 8 {
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

// isEmailValid reports whether s parses as an email address — v1's
// util.IsEmailValid (net/mail.ParseAddress), the single email check shared by
// signup and send-verification-code.
func isEmailValid(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}
