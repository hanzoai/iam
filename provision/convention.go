// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package provision

import (
	"strings"
	"unicode"
)

// AppType selects the OAuth-client convention an application follows. It is the
// single knob an operator turns; the redirect URIs, grant types and signin
// surface all derive from it. Closed set — Valid() gates unknown values at
// load time so a typo fails loudly instead of provisioning a broken client.
type AppType string

const (
	// TypeSPA is a browser single-page app: public client, PKCE, no secret.
	TypeSPA AppType = "spa"
	// TypeCLI is a command-line app using a loopback redirect: public, PKCE.
	TypeCLI AppType = "cli"
	// TypeDesktop is a native app using a custom-scheme deep link: public, PKCE.
	TypeDesktop AppType = "desktop"
	// TypeConfidential is a server-side web app that holds a client secret.
	TypeConfidential AppType = "confidential"
	// TypeService is a machine-to-machine client: client_credentials only.
	TypeService AppType = "service"
)

// Valid reports whether t is a known application type.
func (t AppType) Valid() bool {
	switch t {
	case TypeSPA, TypeCLI, TypeDesktop, TypeConfidential, TypeService:
		return true
	default:
		return false
	}
}

func appTypeNames() []string {
	return []string{
		string(TypeSPA), string(TypeCLI), string(TypeDesktop),
		string(TypeConfidential), string(TypeService),
	}
}

// public reports whether the type is a public OAuth client — one that proves
// possession with PKCE and never presents a client secret at the token
// endpoint (spa, cli, desktop). Confidential and service are non-public.
func (t AppType) public() bool {
	return t == TypeSPA || t == TypeCLI || t == TypeDesktop
}

// interactive reports whether the type drives a human login UI (everything
// except machine-to-machine service clients).
func (t AppType) interactive() bool {
	return t != TypeService
}

// Sane-default conventions. These are the mechanism's opinions — the values
// every provisioned entity inherits unless the type says otherwise.
const (
	defaultOwner       = "admin"
	defaultCert        = "cert-built-in"
	defaultTokenFormat = "JWT"
	defaultPasswordTyp = "argon2id"
)

// defaultScopes are the standard OIDC scopes every interactive client requests
// at the authorize endpoint. They are protocol defaults requested per-flow, not
// a stored allowlist, so they live here as the documented convention rather
// than on the application row.
var defaultScopes = []string{"openid", "profile", "email"}

// defaultLanguages mirrors the admin org so provisioned login pages localize.
var defaultLanguages = []string{"en", "es", "fr", "de", "it", "nl", "pt", "ru", "ja", "ko", "zh", "vi"}

// redirectURIs derives an application's callback URIs from its type, the org's
// web hosts (for browser flows), and the org deep-link scheme (for desktop).
//
//	spa, confidential -> per host: https://<host>/auth/callback
//	                                https://<host>/api/auth/callback/<org>
//	                                https://<host>/callback
//	cli               -> http://127.0.0.1/callback, http://localhost/callback
//	desktop           -> <scheme>://oauth/<app>
//	service           -> none
func redirectURIs(org OrgConfig, app AppConfig) []string {
	switch app.Type {
	case TypeSPA, TypeConfidential:
		uris := make([]string, 0, len(app.Hosts)*3)
		for _, h := range app.Hosts {
			uris = append(uris,
				"https://"+h+"/auth/callback",
				"https://"+h+"/api/auth/callback/"+org.Name,
				"https://"+h+"/callback",
			)
		}
		return uris
	case TypeCLI:
		return []string{"http://127.0.0.1/callback", "http://localhost/callback"}
	case TypeDesktop:
		return []string{org.DeepLinkScheme + "://oauth/" + app.App}
	default: // service
		return nil
	}
}

// grantTypes derives the OAuth grant set from the type. Public clients use the
// authorization-code + refresh-token pair (with PKCE); confidential clients add
// client_credentials; service clients use client_credentials alone.
func grantTypes(t AppType) []string {
	switch t {
	case TypeService:
		return []string{"client_credentials"}
	case TypeConfidential:
		return []string{"authorization_code", "refresh_token", "client_credentials"}
	default: // spa, cli, desktop
		return []string{"authorization_code", "refresh_token"}
	}
}

// SigninMethod mirrors the IAM application signin-method row.
type SigninMethod struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Rule        string `json:"rule"`
}

// defaultSigninMethods is the login surface every interactive app exposes:
// password plus verification-code. The verification-code method is what renders
// the email/phone switch on the login page.
func defaultSigninMethods() []*SigninMethod {
	return []*SigninMethod{
		{Name: "Password", DisplayName: "Password", Rule: "All"},
		{Name: "Verification code", DisplayName: "Verification code", Rule: "All"},
	}
}

// OrgPayload is the subset of the IAM Organization object the reconciler
// writes to /v1/iam/add-organization.
type OrgPayload struct {
	Owner              string   `json:"owner"`
	Name               string   `json:"name"`
	DisplayName        string   `json:"displayName"`
	WebsiteUrl         string   `json:"websiteUrl"`
	PasswordType       string   `json:"passwordType"`
	Languages          []string `json:"languages"`
	Tags               []string `json:"tags"`
	EnableSoftDeletion bool     `json:"enableSoftDeletion"`
	IsProfilePublic    bool     `json:"isProfilePublic"`
}

// AppPayload is the subset of the IAM Application object the reconciler POSTs
// to /v1/iam/add-application. Providers is intentionally absent: identity-
// provider wiring is a separate concern with its own reconciler.
type AppPayload struct {
	Owner            string          `json:"owner"`
	Name             string          `json:"name"`
	Organization     string          `json:"organization"`
	DisplayName      string          `json:"displayName"`
	HomepageUrl      string          `json:"homepageUrl"`
	Cert             string          `json:"cert"`
	ClientId         string          `json:"clientId"`
	RedirectUris     []string        `json:"redirectUris"`
	GrantTypes       []string        `json:"grantTypes"`
	TokenFormat      string          `json:"tokenFormat"`
	EnablePassword   bool            `json:"enablePassword"`
	EnableSignUp     bool            `json:"enableSignUp"`
	EnableCodeSignin bool            `json:"enableCodeSignin"`
	SigninMethods    []*SigninMethod `json:"signinMethods"`
}

// buildOrgPayload renders the org row from declared data plus org conventions.
func buildOrgPayload(owner string, org OrgConfig) *OrgPayload {
	return &OrgPayload{
		Owner:              owner,
		Name:               org.Name,
		DisplayName:        orgDisplayName(org),
		WebsiteUrl:         org.Homepage,
		PasswordType:       defaultPasswordTyp,
		Languages:          defaultLanguages,
		Tags:               []string{},
		EnableSoftDeletion: false,
		IsProfilePublic:    false,
	}
}

// buildAppPayload renders the application row by combining declared data with
// the type's derived OAuth shape and the shared defaults.
func buildAppPayload(owner string, org OrgConfig, app AppConfig) *AppPayload {
	id := ClientID(org.Name, app.App)
	p := &AppPayload{
		Owner:        owner,
		Name:         id,
		Organization: org.Name,
		DisplayName:  appDisplayName(org, app),
		HomepageUrl:  org.Homepage,
		Cert:         defaultCert,
		ClientId:     id,
		RedirectUris: redirectURIs(org, app),
		GrantTypes:   grantTypes(app.Type),
		TokenFormat:  defaultTokenFormat,
	}
	if app.Type.interactive() {
		p.EnablePassword = true
		p.EnableSignUp = true
		p.EnableCodeSignin = true
		p.SigninMethods = defaultSigninMethods()
	}
	return p
}

func orgDisplayName(org OrgConfig) string {
	if s := strings.TrimSpace(org.DisplayName); s != "" {
		return s
	}
	return org.Name
}

func appDisplayName(org OrgConfig, app AppConfig) string {
	return strings.TrimSpace(orgDisplayName(org) + " " + title(app.App))
}

// title upper-cases the first rune of s (ASCII-friendly, dependency-free).
func title(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
