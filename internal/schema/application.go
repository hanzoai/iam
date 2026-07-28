// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// This file carries the full Phase-1 field set for the `applications` entity
// (v1 Casdoor `application`). The kind is registered once, centrally, in
// schema.go's init(); nothing is registered here.
//
// Storage model: hanzoai/orm persists each Application as one JSON document in
// the shared _entities table (kind = "applications"), so v1 xorm column types
// (varchar/mediumtext/text/bool/int) carry no meaning and are dropped. Nested
// slices and structs live inline in that document — no serialize sibling is
// needed. The three v1 xorm:"-" members (OrganizationObj, CertPublicKey,
// CertObj) are read-time joins, never persisted; they are marked orm:"-" and
// omitempty so a write round-trips them as absent.

package schema

import (
	"net/url"

	"github.com/hanzoai/orm"
)

// SigninMethod is one enabled authentication method on an application
// (e.g. Password, Verification code, WebAuthn, Face ID) with its display
// label and applicability rule.
type SigninMethod struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Rule        string `json:"rule"`
}

// SignupItem is one field rendered on the application's sign-up form, with
// its visibility, requirement, and validation rule.
type SignupItem struct {
	Name        string   `json:"name"`
	Visible     bool     `json:"visible"`
	Required    bool     `json:"required"`
	Prompted    bool     `json:"prompted"`
	Type        string   `json:"type"`
	CustomCss   string   `json:"customCss"`
	Label       string   `json:"label"`
	Placeholder string   `json:"placeholder"`
	Options     []string `json:"options"`
	Regex       string   `json:"regex"`
	Rule        string   `json:"rule"`
}

// SigninItem is one element of the application's customizable sign-in page
// layout, carrying its per-element CSS and rule.
type SigninItem struct {
	Name        string `json:"name"`
	Visible     bool   `json:"visible"`
	Label       string `json:"label"`
	CustomCss   string `json:"customCss"`
	Placeholder string `json:"placeholder"`
	Rule        string `json:"rule"`
	IsCustom    bool   `json:"isCustom"`
}

// SamlItem is one SAML assertion attribute mapping emitted for this
// application.
type SamlItem struct {
	Name       string `json:"name"`
	NameFormat string `json:"nameFormat"`
	Value      string `json:"value"`
}

// JwtItem is one extra claim projected into issued access/ID tokens.
type JwtItem struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Value    string `json:"value"`
	Type     string `json:"type"`
}

// ScopeItem is one OAuth2/OIDC scope the application may request, plus the
// MCP tool names that scope authorizes.
type ScopeItem struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Tools       []string `json:"tools"`
}

// ProviderItem binds a federated identity Provider into an application and
// records how it may be used (sign-up/sign-in/unlink), its binding rule, and
// the resolved Provider on read.
type ProviderItem struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`

	CanSignUp    bool      `json:"canSignUp"`
	CanSignIn    bool      `json:"canSignIn"`
	CanUnlink    bool      `json:"canUnlink"`
	BindingRule  *[]string `json:"bindingRule"`
	CountryCodes []string  `json:"countryCodes"`
	Prompted     bool      `json:"prompted"`
	SignupGroup  string    `json:"signupGroup"`
	Rule         string    `json:"rule"`
	Provider     *Provider `json:"provider" orm:"-"`
}

// ScopeDescription documents one custom scope surfaced on the consent screen.
type ScopeDescription struct {
	Scope       string `json:"scope"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

// Application is an OAuth2/OIDC client and its hosted-login configuration
// (v1 Casdoor `application`). It is owner-scoped and uniquely named within its
// owner; the (Owner, Name) pair is the natural key, materialized as the orm id
// "<owner>/<name>". Every field below is field-complete with v1 so no auth
// configuration is lost across the cutover.
type Application struct {
	orm.Model[Application]

	Owner       string `json:"owner"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime"`

	DisplayName                  string          `json:"displayName"`
	Category                     string          `json:"category"`
	Type                         string          `json:"type"`
	Scopes                       []*ScopeItem    `json:"scopes"`
	Logo                         string          `json:"logo"`
	Title                        string          `json:"title"`
	Favicon                      string          `json:"favicon"`
	Order                        int             `json:"order"`
	HomepageUrl                  string          `json:"homepageUrl"`
	Description                  string          `json:"description"`
	Organization                 string          `json:"organization"`
	Cert                         string          `json:"cert"`
	DefaultGroup                 string          `json:"defaultGroup"`
	HeaderHtml                   string          `json:"headerHtml"`
	EnablePassword               bool            `json:"enablePassword"`
	EnableSignUp                 bool            `json:"enableSignUp"`
	DisableSignin                bool            `json:"disableSignin"`
	EnableSigninSession          bool            `json:"enableSigninSession"`
	EnableAutoSignin             bool            `json:"enableAutoSignin"`
	EnableCodeSignin             bool            `json:"enableCodeSignin"`
	EnableExclusiveSignin        bool            `json:"enableExclusiveSignin"`
	EnableSamlCompress           bool            `json:"enableSamlCompress"`
	EnableSamlC14n10             bool            `json:"enableSamlC14n10"`
	EnableSamlPostBinding        bool            `json:"enableSamlPostBinding"`
	DisableSamlAttributes        bool            `json:"disableSamlAttributes"`
	EnableSamlAssertionSignature bool            `json:"enableSamlAssertionSignature"`
	UseEmailAsSamlNameId         bool            `json:"useEmailAsSamlNameId"`
	EnableWebAuthn               bool            `json:"enableWebAuthn"`
	EnableLinkWithEmail          bool            `json:"enableLinkWithEmail"`
	OrgChoiceMode                string          `json:"orgChoiceMode"`
	SamlReplyUrl                 string          `json:"samlReplyUrl"`
	Providers                    []*ProviderItem `json:"providers"`
	SigninMethods                []*SigninMethod `json:"signinMethods"`
	SignupItems                  []*SignupItem   `json:"signupItems"`
	SigninItems                  []*SigninItem   `json:"signinItems"`
	GrantTypes                   []string        `json:"grantTypes"`
	OrganizationObj              *Organization   `json:"organizationObj,omitempty" orm:"-"`
	CertPublicKey                string          `json:"certPublicKey,omitempty" orm:"-"`
	Tags                         []string        `json:"tags"`
	SamlAttributes               []*SamlItem     `json:"samlAttributes"`
	SamlHashAlgorithm            string          `json:"samlHashAlgorithm"`
	IsShared                     bool            `json:"isShared"`
	IpRestriction                string          `json:"ipRestriction"`

	// ClientId is the OAuth2/OIDC client identifier and the GLOBAL key every
	// confidential-client resolver authenticates against (store.GetApplicationByClientId,
	// the mint gates, Basic auth). It MUST be globally unique across ALL owners — a
	// collision would let one app shadow another at that key. This store persists each
	// entity as a JSON document in a shared table, so there is no per-field column to
	// carry a DB UNIQUE index; uniqueness is enforced at the write in
	// applications.Create/Update (ensureClientIdUnique), exactly as the (owner,name)
	// natural key is, and store.GetApplicationByClientId resolves admin-preferring as
	// defense-in-depth.
	ClientId             string     `json:"clientId"`
	ClientSecret         string     `json:"clientSecret"`
	ClientCert           string     `json:"clientCert"`
	RedirectUris         []string   `json:"redirectUris"`
	ForcedRedirectOrigin string     `json:"forcedRedirectOrigin"`
	TokenFormat          string     `json:"tokenFormat"`
	TokenSigningMethod   string     `json:"tokenSigningMethod"`
	TokenFields          []string   `json:"tokenFields"`
	TokenAttributes      []*JwtItem `json:"tokenAttributes"`
	ExpireInHours        float64    `json:"expireInHours"`
	RefreshExpireInHours float64    `json:"refreshExpireInHours"`
	CookieExpireInHours  int64      `json:"cookieExpireInHours"`
	SignupUrl            string     `json:"signupUrl"`
	SigninUrl            string     `json:"signinUrl"`
	ForgetUrl            string     `json:"forgetUrl"`
	AffiliationUrl       string     `json:"affiliationUrl"`
	IpWhitelist          string     `json:"ipWhitelist"`
	TermsOfUse           string     `json:"termsOfUse"`
	SignupHtml           string     `json:"signupHtml"`
	SigninHtml           string     `json:"signinHtml"`
	ThemeData            *ThemeData `json:"themeData"`
	FooterHtml           string     `json:"footerHtml"`

	FormCss                 string `json:"formCss"`
	FormCssMobile           string `json:"formCssMobile"`
	FormOffset              int    `json:"formOffset"`
	FormSideHtml            string `json:"formSideHtml"`
	FormBackgroundUrl       string `json:"formBackgroundUrl"`
	FormBackgroundUrlMobile string `json:"formBackgroundUrlMobile"`

	FailedSigninLimit      int `json:"failedSigninLimit"`
	FailedSigninFrozenTime int `json:"failedSigninFrozenTime"`
	CodeResendTimeout      int `json:"codeResendTimeout"`

	CustomScopes []*ScopeDescription `json:"customScopes"`

	Environment string `json:"environment"`
	Project     string `json:"project"`

	Domain       string   `json:"domain"`
	OtherDomains []string `json:"otherDomains"`
	UpstreamHost string   `json:"upstreamHost"`
	SslMode      string   `json:"sslMode"`
	SslCert      string   `json:"sslCert"`

	CertObj *Cert `json:"certObj,omitempty" orm:"-"`
}

// GetId returns the owner-scoped natural key "<owner>/<name>", the value used
// as this entity's orm id.
func (a *Application) GetId() string {
	return a.Owner + "/" + a.Name
}

// IsRedirectUriValid reports whether redirectUri is one of the application's
// registered redirect URIs (RFC 6749 3.1.2.3). Match is exact string equality —
// never a host-suffix, substring, or regex match — so a trusted origin can never
// be leveraged to redeem another app's authorization code. New callbacks are
// added by registering the exact URI, nothing else.
//
// The ONE exception is the loopback interface, where RFC 8252 §7.3 requires the
// server to "allow any port": a native app binds an ephemeral port at runtime
// (hanzo/cli binds 127.0.0.1:0) and therefore CANNOT know its redirect_uri at
// registration time. Exact matching made that flow unsatisfiable — the
// provisioner registers the portless http://127.0.0.1/callback (see
// internal/provision, TypeCLI), the CLI sends http://127.0.0.1:51234/callback,
// authorize answered 400 invalid_redirect_uri, the browser never came back, and
// the CLI blocked on accept() forever. That hang was this comparison.
func (a *Application) IsRedirectUriValid(redirectUri string) bool {
	if redirectUri == "" {
		return false
	}
	for _, registered := range a.RedirectUris {
		if registered == "" {
			continue
		}
		if registered == redirectUri || loopbackPortAgnosticMatch(registered, redirectUri) {
			return true
		}
	}
	return false
}

// loopbackPortAgnosticMatch reports whether two http loopback URIs are identical
// once the port is ignored (RFC 8252 §7.3). Everything except the port must still
// match exactly — scheme, host, path, query and fragment — so this widens the
// registration only along the one axis the app cannot control.
//
// Scoped deliberately to the IP LITERALS 127.0.0.1 and ::1. "localhost" is
// excluded because it resolves through DNS/hosts, so it is not provably the local
// machine (RFC 8252 §8.3 says not to rely on it); a registered localhost URI still
// matches exactly, it just does not gain the port wildcard.
func loopbackPortAgnosticMatch(registered, requested string) bool {
	r, err := url.Parse(registered)
	if err != nil {
		return false
	}
	q, err := url.Parse(requested)
	if err != nil {
		return false
	}
	// Both sides must be loopback: a registered loopback URI must never be
	// satisfied by a remote host, and vice versa.
	if !isLoopbackLiteral(r) || !isLoopbackLiteral(q) {
		return false
	}
	return r.Hostname() == q.Hostname() &&
		r.EscapedPath() == q.EscapedPath() &&
		r.RawQuery == q.RawQuery &&
		r.Fragment == q.Fragment
}

// isLoopbackLiteral reports whether u is an http URI whose host is a loopback IP
// literal. http (not https) because a loopback listener has no usable certificate.
func isLoopbackLiteral(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1":
		return true
	}
	return false
}

// IsPasswordEnabled reports whether password sign-in is available: the explicit
// EnablePassword flag when no per-method list is configured, otherwise the
// presence of a "Password" method in SigninMethods.
func (a *Application) IsPasswordEnabled() bool {
	if len(a.SigninMethods) == 0 {
		return a.EnablePassword
	}
	for _, m := range a.SigninMethods {
		if m.Name == "Password" {
			return true
		}
	}
	return false
}
