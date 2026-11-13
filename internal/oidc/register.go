// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathRegister is the RFC 7591 dynamic client registration endpoint: an MCP
// client (Claude.ai, ChatGPT, Codex, Cursor, VS Code, ...) that holds no
// client_id posts its metadata here and gets one, then runs the ordinary
// authorization-code flow with PKCE.
const PathRegister = "/v1/iam/oauth/register"

// EnvRegistration turns registration on for a deployment and says where its
// clients live:
//
//	IAM_REGISTRATION={"organization":"hanzo","signinUrl":"https://hanzo.ai/login","providers":"hanzo-app"}
//
// organization owns every registered client and signs its tokens (cert-<org>).
// signinUrl is the page a registered client's authorize request is handed to; it
// is followed only where IAM signs people in (hostedLoginTarget), so it can name
// the brand's own site and nothing else. providers names the application whose
// social sign-in methods (Google, GitHub, ...) a registered client offers, so a
// person who signs in that way on the brand's page can do so for a client too;
// they sign people in and never up. Unset, the endpoint answers 404 and
// discovery does not advertise it: a deployment opts in, it is never open by
// default.
const EnvRegistration = "IAM_REGISTRATION"

// registrar is a deployment's registration policy, read once at route time.
type registrar struct {
	Organization string `json:"organization"`
	SigninUrl    string `json:"signinUrl"`
	Providers    string `json:"providers"`
}

// registration is the policy discovery advertises and the endpoint enforces. Nil
// is registration off.
var registration atomic.Pointer[registrar]

// registerCap bounds the NEW clients one address and one network may register in a
// window. A registration that repeats metadata already on file creates nothing and
// counts nothing, which is what lets a hosted client with one egress address
// (every Claude.ai user registers the same name and callback) pass untouched while
// a script minting distinct clients is stopped.
//
// Global bounds all of them together, because addresses are cheap and every row is a
// scan on every sign-in; past it nobody registers a new client until the window
// drops one, which costs a hostile caller nothing it had and a genuine one a retry.
var registerCap = struct {
	IP, Subnet, Global int
	Window             time.Duration
}{IP: 20, Subnet: 100, Global: 600, Window: time.Hour}

// The scopes a registered client can ever hold. Identity and a refresh token, no
// more: what a token may do is decided by its user, not by a scope the client
// invented.
var registerScopes = []string{"openid", "profile", "email", "offline_access"}

// registerGrants are the grants a registered public client may ask for.
var registerGrants = []string{"authorization_code", "refresh_token"}

const (
	maxRegisterBody     = 16 << 10
	maxRedirects        = 5
	maxRedirectLen      = 2048
	maxClientNameRunes  = 64
	defaultClientName   = "MCP client"
	registerRefreshDays = 30
)

// loadRegistrar reads EnvRegistration. Unset is off; a value that does not read is
// off too, and logged, so a typo closes the endpoint instead of opening one with a
// default nobody wrote down.
func loadRegistrar() *registrar {
	raw := strings.TrimSpace(os.Getenv(EnvRegistration))
	if raw == "" {
		return nil
	}
	var r registrar
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		slog.Error("iam: "+EnvRegistration+" unreadable; dynamic registration stays off", "err", err)
		return nil
	}
	r.Organization = strings.TrimSpace(r.Organization)
	if r.Organization == "" || strings.ContainsAny(r.Organization, "/ ") {
		slog.Error("iam: " + EnvRegistration + " names no organization; dynamic registration stays off")
		return nil
	}
	if err := schema.CheckSigninUrl(r.SigninUrl); err != nil {
		slog.Error("iam: "+EnvRegistration+" signinUrl unusable; dynamic registration stays off", "err", err)
		return nil
	}
	return &r
}

// routeRegister serves PathRegister when the deployment turned registration on.
func routeRegister(r *zip.Group, db orm.DB) {
	reg := loadRegistrar()
	registration.Store(reg)
	if reg == nil {
		return
	}
	r.Raw(http.MethodPost, PathRegister, registerHandler(db, reg))
}

// clientMetadata is the RFC 7591 §2 request. Fields a public PKCE client has no
// use for (jwks, contacts, software_statement, logo_uri, ...) are not read: a
// server that stored a client-supplied URL would be one that fetches or renders it.
type clientMetadata struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

// registrationError is a refusal with its RFC 7591 §3.2.2 code.
type registrationError struct{ code, desc string }

func (e *registrationError) Error() string { return e.code + ": " + e.desc }

func reject(code, format string, a ...any) *registrationError {
	return &registrationError{code, fmt.Sprintf(format, a...)}
}

// registerHandler registers a client for itself — the standard way an MCP client
// that has never met this server obtains a client_id (RFC 7591).
//
// What it will register is deliberately small. A PUBLIC client, authenticated by
// PKCE alone, whose redirect URIs are https or loopback, that asks for the
// authorization-code grant (and its refresh), for the identity scopes and no more.
// Anything else in the request is refused or narrowed, and the response says what
// was kept (§3.2.1: the server may substitute values).
//
// The client_id is a digest of what was registered, so the same metadata always
// answers the same client and a repeat creates no row.
//
// A registered client is untrusted until a person says otherwise, and the
// authorization endpoint treats it so: it is never answered from a session, so
// the person types their credential for it every time, and its
// name on the page carries the host it returns to.
func registerHandler(db orm.DB, reg *registrar) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		if len(c.Body()) > maxRegisterBody {
			return registerFail(c, http.StatusRequestEntityTooLarge, reject("invalid_client_metadata", "the request is too large"))
		}
		var in clientMetadata
		if err := json.Unmarshal(c.Body(), &in); err != nil {
			return registerFail(c, http.StatusBadRequest, reject("invalid_client_metadata", "the body must be a JSON object"))
		}
		app, err := newClient(reg, in)
		if err != nil {
			return registerFail(c, http.StatusBadRequest, err)
		}
		// A client registered where authorize would not follow its sign-in page
		// would land its people on the issuer's page instead of the brand's. That is
		// a registration the operator did not mean, so it is refused rather than
		// stored.
		if !signinFollowed(c, reg.SigninUrl) {
			slog.Error("iam: dynamic registration refused: signinUrl is not a sign-in origin of this issuer",
				"signinUrl", reg.SigninUrl, "host", c.Host())
			return tokenError(c, http.StatusServiceUnavailable, "temporarily_unavailable", "registration is not available here")
		}

		ctx := c.Context()
		if err := offerProviders(ctx, db, app, reg.Providers); err != nil {
			slog.Error("iam: dynamic registration failed", "err", err)
			return tokenError(c, http.StatusInternalServerError, "server_error", "")
		}
		client := httpx.Client(c.Header("CF-Connecting-IP"), c.Header("X-Forwarded-For"))
		id := app.ClientId
		app, err = lodge(ctx, db, app, client)
		var held *registerCapped
		if err != nil && !errors.As(err, &held) {
			// Two identical first registrations race: one row wins, and the other
			// is answered with it rather than with its own insert's refusal.
			if have, e := store.ListApplicationsByClientId(ctx, db, id); e == nil && len(have) > 0 {
				app, err = have[0], nil
			}
		}
		switch {
		case errors.As(err, &held):
			c.SetHeader("Retry-After", fmt.Sprint(int64(held.retry/time.Second)+1))
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "temporarily_unavailable", "error_description": held.Error()})
		case err != nil:
			slog.Error("iam: dynamic registration failed", "err", err)
			return tokenError(c, http.StatusInternalServerError, "server_error", "")
		}
		return c.JSON(http.StatusCreated, answerOf(app))
	}
}

// signinFollowed reports whether authorize would hand a request to signin: empty
// is the issuer's own page, and a URL is followed only on an origin the operator
// configured for this request's issuer (hostedLoginTarget).
func signinFollowed(c *zip.Ctx, signin string) bool {
	if signin == "" {
		return true
	}
	iss, err := tokenIssuer(c)
	if err != nil {
		return false
	}
	u, err := url.Parse(signin)
	if err != nil {
		return false
	}
	origin, err := signinOrigin("https://" + u.Host)
	return err == nil && configuredSignin(origin, normalizeIssuer(iss))
}

func registerFail(c *zip.Ctx, status int, err error) error {
	var re *registrationError
	if errors.As(err, &re) {
		return tokenError(c, status, re.code, re.desc)
	}
	return tokenError(c, http.StatusInternalServerError, "server_error", "")
}

// newClient is the application a request registers, or the reason it may not.
func newClient(reg *registrar, in clientMetadata) (*schema.Application, error) {
	uris, err := redirectsOf(in.RedirectURIs)
	if err != nil {
		return nil, err
	}
	grants, err := narrow("grant_types", in.GrantTypes, registerGrants, registerGrants)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(grants, "authorization_code") {
		return nil, reject("invalid_client_metadata", "grant_types must include authorization_code")
	}
	if len(in.ResponseTypes) > 0 && (len(in.ResponseTypes) != 1 || in.ResponseTypes[0] != "code") {
		return nil, reject("invalid_client_metadata", "response_types must be [\"code\"]")
	}
	scopes, err := scopesOf(in.Scope)
	if err != nil {
		return nil, err
	}
	name := nameOf(in.ClientName)

	id := digestOf(reg.Organization, name, uris, grants, scopes)
	a := &schema.Application{
		Owner:        reg.Organization,
		Name:         id,
		ClientId:     id,
		Organization: reg.Organization,
		DisplayName:  name + " (" + hostsOf(uris) + ")",
		Cert:         "cert-" + reg.Organization,
		GrantTypes:   grants,
		RedirectUris: uris,
		IsShared:     true,
		SigninUrl:    reg.SigninUrl,
		Tags:         []string{schema.TagDynamic},
		CreatedTime:  time.Now().UTC().Format(time.RFC3339),

		EnablePassword:       true,
		ExpireInHours:        schema.DefaultExpireInHours,
		RefreshExpireInHours: registerRefreshDays * 24,
	}
	for _, s := range scopes {
		a.Scopes = append(a.Scopes, &schema.ScopeItem{Name: s})
	}
	return a, nil
}

// offerProviders gives a new client the sign-in methods of the application the
// deployment names, as sign-in only: a client registered by anyone must not be a
// way to create accounts. The template not being there leaves the client with the
// password alone, and says so.
func offerProviders(ctx context.Context, db orm.DB, a *schema.Application, template string) error {
	if template == "" {
		return nil
	}
	t, err := store.GetApplicationByClientId(ctx, db, template)
	if err != nil {
		return err
	}
	if t == nil {
		slog.Warn("iam: dynamic registration: the providers application does not exist", "providers", template)
		return nil
	}
	for _, p := range t.Providers {
		if p != nil && p.CanSignIn {
			a.Providers = append(a.Providers, &schema.ProviderItem{Owner: p.Owner, Name: p.Name, CanSignIn: true})
		}
	}
	return nil
}

// redirectsOf validates the redirect URIs: https, or http on the loopback
// interface (RFC 8252 §7.3), and nothing else. A custom scheme is any app on the
// device's to claim, a wildcard or a fragment widens what a code can be sent to,
// and an https address that is an IP literal names no organization at all.
func redirectsOf(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, reject("invalid_redirect_uri", "redirect_uris is required")
	}
	if len(in) > maxRedirects {
		return nil, reject("invalid_redirect_uri", "at most %d redirect_uris", maxRedirects)
	}
	var out []string
	for _, raw := range in {
		if len(raw) > maxRedirectLen {
			return nil, reject("invalid_redirect_uri", "a redirect_uri is too long")
		}
		u, err := url.Parse(raw)
		if err != nil || u.Opaque != "" || u.Host == "" || u.User != nil || u.Fragment != "" || u.ForceQuery ||
			strings.ContainsAny(raw, " \t\r\n*\\") {
			return nil, reject("invalid_redirect_uri", "%q is not an absolute https or loopback URI without userinfo or fragment", raw)
		}
		host := strings.ToLower(u.Hostname())
		switch u.Scheme {
		case "https":
			if !publicHost(host) {
				return nil, reject("invalid_redirect_uri", "%q does not name a public host", raw)
			}
		case "http":
			if host != "127.0.0.1" && host != "::1" && host != "localhost" {
				return nil, reject("invalid_redirect_uri", "%q is http and not on the loopback interface", raw)
			}
		default:
			return nil, reject("invalid_redirect_uri", "%q is neither https nor loopback", raw)
		}
		if !slices.Contains(out, raw) {
			out = append(out, raw)
		}
	}
	return out, nil
}

// publicHost reports whether host is a DNS name of the public internet, written
// in ASCII (an internationalized name in its xn-- form, which a person reads as
// what it is and not as the brand it imitates). An address in any spelling, a
// single label and localhost are not: the last label of a name has a letter in it,
// which no IPv4 spelling (127.1, 0x7f.0.0.1, 2130706433) has.
func publicHost(host string) bool {
	if host == "localhost" || !strings.Contains(host, ".") || host != strings.TrimSuffix(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, r := range host {
		if !(r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	last := host[strings.LastIndex(host, ".")+1:]
	return strings.ContainsAny(last, "abcdefghijklmnopqrstuvwxyz")
}

// narrow keeps the members of asked that are allowed; an empty ask takes def. A
// member outside allowed is refused rather than dropped: a client that asked for
// the implicit grant or client_credentials wants something this endpoint will not
// give, and an answer that silently differs would register it for a different job.
func narrow(field string, asked, allowed, def []string) ([]string, error) {
	if len(asked) == 0 {
		return slices.Clone(def), nil
	}
	var out []string
	for _, v := range asked {
		if !slices.Contains(allowed, v) {
			return nil, reject("invalid_client_metadata", "%s: %q is not available to a registered client", field, v)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out, nil
}

// scopesOf keeps the requested scopes a registered client may hold. Asking for
// none takes them all; asking only for scopes it may not hold is refused.
func scopesOf(scope string) ([]string, error) {
	asked := strings.Fields(scope)
	if len(asked) == 0 {
		return slices.Clone(registerScopes), nil
	}
	var out []string
	for _, s := range registerScopes {
		if slices.Contains(asked, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, reject("invalid_client_metadata", "scope: none of %q is available to a registered client", scope)
	}
	return out, nil
}

// nameOf is the name a registered client is shown under: printable, one line, short.
// It is the client's own word for itself, so it is never the page's only line about
// it (see DisplayName).
func nameOf(raw string) string {
	var b strings.Builder
	space := false
	for _, r := range raw {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
		case unicode.IsPrint(r) && !unicode.IsControl(r) && r != '<' && r != '>':
			if space {
				b.WriteByte(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	name := []rune(b.String())
	if len(name) > maxClientNameRunes {
		name = name[:maxClientNameRunes]
	}
	if len(name) == 0 {
		return defaultClientName
	}
	return string(name)
}

// hostsOf is every place a registered client can send the person back to, as a
// person reads it: each host once, and "localhost" for any loopback address. All of
// them, because any registered address may receive the code, so a name that showed
// only the first would let a second one go unseen.
func hostsOf(redirects []string) string {
	var hosts []string
	for _, r := range redirects {
		u, err := url.Parse(r)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		switch h {
		case "127.0.0.1", "::1", "localhost":
			h = "localhost"
		}
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts)
	return strings.Join(hosts, ", ")
}

// digestOf is a digest of everything a registration states, so equal metadata is
// one client. The redirect set is sorted: the order a client lists them in says
// nothing.
func digestOf(org, name string, uris, grants, scopes []string) string {
	sorted := slices.Clone(uris)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		org, name, strings.Join(sorted, " "), strings.Join(grants, " "), strings.Join(scopes, " ")}, "\n")))
	return "mcp-" + hex.EncodeToString(sum[:12])
}

// answerOf is the RFC 7591 §3.2.1 response: what was registered, which may differ
// from what was asked.
func answerOf(a *schema.Application) map[string]any {
	scopes := make([]string, 0, len(a.Scopes))
	for _, s := range a.Scopes {
		scopes = append(scopes, s.Name)
	}
	issued := time.Now().Unix()
	if t, err := time.Parse(time.RFC3339, a.CreatedTime); err == nil {
		issued = t.Unix()
	}
	return map[string]any{
		"client_id":                  a.ClientId,
		"client_id_issued_at":        issued,
		"client_name":                a.DisplayName,
		"redirect_uris":              a.RedirectUris,
		"grant_types":                a.GrantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      strings.Join(scopes, " "),
	}
}

// registerCapped is a registration the cap refused, and how long until the bound
// that held it admits one more.
type registerCapped struct {
	bound string
	retry time.Duration
}

func (e *registerCapped) Error() string {
	if e.bound == "service" {
		return "too many new clients registered; try again later"
	}
	return "too many new clients registered from this " + e.bound + "; try again later"
}

// lodge stores the client and records the registration, or finds the client
// already on file and answers that one. The cap is counted in the transaction that
// writes the row and its ledger entry, so concurrent registrations cannot all pass
// one count.
func lodge(ctx context.Context, db orm.DB, a *schema.Application, client netip.Addr) (*schema.Application, error) {
	stored := a
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		have, err := store.ListApplicationsByClientId(ctx, tx, a.ClientId)
		if err != nil {
			return err
		}
		if len(have) > 0 {
			stored = have[0]
			return nil
		}
		addr, network := ledgerKey(client)
		now := time.Now()
		since := now.Add(-registerCap.Window)
		for _, b := range []struct {
			bound string
			limit int
			match []string
		}{
			{"address", registerCap.IP, []string{"ClientIp", addr}},
			{"network", registerCap.Subnet, []string{"Object", network}},
			{"service", registerCap.Global, nil},
		} {
			n, err := store.Recorded(ctx, tx, schema.ActionRegisterClient, since, b.match...)
			if err != nil {
				return err
			}
			if n >= b.limit {
				return &registerCapped{bound: b.bound, retry: registerCap.Window}
			}
		}
		row := orm.New[schema.Application](tx)
		model := row.Model
		*row = *a
		row.Model = model
		row.SetId(a.Owner + "/" + a.Name)
		if err := row.CreateCtx(ctx); err != nil {
			return err
		}
		return store.Append(ctx, tx, &schema.AuditLog{
			Owner:        a.Owner,
			Organization: a.Organization,
			User:         a.Owner + "/" + a.Name,
			ClientIp:     addr,
			Object:       network,
			Action:       schema.ActionRegisterClient,
			Method:       http.MethodPost,
			RequestUri:   PathRegister,
			Response:     a.DisplayName + " -> " + strings.Join(a.RedirectUris, " "),
			StatusCode:   http.StatusCreated,
		})
	})
	return stored, err
}

// ledgerKey is the client's address and its network as the ledger files them: an
// IPv4 /24 or an IPv6 /64. The zero client files both as "", which every such
// request shares.
func ledgerKey(ip netip.Addr) (addr, network string) {
	if !ip.IsValid() {
		return "", ""
	}
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return ip.String(), p.String()
}
