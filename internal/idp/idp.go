// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package idp talks to a third-party identity provider: it builds the upstream
// authorize redirect, exchanges the returned code for a token, and reads back
// one Identity. It is the ONLY place that knows a provider's dialect, and it
// knows nothing about IAM's own protocol, accounts, or linking rules — those
// live in internal/oidc and internal/social respectively (HIP-0111 §7).
//
// The Identity it returns carries Verified: whether the PROVIDER asserts the
// email address is verified. That single bit is the reason this layer exists —
// internal/social links an account by a verified email and by nothing else, so
// an unverified address must be reported as such rather than silently promoted.
// All three connectors publish the signal (Google `verified_email`, GitHub's
// per-address `verified` flag, GitLab `confirmed_at`); each one is read here.
package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/hanzoai/iam2/internal/schema"
)

// PathCallback is the redirect URI every hop comes back to. This exact URL
// (https://hanzo.id/callback) is registered in Google's, GitHub's and GitLab's
// OAuth application consoles, so it is an EXTERNAL constant: renaming it means
// re-registering upstream. It is served at the root, like /healthz.
const PathCallback = "/callback"

// ErrKind is returned for a provider type this package does not connect to.
// iam2 carries exactly three connectors; an unknown type fails closed rather
// than dead-ending a browser at a half-configured button.
var ErrKind = errors.New("idp: unsupported provider type")

// readLimit bounds an upstream response body. A provider is a third party: its
// response is untrusted input, so the read is bounded rather than unbounded
// into memory.
const readLimit = 1 << 20

// Identity is one third-party account, normalized. Subject is the provider's
// own stable user id — the only unforgeable key, and the only one an account is
// ever re-matched by. Verified reports whether the provider asserts Email is a
// verified address; a false Verified means Email is descriptive only and can
// never select an existing account (internal/social/link.go).
type Identity struct {
	Subject  string
	Username string
	Display  string
	Email    string
	Verified bool
	Phone    string
	Avatar   string
}

// Connector is one provider's half of the authorization-code flow: send the
// browser out, trade the returned code for a token, read back the identity.
type Connector interface {
	// Auth is the upstream authorization URL to redirect the browser to. state
	// is the opaque handle the provider echoes back; challenge, when non-empty,
	// is the S256 PKCE challenge for the hop.
	Auth(state, challenge string) string
	// Exchange trades the returned code for an upstream token, replaying the
	// PKCE verifier when the hop used one.
	Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error)
	// Identify reads the account behind a token.
	Identify(ctx context.Context, tok *oauth2.Token) (*Identity, error)
}

// spec is one provider's dialect: its three endpoints, the scopes iam2 asks
// for, and how to read an identity back.
//
// The scope set belongs to the CONNECTOR, not to operator data: v1 ignores
// Provider.Scopes for these three and hard-codes the same values, so honoring
// the column here would let a stale or wrong seeded value silently break a
// sign-in that works today.
type spec struct {
	auth  string
	token string
	api   string
	scope []string
	read  func(context.Context, *conn, *oauth2.Token) (*Identity, error)
}

// connectors is the ONE table of supported providers — the single source of
// truth both Supports and Open read, so a type can never be answerable by one
// and unknown to the other. v1's other 25 Casdoor connectors are deliberately
// absent: iam2 federates Google, GitHub and GitLab.
var connectors = map[string]spec{
	"Google": {
		auth:  "https://accounts.google.com/o/oauth2/v2/auth",
		token: "https://oauth2.googleapis.com/token",
		api:   "https://www.googleapis.com/oauth2/v2/userinfo",
		scope: []string{"profile", "email"},
		read:  readGoogle,
	},
	"GitHub": {
		auth:  "https://github.com/login/oauth/authorize",
		token: "https://github.com/login/oauth/access_token",
		api:   "https://api.github.com/user",
		scope: []string{"user:email", "read:user"},
		read:  readGitHub,
	},
	"GitLab": {
		auth:  "https://gitlab.com/oauth/authorize",
		token: "https://gitlab.com/oauth/token",
		api:   "https://gitlab.com/api/v4/user",
		scope: []string{"read_user"},
		read:  readGitLab,
	},
}

// phoneScope reads a Google account's phone numbers through the People API.
// It is requested only under the DisableSsl flag, which v1 reuses as the
// Google phone-sync toggle; the lookup in readGoogle is gated on the same flag,
// so the scope asked for and the call made never diverge.
const phoneScope = "https://www.googleapis.com/auth/user.phonenumbers.read"

// Supports reports whether a provider type has a connector. The hint branch in
// the authorize endpoint calls this so a hint naming an unconnectable provider
// falls through to the hosted login instead of dead-ending.
func Supports(kind string) bool {
	_, ok := connectors[kind]
	return ok
}

// Open builds the connector for p. The redirect URI is DERIVED from origin +
// PathCallback rather than passed in, so the value sent to the provider at the
// authorize hop and the value replayed at the token exchange are the same bytes
// by construction — a mismatch is what makes an exchange fail with an opaque
// upstream 400 (RFC 6749 §4.1.3 requires the two to be identical).
func Open(p *schema.Provider, origin string) (Connector, error) {
	if p == nil {
		return nil, ErrKind
	}
	s, ok := connectors[p.Type]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKind, p.Type)
	}
	scope := s.scope
	if p.Type == "Google" && p.DisableSsl {
		scope = append(append([]string{}, scope...), phoneScope)
	}
	return &conn{
		kind: p.Type,
		cfg: oauth2.Config{
			ClientID:     p.ClientId,
			ClientSecret: p.ClientSecret,
			RedirectURL:  origin + PathCallback,
			Scopes:       scope,
			Endpoint: oauth2.Endpoint{
				AuthURL:   or(p.CustomAuthUrl, s.auth),
				TokenURL:  or(p.CustomTokenUrl, s.token),
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		api:   or(p.CustomUserInfoUrl, s.api),
		phone: p.DisableSsl,
		read:  s.read,
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// conn is the shared connector: the OAuth2 half (redirect + exchange) is
// RFC 6749 §4.1 and identical everywhere, so only the identity read varies and
// each provider supplies just that function.
type conn struct {
	kind  string
	cfg   oauth2.Config
	api   string
	phone bool
	read  func(context.Context, *conn, *oauth2.Token) (*Identity, error)
	http  *http.Client
}

func (c *conn) Auth(state, challenge string) string {
	opts := []oauth2.AuthCodeOption{}
	if challenge != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	return c.cfg.AuthCodeURL(state, opts...)
}

func (c *conn) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{}
	if verifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	return c.cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, c.http), code, opts...)
}

func (c *conn) Identify(ctx context.Context, tok *oauth2.Token) (*Identity, error) {
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("idp: no upstream access token")
	}
	return c.read(ctx, c, tok)
}

// get reads an upstream JSON endpoint as the token's bearer. The access token
// rides in the Authorization header and never in the query string, where it
// would be captured by upstream access logs and referrers.
func (c *conn) get(ctx context.Context, url string, tok *oauth2.Token, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return &upstream{kind: c.kind, url: url, status: resp.StatusCode, body: body}
	}
	return json.Unmarshal(body, v)
}

// upstream is a non-200 from a provider. It names the provider, endpoint and
// status so an operator can act on it — a GitHub App missing the account
// permissions answers GET /user with 403, and the old behavior (parsing the
// error body into an empty user) surfaced much later as a generic bad-password.
// It carries no token: the request's own credential never reaches the message.
type upstream struct {
	kind   string
	url    string
	status int
	body   []byte
}

func (e *upstream) Error() string {
	var msg struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(e.body, &msg)
	return fmt.Sprintf("idp: %s rejected GET %s (status %d): %s%s",
		e.kind, e.url, e.status, msg.Message, msg.Error)
}

// --- Google -----------------------------------------------------------------

// googleUser is the userinfo v2 shape. verified_email is Google's assertion
// that it owns the address; v1 parses this field and then drops it, which is
// what let an unverified address select an existing account.
type googleUser struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// googlePeople is the People API phone-number projection.
type googlePeople struct {
	PhoneNumbers []struct {
		CanonicalForm string `json:"canonicalForm"`
		Metadata      struct {
			Primary bool `json:"primary"`
		} `json:"metadata"`
	} `json:"phoneNumbers"`
}

const peopleAPI = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"

func readGoogle(ctx context.Context, c *conn, tok *oauth2.Token) (*Identity, error) {
	var g googleUser
	if err := c.get(ctx, c.api+"?alt=json", tok, &g); err != nil {
		return nil, err
	}
	if g.Email == "" {
		return nil, errors.New("idp: google returned no email")
	}
	id := &Identity{
		Subject:  g.Id,
		Username: g.Email, // Google has no handle; v1 uses the address
		Display:  g.Name,
		Email:    g.Email,
		Verified: g.VerifiedEmail,
		Avatar:   g.Picture,
	}
	if c.phone {
		id.Phone = googlePhone(ctx, c, tok)
	}
	return id, nil
}

// googlePhone returns the account's primary phone number in E.164, or "" when
// the account has none or the People API refuses. A phone is profile data only
// — it never selects an account — so a failed lookup degrades to empty rather
// than failing the sign-in.
//
// v1 additionally splits the number into a national number plus an ISO region
// code via a phone-metadata library; iam2 stores the canonical E.164 form and
// takes no dependency to re-derive what the string already encodes.
func googlePhone(ctx context.Context, c *conn, tok *oauth2.Token) string {
	var p googlePeople
	if err := c.get(ctx, peopleAPI, tok, &p); err != nil {
		return ""
	}
	for _, n := range p.PhoneNumbers {
		if n.Metadata.Primary {
			return n.CanonicalForm
		}
	}
	return ""
}

// --- GitHub -----------------------------------------------------------------

type githubUser struct {
	Id     int    `json:"id"`
	Login  string `json:"login"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Avatar string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

const githubNoreply = "users.noreply.github.com"

func readGitHub(ctx context.Context, c *conn, tok *oauth2.Token) (*Identity, error) {
	var g githubUser
	if err := c.get(ctx, c.api, tok, &g); err != nil {
		return nil, err
	}
	id := &Identity{
		Subject:  strconv.Itoa(g.Id),
		Username: g.Login,
		Display:  g.Name,
		Avatar:   g.Avatar,
	}
	// The public-profile email is published by GitHub only after the address is
	// verified, so it is a verified address — asserted here explicitly rather
	// than assumed by omission.
	if g.Email != "" {
		id.Email, id.Verified = g.Email, true
		return id, nil
	}
	var list []githubEmail
	if err := c.get(ctx, c.api+"/emails", tok, &list); err == nil {
		if addr := verifiedEmail(list); addr != "" {
			id.Email, id.Verified = addr, true
			return id, nil
		}
	}
	// No readable verified address: fall back to GitHub's canonical noreply
	// identifier so sign-up still has a unique handle. It is NOT verified — it
	// is an identifier, not a mailbox — so it can only ever name a new account,
	// never select an existing one.
	id.Email = fmt.Sprintf("%d+%s@%s", g.Id, g.Login, githubNoreply)
	id.Verified = false
	return id, nil
}

// verifiedEmail picks the account's primary verified address, else any verified
// address, ignoring the noreply alias (an identifier, not a mailbox). An
// unverified address is never returned.
func verifiedEmail(list []githubEmail) string {
	fallback := ""
	for _, a := range list {
		if !a.Verified || strings.Contains(a.Email, githubNoreply) {
			continue
		}
		if a.Primary {
			return a.Email
		}
		if fallback == "" {
			fallback = a.Email
		}
	}
	return fallback
}

// --- GitLab -----------------------------------------------------------------

// gitlabUser is the /api/v4/user shape. confirmed_at is the moment GitLab
// confirmed the address; v1 parses it and then drops it.
type gitlabUser struct {
	Id          int       `json:"id"`
	Username    string    `json:"username"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	Avatar      string    `json:"avatar_url"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

func readGitLab(ctx context.Context, c *conn, tok *oauth2.Token) (*Identity, error) {
	var g gitlabUser
	if err := c.get(ctx, c.api, tok, &g); err != nil {
		return nil, err
	}
	return &Identity{
		Subject:  strconv.Itoa(g.Id),
		Username: g.Username,
		Display:  g.Name,
		Email:    g.Email,
		Verified: !g.ConfirmedAt.IsZero(),
		Avatar:   g.Avatar,
	}, nil
}

// or returns v when set, else fallback — the custom-endpoint override every
// provider row may carry (a self-hosted GitLab, or a test's fake upstream).
func or(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
