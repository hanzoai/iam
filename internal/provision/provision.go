// Copyright 2026 Hanzo AI, Inc. All rights reserved.

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
package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
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
	Apps           []App  `yaml:"apps"`
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
}

// Client is the derived, serialized registration — the body of an upsert call.
// It is deliberately the shape bootstrap.appUpsertReq accepts, minus the
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
	return &d, nil
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

	c := Client{
		Organization: org.Name,
		Name:         id,
		ClientId:     id,
		DisplayName:  displayName(org, name),
		GrantTypes:   grants,
		RedirectUris: redirects(org, a),
		Public:       publicByType[a.Type],
		Cert:         strings.TrimSpace(a.Cert),
	}
	if c.RedirectUris == nil && a.Type != TypeService {
		return Client{}, fmt.Errorf("provision: app %s declares no hosts and type %q needs a redirect", id, a.Type)
	}
	return c, nil
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

// Reconciler converges a live IAM onto derived clients over the admin upsert
// endpoint.
type Reconciler struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	DryRun  bool
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
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	url := strings.TrimRight(r.BaseURL, "/") + "/v1/iam/admin/applications/upsert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Token)

	resp, err := r.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upsert %s: HTTP %d: %s", c.Name, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Status string `json:"status"`
		Action string `json:"action"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("upsert %s: undecodable response: %w", c.Name, err)
	}
	if out.Status != "ok" {
		return "", fmt.Errorf("upsert %s: %s", c.Name, out.Msg)
	}
	return out.Action, nil
}
