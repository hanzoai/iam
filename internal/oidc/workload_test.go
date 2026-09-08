// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// RFC 7523 — a workload authenticates with its pod's ServiceAccount token and
// receives the application token client_credentials would have given it for a
// stored secret. These tests stand up a real cluster issuer (a JWKS served over
// TLS behind its own CA) and pin both halves: the happy path mints exactly what
// the secret path mints, and every mismatch — audience, issuer, key, namespace,
// registration, expiry — fails closed.

// cluster fixture ------------------------------------------------------------

// fakeCluster is an in-test Kubernetes issuer: a signing key, a JWKS served over
// TLS, and the CA file a client needs to read it. The published key set is
// mutable so a test can rotate the cluster's signing key underneath a running
// server, which is the case no static fixture can produce.
type fakeCluster struct {
	iss  string
	jwks string
	ca   string

	// requires is the bearer the apiserver demands before it will serve the key
	// set, and bearerFile is where IAM reads its copy — the k3s shape, where an
	// anonymous read answers 401.
	requires   string
	bearerFile string

	mu    sync.Mutex
	keys  []map[string]any
	reads int
}

// newCluster starts an issuer publishing one key under kid.
func newCluster(t *testing.T, kid string) *fakeCluster {
	t.Helper()
	c := &fakeCluster{iss: "https://kubernetes.default.svc.cluster.local"}
	c.publish(t, kid)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.requires != "" && r.Header.Get("Authorization") != "Bearer "+c.requires {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.reads++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": c.keys})
	}))
	t.Cleanup(srv.Close)

	c.jwks = srv.URL + "/openid/v1/jwks"
	c.ca = writeCA(t, srv.Certificate())
	return c
}

// demand makes the issuer refuse an anonymous read and returns the path IAM
// reads its own discovery token from. Writing the token to a FILE is the point:
// the kubelet rotates it in place, so IAM must read it per fetch.
func (c *fakeCluster) demand(t *testing.T, token string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write discovery token: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requires, c.bearerFile = token, path
}

// rotate rewrites the discovery token on disk and at the apiserver, the way a
// kubelet refreshes a projected volume under a running process.
func (c *fakeCluster) rotate(t *testing.T, token string) {
	t.Helper()
	c.mu.Lock()
	path := c.bearerFile
	c.requires = token
	c.mu.Unlock()
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("rotate discovery token: %v", err)
	}
}

// publish adds a key id to what the JWKS serves. The key MATERIAL is the shared
// test key throughout: what is under test is which kid the server can resolve,
// not which modulus it carries.
func (c *fakeCluster) publish(t *testing.T, kid string) {
	t.Helper()
	k := rsaJWK(&sharedKey(t).PublicKey)
	k["kid"], k["alg"], k["use"] = kid, "RS256", "sig"
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = append(c.keys, k)
}

// fetches is how many times the JWKS has been read.
func (c *fakeCluster) fetches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// trust points IAM at this cluster and states which org owns which namespace.
func (c *fakeCluster) trust(t *testing.T, namespaces map[string]string) {
	t.Helper()
	issuers, err := json.Marshal(map[string]any{
		c.iss: map[string]string{"jwks_uri": c.jwks, "ca_file": c.ca, "bearer_file": c.bearerFile},
	})
	if err != nil {
		t.Fatalf("marshal cluster config: %v", err)
	}
	orgs, err := json.Marshal(namespaces)
	if err != nil {
		t.Fatalf("marshal namespace config: %v", err)
	}
	t.Setenv(envClusters, string(issuers))
	t.Setenv(envNamespaces, string(orgs))
}

// assertion signs a ServiceAccount token the way a kubelet projects one.
func (c *fakeCluster) assertion(t *testing.T, kid, sub, audience string, life time.Duration) string {
	t.Helper()
	return signAs(t, c.iss, kid, sub, audience, life)
}

// signAs signs an assertion under an arbitrary issuer, so a test can present one
// that is correctly signed and still names a cluster nobody configured.
func signAs(t *testing.T, iss, kid, sub, audience string, life time.Duration) string {
	t.Helper()
	now := nowFunc()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    iss,
		Subject:   sub,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(now.Add(life)),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(sharedKey(t))
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return s
}

// writeCA writes a certificate where a ca_file entry can name it.
func writeCA(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster-ca.crt")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

// audience is the issuer an assertion must name — the same value tokenIssuer
// resolves for the test host, so the fixture and the server cannot drift.
func audience() string { return resolveIssuer("hanzo.id") }

// present posts an assertion at the token endpoint. No client_id and no
// client_secret travel with it: the assertion IS the authentication, which is
// the whole point of the grant.
func present(t *testing.T, app *zip.App, assertion string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type": {grantTypeAssertion},
		"assertion":  {assertion},
	}
	for k, v := range extra {
		form[k] = v
	}
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp.StatusCode, decode(t, body)
}

// serviceApp seeds an application shaped the way provision.yaml's `type: service`
// derives one: clientId <org>-<app>, client_credentials the only grant.
func serviceApp(t *testing.T, db orm.DB, clientID string) {
	t.Helper()
	seedApp(t, db, appOpts{
		clientID: clientID,
		secret:   "a-secret-the-pod-never-holds",
		grants:   []string{"client_credentials"},
	})
}

// tests ----------------------------------------------------------------------

func TestWorkload_mintsForServiceAccount(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour), nil)
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token; body=%v", tok)
	}
	if tok["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tok["token_type"])
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Error("a machine token must carry no refresh token")
	}

	// The token IAM's own JWKS verifies, carrying exactly what client_credentials
	// mints for this application: the app is the principal, the org is the tenant,
	// and the class says a program obtained it.
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Subject != "admin/hanzo-pkg" {
		t.Errorf("sub = %q, want admin/hanzo-pkg", claims.Subject)
	}
	if claims.Owner != "hanzo" || claims.Name != "hanzo-pkg" {
		t.Errorf("owner/name = %q/%q, want hanzo / hanzo-pkg", claims.Owner, claims.Name)
	}
	if claims.Azp != "hanzo-pkg" {
		t.Errorf("azp = %q, want hanzo-pkg", claims.Azp)
	}
	if claims.Type != schema.Program {
		t.Errorf("type = %q, want %q", claims.Type, schema.Program)
	}
	if len(claims.Orgs) != 0 {
		t.Errorf("a machine token carries no membership set, got %v", claims.Orgs)
	}

	// The mint is on the record: who presented, for which application, in which org.
	rows := auditRows(t, db, schema.ActionWorkloadToken)
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if rows[0].Object != "system:serviceaccount:hanzo:pkg" {
		t.Errorf("audit object = %q, want the service account", rows[0].Object)
	}
	if rows[0].User != "hanzo/hanzo-pkg" || rows[0].Owner != "hanzo" {
		t.Errorf("audit user/owner = %q/%q, want hanzo/hanzo-pkg and hanzo", rows[0].User, rows[0].Owner)
	}
}

func TestWorkload_mintsForTheResourceItNames(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour),
		url.Values{"resource": {"hanzo-cloud"}, "scope": {"read"}})
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	claims, err := verifyToken(context.Background(), db, tok["access_token"].(string))
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "hanzo-cloud" {
		t.Errorf("aud = %v, want [hanzo-cloud]", claims.Audience)
	}
	if claims.Scope != "read" {
		t.Errorf("scope = %q, want read", claims.Scope)
	}
}

func TestWorkload_refusesWrongAudience(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	// A token the kubelet projected for some other service. It is correctly signed
	// by the cluster and names a real service account; only `aud` is not ours.
	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", "https://vault.internal", time.Hour), nil)
	if status != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("status/error = %d/%v, want 400 invalid_grant", status, tok["error"])
	}
}

func TestWorkload_refusesUnknownIssuer(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	// Signed with the same key, naming a cluster nobody configured. The issuer is
	// what selects the key source, so there is no verification path at all.
	status, tok := present(t, app,
		signAs(t, "https://oidc.some-other-cluster", "cluster-key-1",
			"system:serviceaccount:hanzo:pkg", audience(), time.Hour), nil)
	if status != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("status/error = %d/%v, want 400 invalid_grant", status, tok["error"])
	}
}

func TestWorkload_rereadsOnUnknownKid(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	sub := "system:serviceaccount:hanzo:pkg"
	if status, tok := present(t, app, c.assertion(t, "cluster-key-1", sub, audience(), time.Hour), nil); status != 200 {
		t.Fatalf("first mint: status = %d; body=%v", status, tok)
	}
	if got := c.fetches(); got != 1 {
		t.Fatalf("JWKS reads = %d after the first mint, want 1", got)
	}

	// The cluster rotates. Nothing tells IAM; the first token under the new kid is
	// what asks, and one re-read resolves it.
	c.publish(t, "cluster-key-2")
	if status, tok := present(t, app, c.assertion(t, "cluster-key-2", sub, audience(), time.Hour), nil); status != 200 {
		t.Fatalf("after rotation: status = %d; body=%v", status, tok)
	}
	if got := c.fetches(); got != 2 {
		t.Fatalf("JWKS reads = %d after the rotation, want 2", got)
	}

	// An invented kid costs ONE read per held set, not one per request — otherwise
	// anyone who can reach the token endpoint has an amplifier pointed at the
	// apiserver.
	for i := 0; i < 3; i++ {
		if status, _ := present(t, app, c.assertion(t, "no-such-kid", sub, audience(), time.Hour), nil); status != 400 {
			t.Fatalf("invented kid: status = %d, want 400", status)
		}
	}
	if got := c.fetches(); got != 3 {
		t.Fatalf("JWKS reads = %d after three invented kids, want 3", got)
	}
}

func TestWorkload_refusesUnmappedNamespace(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	// kube-system is a real namespace with real service accounts and no org.
	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:kube-system:pkg", audience(), time.Hour), nil)
	if status != 403 || tok["error"] != "unauthorized_client" {
		t.Fatalf("status/error = %d/%v, want 403 unauthorized_client", status, tok["error"])
	}
}

func TestWorkload_refusesUnprovisionedApplication(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, _ := newServer(t) // nothing seeded: hanzo-pkg was never declared

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour), nil)
	if status != 403 || tok["error"] != "unauthorized_client" {
		t.Fatalf("status/error = %d/%v, want 403 unauthorized_client", status, tok["error"])
	}
}

func TestWorkload_refusesApplicationThatDeclaresNoMachineGrant(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	// A browser client that happens to be named <org>-<account>. It never declared
	// client_credentials, so it may not be handed that grant's token by another door.
	seedApp(t, db, appOpts{clientID: "hanzo-pkg", secret: "s", grants: []string{"authorization_code"}})

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour), nil)
	if status != 403 || tok["error"] != "unauthorized_client" {
		t.Fatalf("status/error = %d/%v, want 403 unauthorized_client", status, tok["error"])
	}
}

func TestWorkload_refusesApplicationOfAnotherOrg(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"zoo-ns": "zoo"})
	app, db := newServer(t)
	// The clientId a zoo namespace derives, registered under the hanzo org. A
	// clientId is a globally unique STRING; without the org check the zoo namespace
	// would mint hanzo's token.
	serviceApp(t, db, "zoo-pkg")

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:zoo-ns:pkg", audience(), time.Hour), nil)
	if status != 403 || tok["error"] != "unauthorized_client" {
		t.Fatalf("status/error = %d/%v, want 403 unauthorized_client", status, tok["error"])
	}
}

func TestWorkload_refusesExpiredAssertion(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), -time.Hour), nil)
	if status != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("status/error = %d/%v, want 400 invalid_grant", status, tok["error"])
	}
}

func TestWorkload_refusesAHumanSubject(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "z@hanzo.ai", audience(), time.Hour), nil)
	if status != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("status/error = %d/%v, want 400 invalid_grant", status, tok["error"])
	}
}

func TestWorkload_unconfiguredIsNotAGrant(t *testing.T) {
	t.Setenv(envClusters, "")
	t.Setenv(envNamespaces, "")
	app, _ := newServer(t)

	status, tok := present(t, app, "irrelevant", nil)
	if status != 400 || tok["error"] != "unsupported_grant_type" {
		t.Fatalf("status/error = %d/%v, want 400 unsupported_grant_type", status, tok["error"])
	}
	// And discovery does not advertise a grant this deployment will refuse.
	_, body := do(t, app, formReqNoBody("GET", PathDiscovery))
	if containsStr(decode(t, body)["grant_types_supported"], grantTypeAssertion) {
		t.Error("discovery advertises the workload grant with no cluster configured")
	}
}

func TestWorkload_configuredIsAdvertised(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, _ := newServer(t)

	_, body := do(t, app, formReqNoBody("GET", PathDiscovery))
	if !containsStr(decode(t, body)["grant_types_supported"], grantTypeAssertion) {
		t.Error("discovery omits the workload grant with a cluster configured")
	}
}

// An apiserver that refuses an anonymous read of its key set — k3s answers 401 —
// is read with IAM's own ServiceAccount token, and keeps being read after the
// kubelet rotates it.
func TestWorkload_readsAKeySetThatDemandsABearer(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.demand(t, "discovery-token-1")
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	sub := "system:serviceaccount:hanzo:pkg"
	status, tok := present(t, app, c.assertion(t, "cluster-key-1", sub, audience(), time.Hour), nil)
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}

	// The kubelet rewrites the projected token. A copy taken at the first fetch
	// would be refused from here on; the file is what IAM reads.
	c.rotate(t, "discovery-token-2")
	c.publish(t, "cluster-key-2") // forces a fresh read rather than a cache hit
	status, tok = present(t, app, c.assertion(t, "cluster-key-2", sub, audience(), time.Hour), nil)
	if status != 200 {
		t.Fatalf("after the token rotated: status = %d; body=%v", status, tok)
	}
	if got := c.fetches(); got != 2 {
		t.Fatalf("JWKS reads = %d, want 2", got)
	}
}

// Without the bearer the apiserver answers 401, there is no key, and the grant
// fails closed rather than minting on an unverified assertion.
func TestWorkload_refusesWhenTheKeySetIsUnreadable(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.demand(t, "discovery-token-1")
	c.bearerFile = "" // configured without the token the apiserver requires
	c.trust(t, map[string]string{"hanzo": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")

	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour), nil)
	if status != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("status/error = %d/%v, want 400 invalid_grant", status, tok["error"])
	}
}

func TestWorkload_refusesMalformedConfig(t *testing.T) {
	t.Setenv(envClusters, "{not json")
	t.Setenv(envNamespaces, `{"hanzo":"hanzo"}`)
	app, _ := newServer(t)

	// Unreadable is not the same answer as unconfigured: one bad character must not
	// look like a deployment that never offered the grant.
	status, tok := present(t, app, "irrelevant", nil)
	if status != 500 || tok["error"] != "server_error" {
		t.Fatalf("status/error = %d/%v, want 500 server_error", status, tok["error"])
	}
}

// serviceAccount reads the two names a Kubernetes subject carries, and refuses
// every shape that is not one.
func TestServiceAccount(t *testing.T) {
	for _, tc := range []struct{ sub, namespace, name string }{
		{"system:serviceaccount:hanzo:pkg", "hanzo", "pkg"},
		{"system:serviceaccount:operator-system:operator", "operator-system", "operator"},
		{"system:serviceaccount:hanzo:", "", ""},
		{"system:serviceaccount::pkg", "", ""},
		{"system:serviceaccount:hanzo:pkg:extra", "", ""},
		{"system:serviceaccount:hanzo", "", ""},
		{"system:node:worker-1", "", ""},
		{"hanzo/z", "", ""},
		{"", "", ""},
	} {
		ns, name := serviceAccount(tc.sub)
		if ns != tc.namespace || name != tc.name {
			t.Errorf("serviceAccount(%q) = %q, %q; want %q, %q", tc.sub, ns, name, tc.namespace, tc.name)
		}
	}
}

// lifeOf honours the lifetime an issuer asks for and falls back when it asks for
// nothing usable — never to zero, which would be a read per request.
func TestLifeOf(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"public, max-age=300", 5 * time.Minute},
		{"max-age=60", time.Minute},
		{"no-cache, private", keyLife},
		{"max-age=0", keyLife},
		{"max-age=nonsense", keyLife},
		{"", keyLife},
	} {
		if got := lifeOf(tc.header); got != tc.want {
			t.Errorf("lifeOf(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}
