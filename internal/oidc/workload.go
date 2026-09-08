// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// RFC 7523 — a workload authenticates with the ServiceAccount token its pod
// already carries, and receives the application token client_credentials would
// have given it for a stored secret.
//
// A secret in a pod is a secret in etcd, in whatever manifest names it, and in
// every `kubectl get secret` anyone with read access on the namespace runs. The
// projected ServiceAccount token is none of those: the kubelet mints it for one
// pod, for one audience, with a lifetime measured in hours, and rotates it in
// place. The cluster is already vouching for that pod — this grant reads what the
// cluster says instead of asking the deployment to carry a second credential
// asserting the same thing.
//
// What the assertion PROVES, checked here:
//
//   - it is signed by a key the named cluster publishes in its own JWKS;
//   - `aud` names THIS issuer, so a token the kubelet minted for some other
//     audience cannot be replayed against the token endpoint;
//   - it is inside its own validity window (`exp` required, `nbf` honoured);
//   - `sub` is `system:serviceaccount:<namespace>:<name>`.
//
// What is CONFIGURED, not proved: which cluster issuers are trusted at all
// (IAM_CLUSTER_ISSUERS) and which org owns each namespace (IAM_NAMESPACE_ORGS).
// Both are exact — no globs — because a namespace is a name anyone with cluster
// write can choose, and no pattern names "the hanzo org" more precisely than the
// list of namespaces that are in it.
//
// The application is DECLARED, never created here: provision.yaml states it as
// `type: service`, so `<org>-<name>` either names a reviewed registration or the
// request is refused. With neither variable set the grant does not exist and the
// endpoint answers unsupported_grant_type.

const (
	// grantTypeAssertion is RFC 7523 §2.1's grant type — the assertion IS the
	// authentication, so no client secret travels with it.
	grantTypeAssertion = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// saSubject is the prefix Kubernetes puts on every ServiceAccount subject.
	saSubject = "system:serviceaccount:"

	envClusters   = "IAM_CLUSTER_ISSUERS"
	envNamespaces = "IAM_NAMESPACE_ORGS"
)

// clusterAlgs is the closed set of algorithms a cluster assertion may be signed
// under — the asymmetric families kube-apiserver signs ServiceAccount tokens
// with. alg:none and every HMAC family are absent, so a forged header cannot
// select a verification path that trusts material the attacker supplied.
var clusterAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

// workloadGrant handles grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
func workloadGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	// 1) Config. Unconfigured is not a refusal — it is a grant this deployment
	//    does not offer, which is what unsupported_grant_type says. A config that
	//    is present but unreadable is a different thing and says so: silently
	//    behaving as if nothing were configured would turn one bad JSON character
	//    into every workload in the fleet failing to authenticate, with nothing
	//    naming the reason.
	set, err := clusters()
	if err != nil {
		return tokenError(c, 500, "server_error", err.Error())
	}
	orgs, err := namespaceOrgs()
	if err != nil {
		return tokenError(c, 500, "server_error", err.Error())
	}
	if len(set) == 0 && len(orgs) == 0 {
		return tokenError(c, 400, "unsupported_grant_type", "unsupported grant_type")
	}

	// 2) The assertion (RFC 7523 §2.1, required) is the whole credential.
	assertion := param(c, "assertion")
	if assertion == "" {
		return tokenError(c, 400, "invalid_request", "assertion is required")
	}
	claims, err := verifyAssertion(assertion, tokenIssuer(c), set)
	if err != nil {
		return tokenError(c, 400, "invalid_grant", "the assertion is invalid or expired")
	}
	namespace, account := serviceAccount(claims.Subject)
	if namespace == "" {
		return tokenError(c, 400, "invalid_grant", "the assertion does not name a service account")
	}

	// 3) Identity. The namespace decides the org and the account decides the name;
	//    together they ARE the clientId provision.yaml derives, so a workload can
	//    only ever reach the registration its own namespace declares.
	org := orgs[namespace]
	if org == "" {
		return tokenError(c, 403, "unauthorized_client", "no organization is configured for the "+namespace+" namespace")
	}
	clientID := org + "-" + account
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// The application must ALREADY exist, declare the grant whose token it is
	// about to be handed, and belong to the org the namespace maps to. Never
	// auto-created: a registration that appears because a pod asked for one is a
	// registration nobody reviewed. The org check is what keeps the mapping
	// honest — a clientId is a globally unique STRING, so `zoo-pkg` registered
	// under some other org would otherwise let the zoo namespace mint that org's
	// token.
	if app == nil || app.Organization != org ||
		!appGrants(app, "client_credentials") || publicTokenEndpointForbidden(app) {
		return tokenError(c, 403, "unauthorized_client", clientID+" is not a provisioned service application")
	}

	// 4) Mint what client_credentials would mint for this application — same
	//    signer, same claims, azp = the app — and record who obtained it.
	resp, err := machineToken(ctx, db, app, tokenIssuer(c), param(c, "scope"), resourceOf(c), "wl", now)
	if err != nil {
		return mintError(c, err)
	}
	// The row records the service account that PRESENTED the assertion against the
	// application the credential is FOR, so it is owned by the tenant that may read
	// it — the same shape the exchange grant writes, with the workload standing
	// where the acting client stands there.
	auditMint(ctx, db, c, schema.ActionWorkloadToken, claims.Subject, org+"/"+app.Name)
	return c.JSON(200, resp)
}

// serviceAccount splits a Kubernetes subject into the namespace and the account
// it names. Anything else — a human's subject, a node's, a truncated one —
// yields empty strings and is refused: this grant speaks for service accounts,
// and a subject it cannot read is not one it may guess at.
func serviceAccount(sub string) (namespace, name string) {
	rest, ok := strings.CutPrefix(sub, saSubject)
	if !ok {
		return "", ""
	}
	namespace, name, ok = strings.Cut(rest, ":")
	if !ok || namespace == "" || name == "" || strings.ContainsRune(name, ':') {
		return "", ""
	}
	return namespace, name
}

// verifyAssertion checks an assertion against the cluster that issued it and
// returns its validated claims. Fail-closed by construction: the issuer selects
// the key source, so an issuer nobody configured has no keys and therefore no
// verification path at all — there is nothing to relax.
func verifyAssertion(assertion, audience string, set map[string]*cluster) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	key := func(t *jwt.Token) (any, error) {
		// ParseWithClaims decodes the claims before it asks for a key, so `iss` is
		// readable here and is the ONLY thing that chooses where the key comes from.
		k := set[claims.Issuer]
		if k == nil {
			return nil, fmt.Errorf("workload: %q is not a configured cluster issuer", claims.Issuer)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("workload: the assertion carries no kid")
		}
		return k.key(kid)
	}
	if _, err := jwt.ParseWithClaims(assertion, claims, key,
		jwt.WithValidMethods(clusterAlgs),
		jwt.WithTimeFunc(nowFunc),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
	); err != nil {
		return nil, err
	}
	return claims, nil
}

// cluster is one trusted Kubernetes issuer: where its key set is published, what
// it takes to read it, and the keys read so far.
type cluster struct {
	iss    string
	uri    string
	bearer string // path to the token that reads the key set; "" where it is public
	client *http.Client

	mu     sync.Mutex
	keys   map[string]any
	until  time.Time // when the held set goes stale
	reread bool      // an unknown kid already made this set re-read once
}

const (
	// keyLife is how long a key set stands when the issuer states nothing.
	keyLife = 10 * time.Minute
	// keyRetry is how long a held set stands after a read that did not answer,
	// so a failing apiserver costs one attempt rather than one per request.
	keyRetry = 30 * time.Second
	// readLimit and readTimeout bound a JWKS read. A key set is a small document;
	// anything larger is not one.
	readLimit   = 1 << 20
	readTimeout = 10 * time.Second
)

// errNoKey is a kid the issuer does not publish — after a re-read, so a rotation
// the cluster performed without telling anyone is not mistaken for a forgery.
var errNoKey = errors.New("workload: the cluster publishes no such key")

// key returns the verification key for kid, reading the issuer's JWKS when the
// held set cannot answer.
//
// A cluster rotates its signing key on its own schedule, so the first token
// carrying the new kid is what asks for it — the held set is re-read even though
// it has not aged out.
//
// An UNPRODUCTIVE re-read is the one such read a held set gets: a kid nobody
// publishes costs a single read and then nothing, while a rotation that the
// re-read did resolve leaves the set answering as it always did. Without that,
// anyone who can reach the token endpoint has an amplifier pointed at the
// apiserver — a made-up kid per request is a JWKS read per request.
func (k *cluster) key(kid string) (any, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	fresh := k.keys != nil && nowFunc().Before(k.until)
	if fresh {
		if key, ok := k.keys[kid]; ok {
			return key, nil
		}
		if k.reread {
			return nil, errNoKey
		}
	}
	keys, life, err := k.read()
	if err != nil {
		if key, ok := k.keys[kid]; ok {
			k.until = nowFunc().Add(keyRetry) // it did not answer; what we hold still verifies
			return key, nil
		}
		return nil, err
	}
	key, ok := keys[kid]
	k.keys, k.until, k.reread = keys, nowFunc().Add(life), fresh && !ok
	if !ok {
		return nil, errNoKey
	}
	return key, nil
}

// read fetches and decodes the issuer's key set, with the lifetime the response
// asks for.
//
// Some apiservers — k3s among them — refuse an anonymous read of the key set and
// answer 401. IAM then reads it as a client of that cluster too, presenting its
// own ServiceAccount token bound to nothing but
// system:service-account-issuer-discovery: the least authority that can see a
// document whose whole content is public keys.
//
// That token is read from disk at EVERY fetch and never held, because the kubelet
// projecting it rotates it in place — a copy taken at boot is a copy that stops
// working somewhere in the middle of a Tuesday, and the failure would look like a
// cluster that had gone away.
func (k *cluster) read() (map[string]any, time.Duration, error) {
	req, err := http.NewRequest(http.MethodGet, k.uri, nil)
	if err != nil {
		return nil, 0, err
	}
	if k.bearer != "" {
		token, err := os.ReadFile(k.bearer)
		if err != nil {
			return nil, 0, fmt.Errorf("workload: %s: cannot read the discovery token: %w", k.iss, err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("workload: %s answered %d for %s", k.iss, resp.StatusCode, k.uri)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, 0, err
	}
	keys, err := parseKeys(body)
	if err != nil {
		return nil, 0, err
	}
	return keys, lifeOf(resp.Header.Get("Cache-Control")), nil
}

// lifeOf reads the lifetime a Cache-Control header asks for, falling back to
// keyLife. Honouring it keeps the server's idea of freshness the issuer's own;
// a header that asks for nothing cacheable would otherwise mean a read per
// request against the apiserver, which is why "no max-age" lands on the default
// rather than on zero.
func lifeOf(header string) time.Duration {
	for _, part := range strings.Split(header, ",") {
		age, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age=")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(age); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return keyLife
}

// parseKeys decodes a cluster's key set into verification keys by kid, through
// the SAME JWK decoder the federation leg verifies an external id_token with
// (federation_idp.go). One decoder: a second one would be a second opinion about
// what a published key is, and the weaker of the two would be the one an attacker
// picks.
//
// A key it cannot read is skipped rather than failing the set — an issuer that
// also publishes a key type we do not verify still publishes the ones we do — but
// a set with nothing readable in it is an error, because holding one would mean
// answering errNoKey forever without ever reading again.
func parseKeys(body []byte) (map[string]any, error) {
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := k.publicKey()
		if err != nil || k.Kid == "" {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("workload: the cluster key set carries no readable key")
	}
	return out, nil
}

// trusted holds the cluster set built from IAM_CLUSTER_ISSUERS, rebuilt only when
// the value itself changes. The keys a cluster has read live ON the cluster, so
// the set has to be the same objects from one request to the next — a per-request
// parse would throw the key cache away with the structs that held it.
var trusted struct {
	sync.Mutex
	built bool
	raw   string
	set   map[string]*cluster
	err   error
}

// clusters is the trusted cluster issuers, by issuer. Empty means the grant is
// not offered here; an error means the config is present and unreadable, which
// is a different answer and gets a different one.
func clusters() (map[string]*cluster, error) {
	raw := strings.TrimSpace(os.Getenv(envClusters))
	trusted.Lock()
	defer trusted.Unlock()
	if !trusted.built || raw != trusted.raw {
		trusted.built, trusted.raw = true, raw
		trusted.set, trusted.err = buildClusters(raw)
	}
	return trusted.set, trusted.err
}

// buildClusters parses IAM_CLUSTER_ISSUERS:
//
//	{"https://kubernetes.default.svc.cluster.local":
//	   {"jwks_uri":   "https://10.0.0.19:6443/openid/v1/jwks",
//	    "ca_file":    "/etc/iam/cluster-ca.crt",
//	    "bearer_file":"/var/run/secrets/kubernetes.io/serviceaccount/token"}}
//
// ca_file is the certificate that reads the apiserver; bearer_file is optional
// and names the ServiceAccount token to present where the apiserver refuses an
// anonymous read (see cluster.read).
//
// An entry missing its jwks_uri, or naming a CA file that is not a certificate,
// fails the WHOLE set rather than dropping that issuer: a half-built trust set
// looks exactly like a working one until the workloads of the dropped cluster
// start failing to authenticate.
func buildClusters(raw string) (map[string]*cluster, error) {
	if raw == "" {
		return nil, nil
	}
	var doc map[string]struct {
		JWKS   string `json:"jwks_uri"`
		CA     string `json:"ca_file"`
		Bearer string `json:"bearer_file"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", envClusters, err)
	}
	set := make(map[string]*cluster, len(doc))
	for iss, cfg := range doc {
		if iss == "" || cfg.JWKS == "" {
			return nil, fmt.Errorf("%s: entry %q states no jwks_uri", envClusters, iss)
		}
		client, err := reader(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %q: %w", envClusters, iss, err)
		}
		set[iss] = &cluster{iss: iss, uri: cfg.JWKS, bearer: cfg.Bearer, client: client}
	}
	return set, nil
}

// reader builds the client that reads one issuer's key set. The CA is the
// cluster's own: an apiserver serves its key set under a certificate no public
// root signs, so a client carrying only the system pool cannot read it at all.
// An empty ca_file keeps the system pool, for an issuer published behind a
// public CA.
func reader(caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s carries no certificate", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: readTimeout}, nil
}

// namespaceOrgs reads IAM_NAMESPACE_ORGS — {"hanzo":"hanzo","operator-system":"hanzo"} —
// the exact namespace→org map. Parsed per request rather than held, because
// unlike the cluster set it anchors no cache and a map this size costs less to
// read than to keep in step.
func namespaceOrgs() (map[string]string, error) {
	raw := strings.TrimSpace(os.Getenv(envNamespaces))
	if raw == "" {
		return nil, nil
	}
	var orgs map[string]string
	if err := json.Unmarshal([]byte(raw), &orgs); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", envNamespaces, err)
	}
	return orgs, nil
}

// grantsSupported is the grant list discovery advertises. Every entry is
// implemented AND reachable here: the workload grant appears only where a cluster
// issuer is configured, because a deployment without one does not offer it and a
// document that says otherwise sends clients at a grant that refuses them.
func grantsSupported() []string {
	g := []string{"authorization_code", "refresh_token", "client_credentials", "password", grantTypeTokenExchange, deviceGrant}
	if set, err := clusters(); err == nil && len(set) > 0 {
		g = append(g, grantTypeAssertion)
	}
	return g
}
