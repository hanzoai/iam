// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package server is the PUBLIC embedding surface of iam: a host binary (cloud)
// imports this and registers the full IAM HTTP surface onto its own zip app,
// over its own orm.DB. This is how iam goes live embedded in hanzoai/cloud
// without a separate pod.
//
// The caller decides the route prefix. It is normally the canonical /v1/iam/*;
// a shadow prefix still works if a host wants to stand a second instance up
// beside the live one before moving traffic.
package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/internal/featurestore"
	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/seed"
	_ "github.com/hanzoai/iam/pkg/schema" // registers the entity kinds
	"github.com/hanzoai/iam/pkg/store"
)

// Route registers the entire IAM surface (OIDC discovery/JWKS, get-app-login,
// auth/methods, token, login, and the v2 entity CRUD) onto app, backed by db.
// This is the one call a host binary makes to embed iam.
func Route(app *zip.App, db orm.DB) {
	routes.Route(app, db)
	// Enterprise features (hanzoai/iam/feature — SAML and LDAP live in the
	// hanzoiam/* modules and Register themselves; SCIM is core, registered above by
	// routes.Route). No-op until a host registers one; fail-fast if a registered
	// module cannot register (a boot misconfiguration).
	//
	// A feature registers on THIS app, which is not the guarded group, so it is
	// unauthenticated unless it says otherwise — it owns that decision. That is
	// the right default for the two modules there are (a SAML assertion consumer
	// and metadata endpoint must answer a browser that holds no IAM bearer, the
	// same way the OIDC surface does), and it is a real change from when
	// routes.Route put a Guard in front of the whole app and this line inherited
	// it by accident of coming after. Registry is empty in this repo, so nothing
	// today moved; a module that wants gating must reach for authz.Guard itself.
	if err := feature.RouteAll(app, featurestore.New(db)); err != nil {
		panic("iam: enterprise feature registration failed: " + err.Error())
	}
}

// NewApp builds a STANDALONE iam zip.App over db — the whole IAM surface
// registered as one self-contained app. It is what a host COMPOSES:
//
//	app.Use(iamserver.NewApp(db))
//
// An App is a Component, so composing one is the same verb as adding
// middleware — zip.Graft was a second name for this and is gone. The host's
// router learns iam's route patterns and its OP REGISTRY, while iam's own
// router keeps iam's behaviour (its Use chain, its Guard, its error handler),
// and iam's Guard reaches iam's subtree only. The caller owns the returned
// app's Shutdown; composing adopts it.
//
// Build renders iam's OWN document, tool list and call plane onto iam's own
// control plane, and returns the verdict on the composition — which is why it
// replaced zip's old Prepare, whose silence meant a program that did not
// compose was only discovered by starting a server. A host does not adopt
// those projections — a zip Declaration excludes the control plane, so the host
// keeps its own /docs, MCP door and op plane and the composed document is the
// HOST's.
//
// A failed Build is a wiring error in this package, not a runtime condition the
// caller can act on, so it panics for the same reason [Route] panics on a
// feature module that cannot register.
//
// There is no net/http adaptation any more. Handler() used to exist for a host
// that hung the whole surface on one wildcard, and it went through
// adaptor.FiberApp: the App went in, an http.Handler came out, and iam's 94
// typed ops went with it — invisible to the host's OpenAPI document, MCP tool
// list, CLI and call plane. A host published a wildcard where 94 typed
// operations were. Composing the App is what keeps them.
func NewApp(db orm.DB) *zip.App {
	app := zip.New(zip.Config{AppName: "iam", DisableStartupMessage: true})
	// A nil store is a HOST that could not open one, and it changes what every op
	// ANSWERS — never which addresses exist. Those are different kinds of fact: the
	// route table is fixed by this code, the store is a property of the machine the
	// code is running on, and braiding them makes the published document depend on
	// whether a volume happened to be mounted when it was generated.
	//
	// cloud used to express this by registering a DIFFERENT surface — five wildcards
	// answering 503 instead of the App — so an absent volume replaced 94 typed
	// operations with 15 undescribed catch-alls in its OpenAPI document, its MCP tool
	// list, its SDKs and its CLI. Two route tables for one program, chosen at boot by
	// a stat() call.
	//
	// Refusing in FRONT of the routes gives one table and one registration: every
	// address IAM declares still exists, still documents itself, and answers 503
	// until the store is there. It also means no handler dereferences the nil.
	if db == nil {
		app.Use(zip.H(unavailable))
	}
	Route(app, db)
	if err := app.Build(); err != nil {
		panic("iam: app does not compose: " + err.Error())
	}
	return app
}

// unavailable answers every identity request 503 while there is no store to serve
// from, and is installed only in that case.
//
// It states the fault in the body rather than leaving the status to speak alone: the
// caller is a relying party or a console, and "iam has no store" is the difference
// between waiting a minute and re-registering an OIDC client. Retry-After says the
// condition is transient, which it is — a volume gets mounted, not fixed.
//
// It ANSWERS rather than returning the error for a host to render, because the host
// may not render it faithfully: cloud installs an error-flattening filter on its /v1
// group that rewrites any PROPAGATED error to 500, so a returned 503 would reach a
// relying party as an internal error and hide the one fact worth saying. Answering
// writes the status before any such filter can see it.
func unavailable(c *zip.Ctx) error {
	c.SetHeader("Retry-After", "30")
	return c.JSON(http.StatusServiceUnavailable, map[string]any{
		"status": http.StatusServiceUnavailable,
		"code":   "iam_no_store",
		"error":  "iam has no identity store open, so no identity request can be answered",
	})
}

// OpenSQLite opens an embedded SQLite store for iam at path (WAL). The host may
// instead pass its own orm.DB (e.g. hanzoai/sql over ZAP) to Route.
func OpenSQLite(path string) (orm.DB, error) {
	return orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   path,
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
}

// Seed bootstraps the config (orgs/apps/providers/certs) from an init_data.json
// path — the same file the legacy surface uses. New-only + idempotent; ${VAR} from env.
// Returns the created/skipped counts. Call once at host startup after opening db.
//
// It then asserts the process can SIGN what it just configured (RequireSigning),
// because this is the one boot step an embedded host cannot skip — internal/seed
// is unimportable, so a host reaches the seed only through here. Without the
// assertion an embedded host boots green over a config it cannot serve: an empty
// JWKS answered 200 and every mint 401s. A host that seeds its store out of band
// calls RequireSigning itself.
func Seed(ctx context.Context, db orm.DB, initDataPath string) (*seed.Summary, error) {
	sum, err := seed.FromInitData(ctx, db, initDataPath)
	if err != nil {
		return sum, err
	}
	if err := RequireSigning(ctx, db); err != nil {
		return sum, err
	}
	return sum, nil
}

// RequireSigning reports whether this process holds the keys it must sign with,
// and is the precondition a boot asserts before it serves — main() before its
// listener, and [Seed] for an embedded host.
//
// Everything IAM emits is signed: every access token, every id token, the
// session-cookie MAC. The material arrives from the DEPLOYMENT — internal/keyring
// reads one PEM per cert name from the directory $IAM_SIGNING_KEYS names — so
// whether a process can do its job is a property of the pod it landed in, not of
// the binary and not of the store. Two replicas of one image can disagree.
//
// Asked ONCE, at boot, because that is the only moment the answer is actionable. A
// keyless replica answers a liveness probe perfectly and then fails every mint, so
// a rollout reads it as healthy and keeps going. Refusing here makes the pod never
// reach ready, which is the one signal a rollout already stops on.
//
// THREE questions, because one key is not the whole job:
//
//   - PlatformSigningCert must resolve. It keys the session-cookie MAC
//     (internal/sessions), so without it no browser session can be issued or read.
//     It selects the lexically-least reserved cert WITH material, so two replicas
//     holding different partial mounts would key cookies with DIFFERENT certs and
//     flap every session behind the load balancer — the signable check below is
//     what stops them both booting to diverge.
//   - Every cert this process must sign under must be signable. Two sources: the
//     certs the JWKS PUBLISHES (a `kid` a relying party will trust), and the certs
//     a reserved-owner application NAMES (the cert it mints tokens with). A cert an
//     application depends on but the mount omits is a token endpoint that 500s for
//     that application while the pod reports ready.
//   - Where a cert carries BOTH a published certificate and a mounted key, the two
//     must describe the same key, or the JWKS publishes one and the signer signs
//     with another and every token is rejected.
//
// The application half is read ONLY for the reserved owner. An application row is
// tenant-writable — an org admin registers applications in their own org and
// names a `cert` on them — so consulting a tenant's applications would let any org
// wedge the boot of the whole estate's identity plane by naming a cert that cannot
// resolve. A reserved-owner application is created by an operator, which is what
// makes its dependencies safe to require. A cert row carrying neither key nor
// published certificate, named by nothing, is a rotation staged ahead of its
// material and is required by neither source.
func RequireSigning(ctx context.Context, db orm.DB) error {
	cert, err := store.PlatformSigningCert(ctx, db)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if cert == nil {
		return fmt.Errorf("signing key: no certificate under a reserved owner carries key material — "+
			"mount one PEM per certificate name in the directory $%s names", keyring.EnvDir)
	}
	unsignable, err := unsignable(ctx, db)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if len(unsignable) > 0 {
		return fmt.Errorf("signing key: this process must sign under %s and holds no key for %s — "+
			"mount one PEM per certificate name in the directory $%s names",
			strings.Join(unsignable, ", "), pluralThem(len(unsignable)), keyring.EnvDir)
	}
	mismatched, err := mismatched(ctx, db)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if len(mismatched) > 0 {
		return fmt.Errorf("signing key: the published certificate and the mounted key disagree for %s — "+
			"the JWKS would publish a key that did not sign the tokens; mount the key that matches the "+
			"published certificate for %s", strings.Join(mismatched, ", "), pluralThem(len(mismatched)))
	}
	return nil
}

// unsignable names every signing cert this process must be able to sign under but
// cannot, deduped and sorted. Two sources, unioned:
//
//   - a cert the JWKS PUBLISHES (oidc.Publishes) whose private half is absent — a
//     `kid` relying parties trust that nothing can produce a token for.
//   - a cert a reserved-owner application NAMES that resolves to no signable
//     material — a token endpoint that 500s for that application.
//
// GetSigningCert and ListCerts both fill from the mount (keyring), so "no private
// half" here means the deployment did not supply it, not that the row lacks a
// column.
func unsignable(ctx context.Context, db orm.DB) ([]string, error) {
	need := map[string]bool{}
	certs, err := store.ListCerts(ctx, db)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if oidc.Publishes(c) && c.PrivateKey == "" {
			need[c.Name] = true
		}
	}
	apps, err := store.ListApplicationsByOwner(ctx, db, policy.AdminOrg)
	if err != nil {
		return nil, err
	}
	for _, a := range apps {
		if a.Cert == "" {
			continue
		}
		c, err := store.GetSigningCert(ctx, db, a.Cert)
		if err != nil {
			return nil, err
		}
		if c == nil || c.PrivateKey == "" {
			need[a.Cert] = true
		}
	}
	return sortedKeys(need), nil
}

// mismatched names the certs whose published half and mounted key describe
// different keys — latent until a rotation populates a published Certificate,
// then a silent source of universally-rejected tokens. A half that will not parse
// counts as a mismatch: an unverifiable pair is not a servable one.
func mismatched(ctx context.Context, db orm.DB) ([]string, error) {
	certs, err := store.ListCerts(ctx, db)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range certs {
		if c.Certificate == "" || c.PrivateKey == "" {
			continue
		}
		agree, err := oidc.SigningHalvesAgree(c)
		if err != nil || !agree {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// sortedKeys returns a set's members in sorted order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pluralThem picks the pronoun a count calls for, so a refusal reads as a
// sentence whether it names one certificate or six.
func pluralThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// Message is one verification code, worded and addressed. Re-exported with Sender
// for the same reason: a host outside this module has to be able to read one.
//
// IAM composes it. The expiry sentence is rendered from the same constant that
// expires the record, so a transport never has to know — or restate — how long a
// code lasts.
type Message = otp.Message

// Sender carries one Message. It is re-exported here because the seam itself lives
// in an internal package: a HOST binary that grafts IAM (cloud embeds it with
// server.NewApp) has to be able to supply the transport, and internal/otp is by
// definition unreachable from outside this module.
//
// Composition is exactly what this package is for, and delivery is composition:
// which wire carries a code is the host's decision, never IAM's. THE HOST IS THE
// ONLY ONE THAT CAN MAKE IT. The delivery service is a cloud app reached over the
// internal plane, and in the fleet it is started on demand — so "can a code be
// delivered here" is answered by the router that owns the app list and can bring
// the app up, and IAM links neither. This module used to answer it anyway, by
// looking for the service's socket FILE, and got it wrong in both directions: a
// file left behind by a dead pod reported delivery that could not happen, and a
// service that was merely not started yet reported none that could.
type Sender = otp.Sender

// BindSender installs the delivery transport for email and SMS codes. Call it at
// boot, before serving.
//
// Everything code-shaped stays OFF until this is called with a non-nil sender:
// email sign-in, SMS sign-in, and the email and SMS second factors all read one
// predicate, and that predicate reports on the BOUND SENDER rather than on any
// configuration. So there is no half-configured state to reason about — a host
// that can deliver binds one and all four turn on together.
//
// Binding is therefore an ASSERTION by the host: it says a code given to this
// transport reaches a person. A host that cannot say that binds nothing, and every
// screen keeps offering only the methods that work.
func BindSender(s Sender) { otp.BindSender(s) }

// DeliveryConfigured reports whether a verification code can actually reach a
// person, so a host can assert on its own wiring. It answers from the bound
// sender, never from configuration.
func DeliveryConfigured() bool { return otp.DeliveryConfigured() }
