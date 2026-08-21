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
func Seed(ctx context.Context, db orm.DB, initDataPath string) (*seed.Summary, error) {
	return seed.FromInitData(ctx, db, initDataPath)
}

// RequireSigning reports whether this process holds the keys it signs with, and
// is the precondition a composition root asserts before it opens a listener.
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
// TWO questions, because one key is not the whole job:
//
//   - PlatformSigningCert must resolve. It keys the session-cookie MAC
//     (internal/sessions), so without it no browser session can be issued or read.
//   - EVERY cert this process would PUBLISH must also be able to sign. A token is
//     minted with the cert its application names (oidc.signerFor), and the JWKS
//     advertises a `kid` for each published cert — so a subset of the mount lets
//     the pod report ready and then fail every mint for the applications naming a
//     cert it did not get, while relying parties cache a `kid` nothing signs.
//
// The second question is asked of the CERT ROWS, through the same predicate that
// decided to publish them, and never of the applications that name them. An
// application row is tenant-writable — an org admin registers applications in
// their own org and states a `cert` on them — so an assertion driven from
// applications would let any tenant decide whether the identity plane of the whole
// estate boots. A cert under a reserved owner can only be created by an operator,
// which is what makes it a safe thing to require.
//
// A cert row carrying NEITHER key nor published certificate is not published and
// is not required: that is a rotation staged ahead of its material, which is how a
// rotation is meant to look (internal/certs Create names the key, the deployment
// then provides it).
func RequireSigning(ctx context.Context, db orm.DB) error {
	cert, err := store.PlatformSigningCert(ctx, db)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if cert == nil {
		return fmt.Errorf("signing key: no certificate under a reserved owner carries key material — "+
			"mount one PEM per certificate name in the directory $%s names", keyring.EnvDir)
	}
	names, err := silent(ctx, db)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if len(names) > 0 {
		return fmt.Errorf("signing key: the JWKS publishes %s with no key to sign under — "+
			"mount one PEM per certificate name in the directory $%s names",
			strings.Join(names, ", "), keyring.EnvDir)
	}
	return nil
}

// silent names the published signing certs this process cannot sign with, sorted.
// A published cert is one the JWKS advertises a `kid` for, so every name here is a
// `kid` a relying party will trust and nothing can produce.
func silent(ctx context.Context, db orm.DB) ([]string, error) {
	certs, err := store.ListCerts(ctx, db)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range certs {
		if oidc.Publishes(c) && c.PrivateKey == "" {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out, nil
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
