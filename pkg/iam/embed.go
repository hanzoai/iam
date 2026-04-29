// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package iam exposes an in-process entry point for the Hanzo IAM
// server, mirroring the shape used by github.com/hanzoai/tasks/pkg/tasks.
//
// Embed lets a parent binary (e.g. a fused `hanzo` daemon that runs
// base + iam + kms + tasks together) boot the IAM Beego server in the
// same address space, reuse its http.Handler, and shut it down via
// context. The standalone iamd binary is now a thin wrapper around
// Embed plus signal handling.
//
// Beego carries non-trivial global state (web.BeeApp, sync.Once init
// hooks, beego.AppPath). For that reason Embed is documented as
// safe to call AT MOST ONCE per process. A second call returns
// ErrAlreadyEmbedded — the parent should reuse the original handle.
package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/session"

	"github.com/hanzoai/iam/iamserver"
)

// ErrAlreadyEmbedded is returned by a second Embed call in the same
// process. Beego's web.BeeApp is a singleton; multiple Embeds would
// share state in confusing ways.
var ErrAlreadyEmbedded = errors.New("iam.Embed: already embedded in this process")

// embedded tracks the single live instance per process. Accessed via
// atomic CAS so a racy double-Embed loses cleanly.
var embedded atomic.Pointer[Embedded]

// EmbedConfig configures the in-process IAM server.
//
// Zero values resolve to production-safe defaults that match the
// canonical iamd container image (DataDir=/data/iam, HTTPAddr=:8000).
type EmbedConfig struct {
	// DataDir is where IAM persists its Base/SQLite database.
	// Empty → "/data/iam" (production default).
	DataDir string

	// HTTPAddr is the bind address for the HTTP server.
	// Empty → ":8000". Use ":0" for an ephemeral port (tests).
	HTTPAddr string

	// JWTKeySource is the JWKS URL used when IAM acts as a relying
	// party (e.g. to validate inbound service tokens). Empty →
	// "https://hanzo.id/.well-known/jwks". Stored as env var
	// IAM_JWT_KEY_SOURCE so downstream config readers see it.
	JWTKeySource string

	// AppConfPath is an optional absolute path to a Beego app.conf.
	// Empty → Beego picks up ./conf/app.conf relative to the binary,
	// matching the standalone iamd behaviour.
	AppConfPath string

	// SkipListen, when true, runs the Beego bootstrap but does NOT
	// bind a TCP listener. Use this when the parent binary serves the
	// returned HTTPHandler() over its own listener (e.g. mounted
	// behind hanzoai/gateway). Tests use this flag.
	SkipListen bool

	// Logger is the structured log target. nil → slog.Default().
	Logger *slog.Logger

	// ShutdownTimeout caps how long Stop will wait for in-flight
	// requests to drain. 0 → 10s.
	ShutdownTimeout time.Duration
}

// Embedded is the handle to a running in-process IAM server.
type Embedded struct {
	cfg    EmbedConfig
	logger *slog.Logger

	// server is our managed http.Server when SkipListen=false.
	server *http.Server
	// ln is the bound listener (nil when SkipListen=true).
	ln net.Listener
	// errCh receives the listener exit. Stop() drains it.
	errCh chan error

	stopped atomic.Bool
}

// Embed boots the IAM Beego server in-process and returns a handle.
//
// Embed is safe to call AT MOST ONCE per process. A second call
// returns ErrAlreadyEmbedded.
//
// The provided ctx is used for cancellation; if ctx is cancelled before
// Stop is called, Embed will trigger a graceful shutdown automatically.
func Embed(ctx context.Context, cfg EmbedConfig) (*Embedded, error) {
	if !embedded.CompareAndSwap(nil, &Embedded{}) {
		return nil, ErrAlreadyEmbedded
	}

	cfg = applyDefaults(cfg)
	logger := cfg.Logger

	// Apply env wiring before iamserver.Init touches conf.GetConfigString.
	// Beego's conf reads env vars first, so this overrides app.conf for
	// the embedded boot.
	if cfg.DataDir != "" {
		_ = os.Setenv("IAM_DATA_DIR", cfg.DataDir)
	}
	if cfg.JWTKeySource != "" {
		_ = os.Setenv("IAM_JWT_KEY_SOURCE", cfg.JWTKeySource)
	}
	if cfg.AppConfPath != "" {
		_ = os.Setenv("BEEGO_APP_CONFIG", cfg.AppConfPath)
	}
	// Disable Beego's own graceful runner — we manage shutdown.
	web.BConfig.Listen.Graceful = false

	// Run the heavy bootstrap (DB init, controllers, filters, background
	// loops). iamserver.Init does not bind a listener.
	confPort := iamserver.Init()

	// Beego's session manager is normally initialized inside web.Run() via
	// the unexported initBeforeHTTPRun() hook. The embed path skips
	// web.Run, so we mirror that one hook here. Without it, every request
	// nil-derefs in the router when SessionStart is called.
	if err := initBeegoSessions(); err != nil {
		embedded.Store(nil)
		return nil, fmt.Errorf("iam.Embed: session init: %w", err)
	}

	em := &Embedded{
		cfg:    cfg,
		logger: logger,
		errCh:  make(chan error, 1),
	}

	if !cfg.SkipListen {
		bindAddr := cfg.HTTPAddr
		if bindAddr == "" {
			bindAddr = fmt.Sprintf(":%d", confPort)
		}
		ln, err := net.Listen("tcp", bindAddr)
		if err != nil {
			embedded.Store(nil)
			return nil, fmt.Errorf("iam.Embed: listen %s: %w", bindAddr, err)
		}
		em.ln = ln
		em.cfg.HTTPAddr = ln.Addr().String()

		em.server = &http.Server{
			Handler:           web.BeeApp.Handlers,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		go func() {
			if err := em.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				em.errCh <- err
				return
			}
			em.errCh <- nil
		}()
	}

	embedded.Store(em)

	// Plumb outer ctx cancellation into a background shutdown.
	go func() {
		<-ctx.Done()
		if !em.stopped.Load() {
			_ = em.Stop(context.Background())
		}
	}()

	logger.Info("iam.Embed: server up",
		"http_addr", em.cfg.HTTPAddr,
		"data_dir", cfg.DataDir,
		"skip_listen", cfg.SkipListen,
	)
	return em, nil
}

// HTTPHandler returns the Beego http.Handler. The fused binary mounts
// this behind its own listener (e.g. hanzoai/gateway).
func (e *Embedded) HTTPHandler() http.Handler {
	if e == nil {
		return http.NotFoundHandler()
	}
	return web.BeeApp.Handlers
}

// HTTPAddr returns the bound listen address. Returns "" when
// SkipListen=true.
func (e *Embedded) HTTPAddr() string {
	if e == nil || e.cfg.SkipListen {
		return ""
	}
	return e.cfg.HTTPAddr
}

// Stop gracefully shuts down the IAM server. Idempotent.
//
// Stop does NOT clear the singleton lock — Beego's process-globals
// (logger registration, flag registration, init hooks) are not reset
// by Stop, so a fresh Embed in the same process would still panic.
// The "one Embed per process" contract is enforced for the lifetime
// of the process, not the lifetime of the running server.
func (e *Embedded) Stop(ctx context.Context) error {
	if e == nil || !e.stopped.CompareAndSwap(false, true) {
		return nil
	}

	if e.server != nil {
		shutdownCtx := ctx
		if e.cfg.ShutdownTimeout > 0 {
			var cancel context.CancelFunc
			shutdownCtx, cancel = context.WithTimeout(ctx, e.cfg.ShutdownTimeout)
			defer cancel()
		}
		if err := e.server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.logger.Warn("iam.Embed: shutdown returned error", "err", err)
		}
		select {
		case <-e.errCh:
		case <-time.After(2 * time.Second):
		}
	}

	e.logger.Info("iam.Embed: stopped")
	return nil
}

// applyDefaults resolves zero-value EmbedConfig fields to production
// defaults.
func applyDefaults(cfg EmbedConfig) EmbedConfig {
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir()
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":" + strconv.Itoa(8000)
	}
	if cfg.JWTKeySource == "" {
		cfg.JWTKeySource = "https://hanzo.id/.well-known/jwks"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 10 * time.Second
	}
	return cfg
}

func defaultDataDir() string {
	if v := os.Getenv("IAM_DATA_DIR"); v != "" {
		return v
	}
	return "/data/iam"
}

// initBeegoSessions mirrors beego/v2/server/web.registerSession (an
// unexported hook normally fired inside web.Run). Embed must trigger
// it explicitly because we never call web.Run on the embed path.
//
// The configuration mirrors iamserver.Init's BConfig.WebConfig.Session
// settings — memory provider, name "iam_session_id", lax SameSite. We
// keep this isolated in embed.go so the standalone iamd path is
// unchanged.
//
// Idempotent: if web.GlobalSessions is already populated by a prior
// Embed (or by some test harness calling web.InitBeegoBeforeTest), we
// reuse it.
func initBeegoSessions() error {
	if web.GlobalSessions != nil {
		return nil
	}
	cfg := &session.ManagerConfig{
		CookieName:              web.BConfig.WebConfig.Session.SessionName,
		EnableSetCookie:         web.BConfig.WebConfig.Session.SessionAutoSetCookie,
		Gclifetime:              web.BConfig.WebConfig.Session.SessionGCMaxLifetime,
		Secure:                  web.BConfig.Listen.EnableHTTPS,
		CookieLifeTime:          web.BConfig.WebConfig.Session.SessionCookieLifeTime,
		ProviderConfig:          filepath.ToSlash(web.BConfig.WebConfig.Session.SessionProviderConfig),
		DisableHTTPOnly:         web.BConfig.WebConfig.Session.SessionDisableHTTPOnly,
		Domain:                  web.BConfig.WebConfig.Session.SessionDomain,
		EnableSidInHTTPHeader:   web.BConfig.WebConfig.Session.SessionEnableSidInHTTPHeader,
		SessionNameInHTTPHeader: web.BConfig.WebConfig.Session.SessionNameInHTTPHeader,
		EnableSidInURLQuery:     web.BConfig.WebConfig.Session.SessionEnableSidInURLQuery,
		CookieSameSite:          web.BConfig.WebConfig.Session.SessionCookieSameSite,
		SessionIDPrefix:         web.BConfig.WebConfig.Session.SessionIDPrefix,
	}
	mgr, err := session.NewManager(web.BConfig.WebConfig.Session.SessionProvider, cfg)
	if err != nil {
		return err
	}
	web.GlobalSessions = mgr
	go mgr.GC()
	return nil
}
