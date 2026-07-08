// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

// session_fixation_test.go — H1 regression: sign-in must regenerate the session
// id so a pre-planted sid can never be shared across the authentication
// boundary. Drives SetSessionUsername (the single sign-in chokepoint) through a
// real memory-backed beego session manager and asserts the sid CHANGES and the
// old sid is INVALIDATED.

package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/beego/v2/server/web"
	beecontext "github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/beego/v2/server/web/session"
)

const fixationCookie = "iam_session_fixation_test"

func newSessionManager(t *testing.T) *session.Manager {
	t.Helper()
	mgr, err := session.NewManager("memory", &session.ManagerConfig{
		CookieName:      fixationCookie,
		Gclifetime:      3600,
		Maxlifetime:     3600,
		EnableSetCookie: true,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// TestSignInRegeneratesSessionID proves the H1 fix: the authenticated identity
// ends up under a FRESH sid, the planted pre-auth sid is destroyed, and pre-auth
// session data is preserved across the migration.
func TestSignInRegeneratesSessionID(t *testing.T) {
	mgr := newSessionManager(t)
	prev := web.GlobalSessions
	web.GlobalSessions = mgr
	t.Cleanup(func() { web.GlobalSessions = prev })
	ctxBg := context.Background()

	// 1) Pre-auth session — the sid an attacker plants in the victim's browser.
	startReq := httptest.NewRequest(http.MethodGet, "/v1/iam/login", nil)
	startRec := httptest.NewRecorder()
	store, err := mgr.SessionStart(startRec, startReq)
	if err != nil {
		t.Fatalf("SessionStart: %v", err)
	}
	plantedSid := store.SessionID(ctxBg)
	if plantedSid == "" {
		t.Fatal("no planted sid established")
	}
	if err := store.Set(ctxBg, "pre", "auth-state"); err != nil {
		t.Fatalf("seed pre-auth data: %v", err)
	}
	store.SessionRelease(ctxBg, startRec)

	// 2) Victim presents the planted sid, then authenticates.
	req := httptest.NewRequest(http.MethodPost, "/v1/iam/login", nil)
	req.AddCookie(&http.Cookie{Name: fixationCookie, Value: plantedSid})
	rec := httptest.NewRecorder()
	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)
	c := &ApiController{Controller: web.Controller{}}
	c.Init(ctx, "ApiController", "Login", c)

	c.SetSessionUsername("alice") // <-- the authentication transition under test

	// 3) The session must now be a NEW sid, not the planted one.
	newSid := c.CruSession.SessionID(ctxBg)
	if newSid == "" || newSid == plantedSid {
		t.Fatalf("sid was NOT regenerated on sign-in (fixation open): planted=%q new=%q", plantedSid, newSid)
	}
	// Authenticated identity lives under the new sid...
	if got := c.CruSession.Get(ctxBg, "username"); got != "alice" {
		t.Fatalf("username not on the regenerated session: %v", got)
	}
	// ...and pre-auth data survived the migration (session preserved, not wiped).
	if got := c.CruSession.Get(ctxBg, "pre"); got != "auth-state" {
		t.Fatalf("pre-auth session data lost across regeneration: %v", got)
	}
	c.CruSession.SessionRelease(ctxBg, rec)

	// 4) The planted (old) sid must be INVALIDATED — reading it must NOT resolve
	//    to the authenticated session. Presenting it yields a fresh, empty
	//    session with no username.
	oldReq := httptest.NewRequest(http.MethodGet, "/", nil)
	oldReq.AddCookie(&http.Cookie{Name: fixationCookie, Value: plantedSid})
	oldRec := httptest.NewRecorder()
	oldStore, err := mgr.SessionStart(oldRec, oldReq)
	if err != nil {
		t.Fatalf("re-read planted sid: %v", err)
	}
	if got := oldStore.Get(ctxBg, "username"); got != nil {
		t.Fatalf("planted sid still carries the authenticated user — fixation NOT closed: %v", got)
	}
}

// TestLogoutStillClearsAndRegenerates guards that the empty-user path (logout via
// ClearUserSession) is unaffected — it clears the username and still regenerates.
func TestLogoutClearsUsername(t *testing.T) {
	mgr := newSessionManager(t)
	prev := web.GlobalSessions
	web.GlobalSessions = mgr
	t.Cleanup(func() { web.GlobalSessions = prev })
	ctxBg := context.Background()

	req := httptest.NewRequest(http.MethodPost, "/v1/iam/logout", nil)
	rec := httptest.NewRecorder()
	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)
	c := &ApiController{Controller: web.Controller{}}
	c.Init(ctx, "ApiController", "Logout", c)

	c.SetSessionUsername("alice")
	if got := c.CruSession.Get(ctxBg, "username"); got != "alice" {
		t.Fatalf("setup: username not set: %v", got)
	}
	c.SetSessionUsername("") // de-auth transition — must NOT panic, must clear
	if got := c.CruSession.Get(ctxBg, "username"); got != "" {
		t.Fatalf("username not cleared on empty set: %v", got)
	}
}
