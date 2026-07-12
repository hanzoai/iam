// Copyright 2021 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package iamserver exports the IAM Beego server startup logic.
package iamserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/hanzoai/beego/v2/core/logs"
	"github.com/hanzoai/beego/v2/server/web"
	"github.com/hanzoai/iam/authz"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/controllers"
	"github.com/hanzoai/iam/ldap"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/proxy"
	"github.com/hanzoai/iam/radius"
	"github.com/hanzoai/iam/routers"
	"github.com/hanzoai/iam/service"
	"github.com/hanzoai/iam/util"
)

// Run starts the IAM Beego server. This is the body of the original main().
//
// Sessions use the beego `memory` provider. Multi-pod IAM is intentionally
// not supported — every cluster runs IAM at a single replica and per-org
// persistent state lives in SQLite under DATA_DIR (replicated by Base
// Network quasar when that flips on). There is no external cache.
func Run() {
	port := Init()
	web.Run(fmt.Sprintf(":%v", port))
}

// bootConfig selects the standalone-daemon-only side effects the shared
// bootstrap runs. The identity runtime itself — config, DB, controllers,
// filters, and the background sync/monitor loops — is IDENTICAL in both modes;
// only process-management and network-listener steps that make sense ONLY for
// the standalone iamd daemon are gated, so in-process embedding cannot inherit a
// standalone side effect that would crash or endanger the shared parent process.
type bootConfig struct {
	// reapOldInstance runs util.StopOldInstance(httpport): it finds the PID
	// holding the HTTP port and kills it. STANDALONE-ONLY — it shells out to
	// `lsof` (absent on distroless/scratch → *exec.Error → panic) and would
	// SIGKILL a co-resident process sharing the netns. The embed owns process
	// lifecycle; there is no prior IAM instance to reap.
	reapOldInstance bool
	// startDirectoryListeners starts the LDAP + RADIUS network servers.
	// STANDALONE-ONLY — RADIUS has no port guard and binds an ephemeral UDP
	// socket with an EMPTY shared secret that is never torn down: an unmanaged
	// credential channel inside a shared auth process. The embed serves only the
	// HTTP handler; a deployment that needs LDAP/RADIUS runs standalone iamd.
	startDirectoryListeners bool
	// allowExportAndExit honors the IAM export envelope by dumping the DB and
	// calling os.Exit(0). STANDALONE-ONLY — an embed must never terminate its
	// parent binary.
	allowExportAndExit bool
}

// Init runs the full IAM bootstrap for the STANDALONE iamd server (config, DB,
// controllers, filters, background loops) but does NOT bind the HTTP listener —
// Run adds that. Standalone contract unchanged: it reaps any old instance on the
// HTTP port and starts the LDAP/RADIUS listeners. Returns the configured HTTP
// port from app.conf.
func Init() int {
	return bootstrap(bootConfig{
		reapOldInstance:         true,
		startDirectoryListeners: true,
		allowExportAndExit:      true,
	})
}

// InitEmbed runs the IAM bootstrap for IN-PROCESS embedding inside a parent
// binary (hanzoai/cloud), returning an error instead of panicking so the
// embedding subsystem can degrade to fail-closed health-only rather than crash
// every co-resident subsystem (KMS, o11y, …). It is Init WITHOUT the
// standalone-daemon side effects that are wrong or dangerous in a shared
// multi-subsystem process:
//
//   - NO StopOldInstance — the reaper shells `lsof` (panics on distroless) and
//     would SIGKILL whatever holds :8000 on a shared netns.
//   - NO LDAP/RADIUS listeners — they bind unmanaged network sockets (RADIUS: an
//     ephemeral UDP port with an empty shared secret) with no teardown.
//   - NO export/os.Exit — an embed must never terminate its parent.
//   - NO HTTP listener (same as Init) — the parent serves web.BeeApp.Handlers.
//
// The parent obtains the routed handler via web.BeeApp.Handlers and must also
// register the Beego session manager (web.Run does this; the embed path skips
// it, so the parent wires it explicitly).
func InitEmbed() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("iamserver.InitEmbed: bootstrap panicked: %v", r)
		}
	}()
	bootstrap(bootConfig{
		reapOldInstance:         false,
		startDirectoryListeners: false,
		allowExportAndExit:      false,
	})
	return nil
}

// bootstrap is the shared IAM boot body. Both Init (standalone) and InitEmbed
// (in-process) call it; cfg gates the standalone-daemon-only side effects.
func bootstrap(cfg bootConfig) int {
	// Refuse to boot if SANDBOX_GLOBAL_OTP is set on a non-sandbox origin.
	// This is a hard fail — see iamserver/sandbox_guard.go.
	EnforceSandboxOriginGuard()

	// Refuse to boot if IAM_SMS_PROVIDER=twilio or IAM_EMAIL_PROVIDER=sendgrid
	// is set but the required credentials are missing. Caches the resolved
	// mode for the process lifetime — see object/otp_provider.go.
	object.EnforceOTPProviderGuard()

	// Resolve IAM_NOTIFY_ZAP_ADDR once. When set to cloud's ZAP listener, every
	// OTP send routes to the canonical notify surface over ZAP with an IAM-minted
	// M2M token — never go-sms-sender / SendGrid in-process. See
	// object/notify_delivery.go.
	object.EnforceNotifyDeliveryGuard()

	web.BConfig.WebConfig.Session.SessionOn = true
	web.BConfig.WebConfig.Session.SessionName = "iam_session_id"
	web.BConfig.WebConfig.Session.SessionProvider = "memory"
	web.BConfig.WebConfig.Session.SessionProviderConfig = ""
	web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
	web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600 * 24 * 30
	web.BConfig.WebConfig.Session.SessionCookieSameSite = http.SameSiteLaxMode

	routers.InitAPI()
	object.InitFlag()
	object.InitKMS()
	object.InitAdapter()
	object.CreateTables()

	object.InitDb()

	// Handle export command (standalone only). We exit the process here rather
	// than returning a port, because the standalone iamd binary's contract is
	// "init then run". The embedded path never sets the export envelope AND must
	// never call os.Exit on its parent, so it is gated off entirely.
	if cfg.allowExportAndExit && object.ShouldExportData() {
		exportPath := object.GetExportFilePath()
		err := object.DumpToFile(exportPath)
		if err != nil {
			panic(fmt.Sprintf("Error exporting data to %s: %v", exportPath, err))
		}
		fmt.Printf("Data exported successfully to %s\n", exportPath)
		os.Exit(0)
	}

	object.InitDefaultStorageProvider()
	object.InitLdapAutoSynchronizer()
	proxy.InitHttpClient()
	authz.InitApi()
	object.InitUserManager()
	object.InitFromFile()

	// Seed a default project for every org that lacks one (idempotent, live-safe).
	// Runs after all orgs are seeded. Best-effort: a failure just leaves the
	// `project` claim absent (default scope) — it must never crash boot.
	if _, err := object.BackfillDefaultProjects(); err != nil {
		logs.Warning("BackfillDefaultProjects failed (default `project` claim will be absent until reseed): %v", err)
	}

	object.InitCleanupTokens()

	object.InitSiteMap()
	if len(object.SiteMap) != 0 {
		object.InitRuleMap()
		object.StartMonitorSitesLoop()
	}

	util.SafeGoroutine(func() { object.RunSyncUsersJob() })

	// Initialize IDV service with provider configs from env.
	controllers.InitIDV(
		conf.GetConfigString("amlUrl"),
		conf.GetConfigString("jumioApiKey"),
		conf.GetConfigString("jumioApiSecret"),
		conf.GetConfigString("jumioEndpoint"),
		conf.GetConfigString("onfidoApiToken"),
		conf.GetConfigString("onfidoWebhookToken"),
		conf.GetConfigString("onfidoEndpoint"),
		conf.GetConfigString("plaidClientId"),
		conf.GetConfigString("plaidSecret"),
		conf.GetConfigString("plaidEndpoint"),
		conf.GetConfigString("idvWebhookSecret"),
		conf.GetConfigString("bdWebhookUrl"),
	)

	web.BConfig.WebConfig.DirectoryIndex = true
	web.SetStaticPath("/swagger", "swagger")
	web.SetStaticPath("/files", "files")
	web.SetStaticPath("/_/iam", "ui/dist")
	web.InsertFilter("*", web.BeforeStatic, routers.SecureCookieFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.StaticFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.CorsFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.AutoSigninFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.TimeoutFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.VerificationRateLimitFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.LoginRateLimitFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.ApiFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.PrometheusFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.RecordMessage)
	web.InsertFilter("*", web.BeforeRouter, routers.FieldValidationFilter)
	web.InsertFilter("*", web.AfterExec, routers.AfterRecordMessage, web.WithReturnOnOutput(false))

	var logAdapter string
	logConfigMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(conf.GetConfigString("logConfig")), &logConfigMap)
	if err != nil {
		panic(err)
	}
	_, ok := logConfigMap["adapter"]
	if !ok {
		logAdapter = "file"
	} else {
		logAdapter = logConfigMap["adapter"].(string)
	}
	if logAdapter == "console" {
		logs.Reset()
	}
	err = logs.SetLogger(logAdapter, conf.GetConfigString("logConfig"))
	if err != nil {
		panic(err)
	}

	port := web.AppConfig.DefaultInt("httpport", 8000)
	logs.SetLogFuncCall(false)

	// Reap a stale instance holding the HTTP port (standalone only): shells `lsof`
	// and kills the PID. Skipped when embedded — the parent owns process lifecycle
	// and `lsof` is absent on distroless (its *exec.Error would panic the parent).
	if cfg.reapOldInstance {
		err = util.StopOldInstance(port)
		if err != nil {
			panic(err)
		}
	}

	// Directory-protocol listeners (standalone only). Skipped when embedded:
	// RADIUS binds an unmanaged ephemeral UDP socket with an empty shared secret
	// and is never torn down; a deployment needing LDAP/RADIUS runs standalone iamd.
	if cfg.startDirectoryListeners {
		go ldap.StartLdapServer()
		go radius.StartRadiusServer()
	}
	go object.ClearThroughputPerSecond()

	if len(object.SiteMap) != 0 {
		service.Start()
	}

	return port
}
