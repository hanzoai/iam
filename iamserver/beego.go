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

// Init runs the full IAM bootstrap (config, DB, controllers, filters,
// background loops) but does NOT bind a listener. It returns the
// configured HTTP port from app.conf.
//
// This is the entry point for in-process embedding (see
// github.com/hanzoai/iam/pkg/iam.Embed). The standalone iamd binary
// uses Run, which is Init + web.Run.
func Init() int {
	// Refuse to boot if SANDBOX_GLOBAL_OTP is set on a non-sandbox origin.
	// This is a hard fail — see iamserver/sandbox_guard.go.
	EnforceSandboxOriginGuard()

	// Refuse to boot if IAM_SMS_PROVIDER=twilio or IAM_EMAIL_PROVIDER=sendgrid
	// is set but the required credentials are missing. Caches the resolved
	// mode for the process lifetime — see object/otp_provider.go.
	object.EnforceOTPProviderGuard()

	// Resolve IAM_NOTIFY_URL once. When set to a notifyd base URL, every
	// OTP send routes through hanzoai/notify instead of go-sms-sender /
	// SendGrid in-process. See object/notify_delivery.go.
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

	// Handle export command. We exit the process here rather than
	// returning a port, because the standalone iamd binary's contract is
	// "init then run", and the embedded path never sets the export
	// envelope. This keeps the Init() return type honest: a real,
	// listenable port for every successful return.
	if object.ShouldExportData() {
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
	// PathRewriteFilter MUST run first so every other filter (and the
	// router itself) sees the canonical path. /v1/iam/foo, /api/iam/foo,
	// and /oauth/* all resolve to one set of routes registered in router.go.
	web.InsertFilter("*", web.BeforeRouter, routers.PathRewriteFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.StaticFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.AutoSigninFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.CorsFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.TimeoutFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.VerificationRateLimitFilter)
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

	err = util.StopOldInstance(port)
	if err != nil {
		panic(err)
	}

	go ldap.StartLdapServer()
	go radius.StartRadiusServer()
	go object.ClearThroughputPerSecond()

	if len(object.SiteMap) != 0 {
		service.Start()
	}

	return port
}
