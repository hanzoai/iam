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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	_ "github.com/beego/beego/v2/server/web/session/redis"
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

func main() {
	web.BConfig.WebConfig.Session.SessionOn = true
	web.BConfig.WebConfig.Session.SessionName = "iam_session_id"
	redisEndpoint := conf.GetConfigString("redisEndpoint")
	if redisEndpoint == "" {
		// Auto-discover Redis in Kubernetes: try well-known service names.
		// This allows the Docker image to use Redis without explicit config
		// when deployed alongside the hanzo-kv service.
		for _, host := range []string{"hanzo-kv", "redis"} {
			if addrs, err := net.LookupHost(host); err == nil && len(addrs) > 0 {
				redisEndpoint = host + ":6379"
				break
			}
		}
	}
	if redisEndpoint == "" {
		web.BConfig.WebConfig.Session.SessionProvider = "file"
		web.BConfig.WebConfig.Session.SessionProviderConfig = "./tmp"
	} else {
		web.BConfig.WebConfig.Session.SessionProvider = "redis"
		web.BConfig.WebConfig.Session.SessionProviderConfig = redisEndpoint
		fmt.Printf("Using Redis for session storage: %s\n", redisEndpoint)
	}
	web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
	web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600 * 24 * 30
	web.BConfig.WebConfig.Session.SessionCookieSameSite = http.SameSiteLaxMode

	routers.InitAPI()
	object.InitFlag()
	object.InitKMS()
	object.InitAdapter()
	object.CreateTables()

	object.InitDb()

	// Handle export command
	if object.ShouldExportData() {
		exportPath := object.GetExportFilePath()
		err := object.DumpToFile(exportPath)
		if err != nil {
			panic(fmt.Sprintf("Error exporting data to %s: %v", exportPath, err))
		}
		fmt.Printf("Data exported successfully to %s\n", exportPath)
		return
	}

	object.InitDefaultStorageProvider()
	object.InitLdapAutoSynchronizer()
	proxy.InitHttpClient()
	authz.InitApi()
	object.InitUserManager()
	object.InitFromFile()
	object.InitCasvisorConfig()
	object.InitCleanupTokens()

	object.InitSiteMap()
	if len(object.SiteMap) != 0 {
		object.InitRuleMap()
		object.StartMonitorSitesLoop()
	}

	util.SafeGoroutine(func() { object.RunSyncUsersJob() })
	util.SafeGoroutine(func() { controllers.InitCLIDownloader() })

	// web.DelStaticPath("/static")
	// web.SetStaticPath("/static", "web/build/static")

	web.BConfig.WebConfig.DirectoryIndex = true
	web.SetStaticPath("/swagger", "swagger")
	web.SetStaticPath("/files", "files")
	// https://studygolang.com/articles/2303
	// SecureCookieFilter MUST run as BeforeStatic — the earliest filter position —
	// because Beego's session init (SessionStart) runs BEFORE BeforeRouter filters.
	// Only BeforeStatic runs before session init, giving us a chance to set
	// req.URL.Scheme and GlobalSessions.SetSecure(true) before the session cookie
	// attributes are determined.
	web.InsertFilter("*", web.BeforeStatic, routers.SecureCookieFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.StaticFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.AutoSigninFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.CorsFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.TimeoutFilter)
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
	// logs.SetLevel(logs.LevelInformational)
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

	web.Run(fmt.Sprintf(":%v", port))
}
