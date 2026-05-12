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

package conf

import (
	_ "embed"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/beego/beego/v2/server/web"
)

//go:embed waf.conf
var WafConf string

func init() {
	// this array contains the beego configuration items that may be modified via env
	presetConfigItems := []string{"httpport", "appname"}
	for _, key := range presetConfigItems {
		if value, ok := os.LookupEnv(key); ok {
			err := web.AppConfig.Set(key, value)
			if err != nil {
				panic(err)
			}
		}
	}
}

func GetConfigString(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	res, _ := web.AppConfig.String(key)
	if res == "" {
		if key == "staticBaseUrl" {
			res = ""
		} else if key == "logConfig" {
			appname, _ := web.AppConfig.String("appname")
			res = fmt.Sprintf("{\"filename\": \"logs/%s.log\", \"maxdays\":99999, \"perm\":\"0770\"}", appname)
		}
	}

	return res
}

func GetConfigBool(key string) bool {
	value := GetConfigString(key)
	if value == "true" {
		return true
	} else {
		return false
	}
}

func GetConfigInt64(key string) (int64, error) {
	value := GetConfigString(key)
	num, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("GetConfigInt64(%s) error, %s", key, err.Error())
	}

	return num, nil
}

func GetConfigDataSourceName() string {
	// First check for explicit IAM_DATABASE_URL env var (used in cloud deployments)
	if dsn := os.Getenv("IAM_DATABASE_URL"); dsn != "" {
		return ReplaceDataSourceNameByDocker(dsn)
	}
	dataSourceName := GetConfigString("dataSourceName")
	return ReplaceDataSourceNameByDocker(dataSourceName)
}

func ReplaceDataSourceNameByDocker(dataSourceName string) string {
	runningInDocker := os.Getenv("RUNNING_IN_DOCKER")
	if runningInDocker == "true" {
		// https://stackoverflow.com/questions/48546124/what-is-linux-equivalent-of-host-docker-internal
		if runtime.GOOS == "linux" {
			dataSourceName = strings.ReplaceAll(dataSourceName, "localhost", "172.17.0.1")
		} else {
			dataSourceName = strings.ReplaceAll(dataSourceName, "localhost", "host.docker.internal")
		}
	}
	return dataSourceName
}

func GetLanguage(language string) string {
	if language == "" || language == "*" {
		return "en"
	}

	if len(language) != 2 || language == "nu" {
		return "en"
	} else {
		return language
	}
}

<<<<<<< HEAD
// IsDemoMode always returns false. The original upstream Casdoor flag
// gated two unrelated things — the UI "go to writable demo site" hijack
// (ripped 2026-05-12 from web/src/backend/FetchFilter.tsx + App.tsx) and
// a Hanzo-added sandbox-OTP shortcut for repeating-digit phone numbers.
// The OTP shortcut moved to SandboxOTPEnabled(); the UI hijack is gone.
// This stays as a no-op so the web/Conf.tsx wire field still serialises
// (clients drop demo-mode-conditional UI when this is false).
func IsDemoMode() bool {
	return false
}

=======
>>>>>>> 39d25a2b1 (rip demo mode + hardcoded hanzo defaults — make image tenant-neutral)
// SandboxOTPEnabled gates the phone-OTP shortcut: when true, non-E.164
// phone numbers are accepted on signin (the country-code prefix is
// added inline) so seed scripts using sandbox phones like 1337000007
// can complete OTP login. Enabled in any non-prod env. Read from
// ENV first (sandbox infra usually sets this), then `environment` in
// app.conf.
//
// Production envs (production / prod / main / mainnet) hard-disable
// this — real phones MUST parse as E.164 or signin fails clearly.
<<<<<<< HEAD
=======
//
// (Replaces the older `IsDemoMode()` which braided two concerns —
// the OTP shortcut and the upstream Casdoor demo-site UI hijack —
// into one boolean. The UI hijack is ripped; this function keeps
// only the OTP semantics under a name that reflects what it does.)
>>>>>>> 39d25a2b1 (rip demo mode + hardcoded hanzo defaults — make image tenant-neutral)
func SandboxOTPEnabled() bool {
	env := strings.ToLower(os.Getenv("ENV"))
	if env == "" {
		env = strings.ToLower(GetConfigString("environment"))
	}
	switch env {
	case "production", "prod", "main", "mainnet":
		return false
	default:
		return true
	}
}

func GetConfigBatchSize() int {
	res, err := strconv.Atoi(GetConfigString("batchSize"))
	if err != nil {
		res = 100
	}
	return res
}

// AdminOrg returns the namespace owner used for system-wide resources
// (apps, certs, providers, syncers, organizations seeded by init.go).
// Configurable via the `adminOrg` setting in app.conf or env var. Defaults
// to "admin". Set per install — Liquidity uses "admin"; other tenants may
// pick their own. There is no fallback: every "admin"-namespaced lookup
// in the codebase resolves through this single source.
func AdminOrg() string {
	if v := GetConfigString("adminOrg"); v != "" {
		return v
	}
	return "admin"
}
