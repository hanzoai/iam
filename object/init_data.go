// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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

package object

import (
	"fmt"
	"strings"

	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/util"
	"github.com/xorm-io/core"
)

type InitData struct {
	Organizations []*Organization `json:"organizations"`
	Applications  []*Application  `json:"applications"`
	Users         []*User         `json:"users"`
	Certs         []*Cert         `json:"certs"`
	Providers     []*Provider     `json:"providers"`
	Ldaps         []*Ldap         `json:"ldaps"`
	Models        []*Model        `json:"models"`
	Permissions   []*Permission   `json:"permissions"`
	Resources     []*Resource     `json:"resources"`
	Roles         []*Role         `json:"roles"`
	Syncers       []*Syncer       `json:"syncers"`
	Tokens        []*Token        `json:"tokens"`
	Webhooks      []*Webhook      `json:"webhooks"`
	Groups        []*Group        `json:"groups"`
	Adapters      []*Adapter      `json:"adapters"`
	Enforcers     []*Enforcer     `json:"enforcers"`
	Invitations   []*Invitation   `json:"invitations"`
	Records       []*Record       `json:"records"`
	Sessions      []*Session      `json:"sessions"`
	Sites         []*Site         `json:"sites"`
	Rules         []*Rule         `json:"rules"`

	EnforcerPolicies map[string][][]string `json:"enforcerPolicies"`
}

var initDataNewOnly bool

// syncTrace collects diagnostic messages during InitFromFile so that
// GetInitDataDiagnostics can include them in the HTTP response.
// This lets us debug sync issues without needing kubectl logs access.
var syncTrace []string

func appendSyncTrace(msg string) {
	syncTrace = append(syncTrace, msg)
}

func InitFromFile() {
	initDataFile := conf.GetConfigString("initDataFile")
	if initDataFile == "" {
		return
	}

	initDataNewOnly = conf.GetConfigBool("initDataNewOnly")

	initData, err := readInitDataFromFile(initDataFile)
	if err != nil {
		panic(err)
	}

	if initData != nil {
		// Reset trace for this sync run
		syncTrace = nil

		msg := fmt.Sprintf("processing: orgs=%d providers=%d apps=%d users=%d (newOnly=%v)",
			len(initData.Organizations), len(initData.Providers),
			len(initData.Applications), len(initData.Users), initDataNewOnly)
		fmt.Printf("[init_data] %s\n", msg)
		appendSyncTrace(msg)

		// Log which apps are in the init_data.json file
		for i, app := range initData.Applications {
			appendSyncTrace(fmt.Sprintf("init_data app[%d]: %s/%s (clientId=%s)", i, app.Owner, app.Name, app.ClientId))
		}

		for _, organization := range initData.Organizations {
			initDefinedOrganization(organization)
		}
		for _, provider := range initData.Providers {
			initDefinedProvider(provider)
		}
		for _, application := range initData.Applications {
			initDefinedApplication(application)
		}
		for _, user := range initData.Users {
			initDefinedUser(user)
		}
		for _, cert := range initData.Certs {
			initDefinedCert(cert)
		}
		for _, ldap := range initData.Ldaps {
			initDefinedLdap(ldap)
		}
		for _, model := range initData.Models {
			initDefinedModel(model)
		}
		for _, resource := range initData.Resources {
			initDefinedResource(resource)
		}
		for _, role := range initData.Roles {
			initDefinedRole(role)
		}
		for _, syncer := range initData.Syncers {
			initDefinedSyncer(syncer)
		}
		for _, token := range initData.Tokens {
			initDefinedToken(token)
		}
		for _, webhook := range initData.Webhooks {
			initDefinedWebhook(webhook)
		}
		for _, group := range initData.Groups {
			initDefinedGroup(group)
		}
		for _, adapter := range initData.Adapters {
			initDefinedAdapter(adapter)
		}
		for _, enforcer := range initData.Enforcers {
			policies := initData.EnforcerPolicies[enforcer.GetId()]
			initDefinedEnforcer(enforcer, policies)
		}
		for _, permission := range initData.Permissions {
			initDefinedPermission(permission)
		}
		for _, invitation := range initData.Invitations {
			initDefinedInvitation(invitation)
		}
		for _, record := range initData.Records {
			initDefinedRecord(record)
		}
		for _, session := range initData.Sessions {
			initDefinedSession(session)
		}
		for _, rule := range initData.Rules {
			initDefinedRule(rule)
		}
		for _, site := range initData.Sites {
			initDefinedSite(site)
		}
	}
}

func readInitDataFromFile(filePath string) (*InitData, error) {
	if !util.FileExist(filePath) {
		return nil, nil
	}

	s := util.ReadStringFromPath(filePath)
	s = resolveSecrets(s)

	data := &InitData{
		Organizations: []*Organization{},
		Applications:  []*Application{},
		Users:         []*User{},
		Certs:         []*Cert{},
		Providers:     []*Provider{},
		Ldaps:         []*Ldap{},
		Models:        []*Model{},
		Permissions:   []*Permission{},
		Resources:     []*Resource{},
		Roles:         []*Role{},
		Syncers:       []*Syncer{},
		Tokens:        []*Token{},
		Webhooks:      []*Webhook{},
		Groups:        []*Group{},
		Adapters:      []*Adapter{},
		Enforcers:     []*Enforcer{},
		Invitations:   []*Invitation{},
		Records:       []*Record{},
		Sessions:      []*Session{},
		Sites:         []*Site{},
		Rules:         []*Rule{},

		EnforcerPolicies: map[string][][]string{},
	}
	err := util.JsonToStruct(s, data)
	if err != nil {
		return nil, err
	}

	// transform nil slice to empty slice
	for _, organization := range data.Organizations {
		if organization.Tags == nil {
			organization.Tags = []string{}
		}
		if organization.AccountItems == nil {
			organization.AccountItems = []*AccountItem{}
		}
	}
	for _, application := range data.Applications {
		if application.Providers == nil {
			application.Providers = []*ProviderItem{}
		}
		if application.SigninMethods == nil {
			application.SigninMethods = []*SigninMethod{}
		}
		if application.SignupItems == nil {
			application.SignupItems = []*SignupItem{}
		}
		if application.GrantTypes == nil {
			application.GrantTypes = []string{}
		}
		if application.Tags == nil {
			application.Tags = []string{}
		}
		if application.RedirectUris == nil {
			application.RedirectUris = []string{}
		}
		if application.TokenFields == nil {
			application.TokenFields = []string{}
		}
	}
	for _, permission := range data.Permissions {
		if permission.Actions == nil {
			permission.Actions = []string{}
		}
		if permission.Resources == nil {
			permission.Resources = []string{}
		}
		if permission.Roles == nil {
			permission.Roles = []string{}
		}
		if permission.Users == nil {
			permission.Users = []string{}
		}
	}
	for _, role := range data.Roles {
		if role.Roles == nil {
			role.Roles = []string{}
		}
		if role.Users == nil {
			role.Users = []string{}
		}
	}
	for _, syncer := range data.Syncers {
		if syncer.TableColumns == nil {
			syncer.TableColumns = []*TableColumn{}
		}
	}
	for _, webhook := range data.Webhooks {
		if webhook.Events == nil {
			webhook.Events = []string{}
		}
		if webhook.Headers == nil {
			webhook.Headers = []*Header{}
		}
	}
	for _, session := range data.Sessions {
		if session.SessionId == nil {
			session.SessionId = []string{}
		}
	}
	return data, nil
}

func initDefinedOrganization(organization *Organization) {
	existed, err := getOrganization(organization.Owner, organization.Name)
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			// Merge languages: ensure all init_data languages are enabled (additive only)
			if len(organization.Languages) > len(existed.Languages) {
				langSet := make(map[string]bool, len(existed.Languages))
				for _, l := range existed.Languages {
					langSet[l] = true
				}
				var added []string
				for _, l := range organization.Languages {
					if !langSet[l] {
						added = append(added, l)
					}
				}
				if len(added) > 0 {
					existed.Languages = append(existed.Languages, added...)
					_, updateErr := ormer.Engine.Where("owner = ? AND name = ?",
						existed.Owner, existed.Name).
						Cols("languages").
						Update(existed)
					if updateErr != nil {
						fmt.Printf("[init_data] WARNING: failed to merge languages for org %s: %v\n",
							existed.Name, updateErr)
					} else {
						fmt.Printf("[init_data] org %s: merged %d languages (%v)\n",
							existed.Name, len(added), added)
					}
				}
			}
			return
		}
		affected, err := deleteOrganization(organization)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete organization")
		}
	}
	organization.CreatedTime = util.GetCurrentTime()
	if len(organization.AccountItems) == 0 {
		organization.AccountItems = getBuiltInAccountItems()
	}

	_, err = AddOrganization(organization)
	if err != nil {
		panic(err)
	}
}

func initDefinedApplication(application *Application) {
	appId := fmt.Sprintf("%s/%s", application.Owner, application.Name)

	// Evict ALL caches for this app — the caches may report "exists" even when
	// the DB row has been deleted, causing initDataNewOnly mode to skip re-creation.
	// We must evict both the owner/name cache AND the clientId cache because
	// AddApplication checks GetApplicationByClientId which uses its own cache.
	EvictAppCache(application.Owner, application.Name)
	if application.ClientId != "" {
		EvictAppCacheByClientId(application.ClientId)
	}
	appendSyncTrace(fmt.Sprintf("[%s] cache evicted (clientId=%s)", appId, application.ClientId))

	// Query DB using explicit WHERE to check true existence.
	// (Using Where() instead of struct-based Get to avoid xorm auto-condition quirks)
	var dbApp Application
	dbExists, err := ormer.Engine.Where("owner = ? AND name = ?",
		application.Owner, application.Name).Get(&dbApp)
	if err != nil {
		appendSyncTrace(fmt.Sprintf("[%s] ERROR: DB check failed: %v", appId, err))
		panic(err)
	}
	appendSyncTrace(fmt.Sprintf("[%s] DB check (WHERE): exists=%v", appId, dbExists))

	// If PK-based lookup fails, also check by client_id.
	// This handles the case where the row exists in the DB but with subtly
	// different owner/name values (e.g., whitespace, encoding differences).
	if !dbExists && application.ClientId != "" {
		var cidApp Application
		cidExists, cidErr := ormer.Engine.Where("client_id = ?",
			application.ClientId).Get(&cidApp)
		if cidErr == nil && cidExists {
			appendSyncTrace(fmt.Sprintf("[%s] NOT FOUND by PK, but FOUND by clientId=%s (DB owner=%q name=%q ownerLen=%d nameLen=%d)",
				appId, application.ClientId, cidApp.Owner, cidApp.Name, len(cidApp.Owner), len(cidApp.Name)))

			// Only delete the orphaned row if it belongs to the same owner (prevent cross-org deletion)
			if cidApp.Owner == application.Owner {
				_, delErr := ormer.Engine.Where("client_id = ? AND owner = ?", application.ClientId, application.Owner).Delete(&Application{})
				if delErr != nil {
					appendSyncTrace(fmt.Sprintf("[%s] ERROR deleting orphan by clientId: %v", appId, delErr))
				} else {
					appendSyncTrace(fmt.Sprintf("[%s] deleted orphan row with clientId=%s", appId, application.ClientId))
				}
			} else {
				appendSyncTrace(fmt.Sprintf("[%s] SKIPPED orphan deletion: clientId=%s belongs to different owner %q", appId, application.ClientId, cidApp.Owner))
			}
			// Fall through to create the app fresh with correct PK values
		}
	}

	if dbExists {
		if initDataNewOnly {
			// Re-cache the app since we evicted it above.
			appCache.set(appCacheKey(application.Owner, application.Name), dbApp, appCacheTTL)
			// Merge critical OAuth fields that may be missing from apps
			// created before init_data.json was updated.
			mergeApplicationOAuthDefaults(&dbApp, application)
			appendSyncTrace(fmt.Sprintf("[%s] EXISTS + newOnly=true → skipped (merged defaults)", appId))
			return
		}
		affected, err := deleteApplication(application)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete application")
		}
	} else {
		fmt.Printf("[init_data] app %s NOT FOUND in DB, creating...\n", appId)
		appendSyncTrace(fmt.Sprintf("[%s] NOT FOUND → will create", appId))
	}
	application.CreatedTime = util.GetCurrentTime()
	created, err := AddApplication(application)
	if err != nil {
		appendSyncTrace(fmt.Sprintf("[%s] AddApplication ERROR: %v", appId, err))
		fmt.Printf("[init_data] AddApplication FAILED for %s: %v\n", appId, err)
		panic(err)
	}
	appendSyncTrace(fmt.Sprintf("[%s] AddApplication returned: created=%v", appId, created))

	// xorm omits bool fields without explicit column tags, so boolean values
	// from init_data.json are silently dropped during Insert. Fix them with
	// a raw SQL UPDATE immediately after creation.
	if created {
		_, sqlErr := ormer.Engine.Exec(
			`UPDATE "application" SET enable_password=$1, enable_sign_up=$2, enable_signin_session=$3, enable_code_signin=$4, enable_web_authn=$5, enable_auto_signin=$6, enable_link_with_email=$7 WHERE owner=$8 AND name=$9`,
			application.EnablePassword, application.EnableSignUp, application.EnableSigninSession,
			application.EnableCodeSignin, application.EnableWebAuthn, application.EnableAutoSignin,
			application.EnableLinkWithEmail, application.Owner, application.Name,
		)
		if sqlErr != nil {
			fmt.Printf("[init_data] WARNING: bool fixup SQL failed for %s: %v\n", appId, sqlErr)
		} else {
			fmt.Printf("[AddApplication] app %s bool fields fixed (enablePassword=%v, enableSignUp=%v, enableSigninSession=%v)\n",
				appId, application.EnablePassword, application.EnableSignUp, application.EnableSigninSession)
			// Refresh the in-process app cache so the API returns the corrected booleans.
			appCache.set(appCacheKey(application.Owner, application.Name), *application, appCacheTTL)
		}
	}

	// Verify the app actually exists in DB after creation
	if !created {
		var verifyApp Application
		verifyExists, _ := ormer.Engine.Where("owner = ? AND name = ?",
			application.Owner, application.Name).Get(&verifyApp)
		var verifyCid Application
		cidExists2, _ := ormer.Engine.Where("client_id = ?",
			application.ClientId).Get(&verifyCid)
		appendSyncTrace(fmt.Sprintf("[%s] POST-CREATE VERIFY: byPK=%v byCid=%v (cidOwner=%q cidName=%q)",
			appId, verifyExists, cidExists2, verifyCid.Owner, verifyCid.Name))
	}
}

// mergeApplicationOAuthDefaults updates an existing application's critical OAuth
// fields if they are empty/default but the init_data definition has values.
// This ensures apps created before init_data.json changes still get essential
// configuration like redirectUris, grantTypes, enablePassword, etc.
func mergeApplicationOAuthDefaults(existing *Application, desired *Application) {
	var updateCols []string

	// Merge redirectUris if existing has none but desired has values
	if len(existing.RedirectUris) == 0 && len(desired.RedirectUris) > 0 {
		existing.RedirectUris = desired.RedirectUris
		updateCols = append(updateCols, "redirect_uris")
	}

	// Merge grantTypes if existing has none
	if len(existing.GrantTypes) == 0 && len(desired.GrantTypes) > 0 {
		existing.GrantTypes = desired.GrantTypes
		updateCols = append(updateCols, "grant_types")
	}

	// Enable password login if desired wants it but existing has it off
	if !existing.EnablePassword && desired.EnablePassword {
		existing.EnablePassword = true
		updateCols = append(updateCols, "enable_password")
	}

	// Enable session-based signin if desired wants it but existing has it off
	if !existing.EnableSigninSession && desired.EnableSigninSession {
		existing.EnableSigninSession = true
		updateCols = append(updateCols, "enable_signin_session")
	}

	// Enable code signin if desired wants it but existing has it off
	if !existing.EnableCodeSignin && desired.EnableCodeSignin {
		existing.EnableCodeSignin = true
		updateCols = append(updateCols, "enable_code_signin")
	}

	// Merge tokenFormat if existing is empty
	if existing.TokenFormat == "" && desired.TokenFormat != "" {
		existing.TokenFormat = desired.TokenFormat
		updateCols = append(updateCols, "token_format")
	}

	// Merge expireInHours if existing is invalid (0 or negative)
	if existing.ExpireInHours <= 0 && desired.ExpireInHours > 0 {
		existing.ExpireInHours = desired.ExpireInHours
		updateCols = append(updateCols, "expire_in_hours")
	}

	// Merge refreshExpireInHours if existing is invalid
	if existing.RefreshExpireInHours <= 0 && desired.RefreshExpireInHours > 0 {
		existing.RefreshExpireInHours = desired.RefreshExpireInHours
		updateCols = append(updateCols, "refresh_expire_in_hours")
	}

	// Merge cert if existing is empty
	if existing.Cert == "" && desired.Cert != "" {
		existing.Cert = desired.Cert
		updateCols = append(updateCols, "cert")
	}

	// Merge providers if existing has none
	if len(existing.Providers) == 0 && len(desired.Providers) > 0 {
		existing.Providers = desired.Providers
		updateCols = append(updateCols, "providers")
	}

	// Merge themeData if existing has none
	if existing.ThemeData == nil && desired.ThemeData != nil {
		existing.ThemeData = desired.ThemeData
		updateCols = append(updateCols, "theme_data")
	}

	// Merge termsOfUse if existing is empty
	if existing.TermsOfUse == "" && desired.TermsOfUse != "" {
		existing.TermsOfUse = desired.TermsOfUse
		updateCols = append(updateCols, "terms_of_use")
	}

	if len(updateCols) == 0 {
		return
	}

	fmt.Printf("[init_data] merging %d OAuth fields for app %s/%s: %v\n",
		len(updateCols), existing.Owner, existing.Name, updateCols)

	_, err := ormer.Engine.ID(core.PK{existing.Owner, existing.Name}).
		Cols(updateCols...).
		Update(existing)
	if err != nil {
		fmt.Printf("[init_data] WARNING: failed to merge app %s/%s: %v\n",
			existing.Owner, existing.Name, err)
	} else {
		// Evict cache so subsequent lookups see the updated values
		EvictAppCache(existing.Owner, existing.Name)
	}
}

func initDefinedUser(user *User) {
	existed, err := getUser(user.Owner, user.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		// SAFETY: Never delete/recreate existing users regardless of initDataNewOnly.
		// Users may have changed their passwords, profile data, MFA settings, etc.
		// Deleting and recreating would destroy all of that.
		// Only create users that don't exist yet (first-time bootstrap).
		fmt.Printf("[init_data] user %s/%s EXISTS (id=%s, pwdType=%s, pwdLen=%d) → SKIPPED (never overwrite existing users)\n",
			user.Owner, user.Name, existed.Id, existed.PasswordType, len(existed.Password))
		return
	}

	fmt.Printf("[init_data] user %s/%s NOT FOUND, creating with pwdType=%q, pwdLen=%d\n",
		user.Owner, user.Name, user.PasswordType, len(user.Password))
	user.CreatedTime = util.GetCurrentTime()
	user.Id = util.GenerateId()
	if user.Properties == nil {
		user.Properties = make(map[string]string)
	}
	_, err = AddUser(user, "en")
	if err != nil {
		fmt.Printf("[init_data] AddUser %s/%s FAILED: %v\n", user.Owner, user.Name, err)
		panic(err)
	}
	fmt.Printf("[init_data] user %s/%s CREATED successfully (id=%s)\n", user.Owner, user.Name, user.Id)
}

func initDefinedCert(cert *Cert) {
	existed, err := getCert(cert.Owner, cert.Name)
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteCert(cert)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete cert")
		}
	}
	cert.CreatedTime = util.GetCurrentTime()
	_, err = AddCert(cert)
	if err != nil {
		panic(err)
	}
}

func initDefinedLdap(ldap *Ldap) {
	existed, err := GetLdap(ldap.Id)
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteLdap(ldap)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete ldap")
		}
	}
	_, err = AddLdap(ldap)
	if err != nil {
		panic(err)
	}
}

func initDefinedProvider(provider *Provider) {
	existed, err := GetProvider(util.GetId("admin", provider.Name))
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteProvider(provider)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete provider")
		}
	}
	_, err = AddProvider(provider)
	if err != nil {
		panic(err)
	}
}

func initDefinedModel(model *Model) {
	existed, err := GetModel(model.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteModel(model)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete provider")
		}
	}
	model.CreatedTime = util.GetCurrentTime()
	_, err = AddModel(model)
	if err != nil {
		panic(err)
	}
}

func initDefinedPermission(permission *Permission) {
	existed, err := GetPermission(permission.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := deletePermission(permission)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete permission")
		}
	}
	permission.CreatedTime = util.GetCurrentTime()
	_, err = AddPermission(permission)
	if err != nil {
		panic(err)
	}
}

func initDefinedResource(resource *Resource) {
	existed, err := GetResource(resource.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteResource(resource)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete resource")
		}
	}
	resource.CreatedTime = util.GetCurrentTime()
	_, err = AddResource(resource)
	if err != nil {
		panic(err)
	}
}

func initDefinedRole(role *Role) {
	existed, err := GetRole(role.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := deleteRole(role)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete role")
		}
	}
	role.CreatedTime = util.GetCurrentTime()
	_, err = AddRole(role)
	if err != nil {
		panic(err)
	}
}

func initDefinedSyncer(syncer *Syncer) {
	existed, err := GetSyncer(syncer.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteSyncer(syncer)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete role")
		}
	}
	syncer.CreatedTime = util.GetCurrentTime()
	_, err = AddSyncer(syncer)
	if err != nil {
		panic(err)
	}
}

func initDefinedToken(token *Token) {
	existed, err := GetToken(token.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteToken(token)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete token")
		}
	}
	token.CreatedTime = util.GetCurrentTime()
	_, err = AddToken(token)
	if err != nil {
		panic(err)
	}
}

func initDefinedWebhook(webhook *Webhook) {
	existed, err := GetWebhook(webhook.GetId())
	if err != nil {
		panic(err)
	}

	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteWebhook(webhook)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete webhook")
		}
	}
	webhook.CreatedTime = util.GetCurrentTime()
	_, err = AddWebhook(webhook)
	if err != nil {
		panic(err)
	}
}

func initDefinedGroup(group *Group) {
	existed, err := getGroup(group.Owner, group.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := deleteGroup(group)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete group")
		}
	}
	group.CreatedTime = util.GetCurrentTime()
	_, err = AddGroup(group)
	if err != nil {
		panic(err)
	}
}

func initDefinedAdapter(adapter *Adapter) {
	existed, err := getAdapter(adapter.Owner, adapter.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteAdapter(adapter)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete adapter")
		}
	}
	adapter.CreatedTime = util.GetCurrentTime()
	_, err = AddAdapter(adapter)
	if err != nil {
		panic(err)
	}
}

func initDefinedEnforcer(enforcer *Enforcer, policies [][]string) {
	existed, err := getEnforcer(enforcer.Owner, enforcer.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteEnforcer(enforcer)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete enforcer")
		}
	}
	enforcer.CreatedTime = util.GetCurrentTime()
	_, err = AddEnforcer(enforcer)
	if err != nil {
		panic(err)
	}

	err = enforcer.InitEnforcer()
	if err != nil {
		panic(err)
	}

	for _, policy := range policies {
		if enforcer.HasPolicy(policy) {
			continue
		}

		_, err = enforcer.AddPolicy(policy)
		if err != nil {
			panic(err)
		}
	}

	err = enforcer.SavePolicy()
	if err != nil {
		panic(err)
	}
}

func initDefinedInvitation(invitation *Invitation) {
	existed, err := getInvitation(invitation.Owner, invitation.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteInvitation(invitation)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete invitation")
		}
	}
	invitation.CreatedTime = util.GetCurrentTime()
	_, err = AddInvitation(invitation, "en")
	if err != nil {
		panic(err)
	}
}

func initDefinedRecord(record *Record) {
	record.Id = 0
	record.CreatedTime = util.GetCurrentTime()
	_ = AddRecord(record)
}

func initDefinedSession(session *Session) {
	session.CreatedTime = util.GetCurrentTime()
	_, err := AddSession(session)
	if err != nil {
		panic(err)
	}
}

func initDefinedSite(site *Site) {
	existed, err := getSite(site.Owner, site.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteSite(site)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete site")
		}
	}
	site.CreatedTime = util.GetCurrentTime()
	_, err = AddSite(site)
	if err != nil {
		panic(err)
	}
}

func initDefinedRule(rule *Rule) {
	existed, err := getRule(rule.Owner, rule.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		if initDataNewOnly {
			return
		}
		affected, err := DeleteRule(rule)
		if err != nil {
			panic(err)
		}
		if !affected {
			panic("Fail to delete rule")
		}
	}
	rule.CreatedTime = util.GetCurrentTime()
	_, err = AddRule(rule)
	if err != nil {
		panic(err)
	}
}

// GetInitDataDiagnostics returns a safe summary of init data sync status.
// Does NOT expose DB schema, indexes, raw SQL, or internal state in production.
func GetInitDataDiagnostics() map[string]interface{} {
	result := map[string]interface{}{
		"status":     "ok",
		"newOnly":    initDataNewOnly,
		"traceCount": len(syncTrace),
	}

	// Only expose detailed diagnostics in dev mode
	runmode := conf.GetConfigString("runmode")
	if runmode != "dev" {
		return result
	}

	// Dev-only: app count and sync trace summary
	count, err := ormer.Engine.Count(&Application{})
	if err != nil {
		result["total-apps"] = fmt.Sprintf("error: %v", err)
	} else {
		result["total-apps"] = count
	}

	var filteredTrace []string
	for _, entry := range syncTrace {
		if strings.Contains(entry, "processing:") ||
			strings.Contains(entry, "ERROR") ||
			strings.Contains(entry, "FAILED") {
			filteredTrace = append(filteredTrace, entry)
		}
	}
	result["sync-trace"] = filteredTrace

	return result
}
