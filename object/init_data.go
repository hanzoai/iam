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
	"github.com/hanzoai/iam/cred"
	"github.com/hanzoai/iam/util"
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

		// Evict app cache — init may have created orgs after apps were
		// first loaded, leaving cached apps with organizationObj: nil.
		for _, application := range initData.Applications {
			EvictAppCache(application.Owner, application.Name)
			if application.ClientId != "" {
				EvictAppCacheByClientId(application.ClientId)
			}
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
		organization.AccountItems = getAdminAccountItems()
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
			// Extend with org before caching so orgObj is populated.
			_ = extendApplicationWithOrg(&dbApp)
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

	// xorm omits bool fields and may mis-serialize slices during Insert.
	// Fix booleans and grant_types with a raw SQL UPDATE immediately after creation.
	if created {
		grantTypesJSON := util.StructToJson(application.GrantTypes)
		providersJSON := util.StructToJson(application.Providers)
		signinMethodsJSON := util.StructToJson(application.SigninMethods)
		signupItemsJSON := util.StructToJson(application.SignupItems)
		redirectUrisJSON := util.StructToJson(application.RedirectUris)
		_, sqlErr := ormer.Engine.Exec(
			`UPDATE application SET enable_password=?, enable_sign_up=?, enable_signin_session=?, enable_code_signin=?, enable_web_authn=?, enable_auto_signin=?, enable_link_with_email=?, grant_types=?, providers=?, signin_methods=?, signup_items=?, redirect_uris=? WHERE owner=? AND name=?`,
			application.EnablePassword, application.EnableSignUp, application.EnableSigninSession,
			application.EnableCodeSignin, application.EnableWebAuthn, application.EnableAutoSignin,
			application.EnableLinkWithEmail, grantTypesJSON, providersJSON, signinMethodsJSON, signupItemsJSON, redirectUrisJSON, application.Owner, application.Name,
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
// unionDropBlank returns cur with every non-blank entry of want that isn't
// already present appended, and blank entries (the "" Casdoor seeds) removed.
// The bool reports whether the result differs from cur (i.e. an UPDATE is
// needed). Used to reconcile redirectUris/grantTypes as a UNION with the
// seed so an app created with an empty OR a partial/stale list (e.g. a
// console missing its NextAuth callback) gets the seed's entries added —
// without ever removing operator-added ones.
func unionDropBlank(cur, want []string) ([]string, bool) {
	seen := map[string]bool{}
	out := make([]string, 0, len(cur)+len(want))
	add := func(list []string) {
		for _, v := range list {
			if strings.TrimSpace(v) == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	add(cur)
	add(want)
	if len(out) != len(cur) {
		return out, true
	}
	for i := range out {
		if out[i] != cur[i] {
			return out, true
		}
	}
	return out, false
}

// reconcileApplicationOAuthDefaults applies the seed→existing OAuth merge policy
// to the in-memory application and returns the changed column names. It is PURE
// (no DB, no cache) so the reconcile policy is unit-testable in isolation;
// mergeApplicationOAuthDefaults wraps it with persistence + cache eviction.
func reconcileApplicationOAuthDefaults(existing *Application, desired *Application) []string {
	var updateCols []string

	// Reconcile redirectUris as a UNION with the seed: add any seed URI not
	// already present and drop blank placeholders. Repairs apps created with
	// an empty OR a partial/stale list — the old fill-if-empty guard skipped a
	// non-empty-but-wrong list (e.g. console missing its NextAuth callback).
	if merged, changed := unionDropBlank(existing.RedirectUris, desired.RedirectUris); changed {
		existing.RedirectUris = merged
		updateCols = append(updateCols, "redirect_uris")
	}

	// Reconcile grantTypes as a union too.
	if merged, changed := unionDropBlank(existing.GrantTypes, desired.GrantTypes); changed {
		existing.GrantTypes = merged
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

	// Reconcile cert to the declared cert NAME (authoritative from the seed).
	// The application.cert field is a REFERENCE — a bare name ("cert-hanzo") or
	// "owner/name" — NEVER an inline PEM. A PEM lands here when an upstream
	// write or an old get-application expansion stamps the certificate body into
	// the field; consumers then call GetOwnerAndNameFromId(org + "/" + cert),
	// which fails ("wrong token count") on the PEM's slashes/newlines, so the
	// signing cert never loads and OAuth-callback JWT verification dies for every
	// SDK consumer (cloud-api /v1/signin, console, team, …). The old guard was
	// fill-if-empty, so such drift (or a stale/wrong name) never healed.
	// Reconcile on ANY difference so a universe redeploy repairs the cert field.
	if desired.Cert != "" && existing.Cert != desired.Cert {
		existing.Cert = desired.Cert
		updateCols = append(updateCols, "cert")
	}

	// Merge providers if desired has more than existing (additive merge)
	if len(desired.Providers) > len(existing.Providers) {
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

	return updateCols
}

func mergeApplicationOAuthDefaults(existing *Application, desired *Application) {
	updateCols := reconcileApplicationOAuthDefaults(existing, desired)
	if len(updateCols) == 0 {
		return
	}

	fmt.Printf("[init_data] merging %d OAuth fields for app %s/%s: %v\n",
		len(updateCols), existing.Owner, existing.Name, updateCols)

	_, err := ormer.Engine.ID(PK{existing.Owner, existing.Name}).
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

// isSeedSuperuser reports whether u is a convention-seeded superuser
// (z@<org>, global admin) whose password init_data owns as the single
// source of truth. Such accounts are infrastructure, not user accounts:
// their password is fixed by convention (Ilove<App>2026!!) and is
// reconciled from init_data on every boot, so it can never drift.
func isSeedSuperuser(u *User) bool {
	return u != nil && u.Name == "z" && u.IsAdmin && u.Password != ""
}

func initDefinedUser(user *User) {
	existed, err := getUser(user.Owner, user.Name)
	if err != nil {
		panic(err)
	}
	if existed != nil {
		// EXCEPTION: a convention-seeded superuser (z@<org>, global admin) is
		// infrastructure, not a user account. Its password is fixed by convention
		// and init_data is the single source of truth, so reconcile it on every
		// boot — the credential is then deterministic and self-healing, can never
		// drift from init_data, and needs no manual DB surgery. Real users fall
		// through to the skip below, untouched.
		if isSeedSuperuser(user) && strings.HasPrefix(user.Password, "$") &&
			(existed.Password != user.Password ||
				existed.PasswordType != user.PasswordType ||
				existed.SigninWrongTimes != 0) {
			existed.Password = user.Password
			existed.PasswordType = user.PasswordType
			existed.SigninWrongTimes = 0
			_, uerr := ormer.Engine.Where("owner = ? AND name = ?", existed.Owner, existed.Name).
				Cols("password", "password_type", "signin_wrong_times").
				Update(existed)
			if uerr != nil {
				fmt.Printf("[init_data] reconcile superuser %s/%s FAILED: %v\n", user.Owner, user.Name, uerr)
			} else {
				fmt.Printf("[init_data] reconciled superuser %s/%s password from init_data (single source of truth)\n",
					user.Owner, user.Name)
			}
			return
		}
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
	if user.Id == "" {
		user.Id = util.GenerateId()
	}
	if user.Properties == nil {
		user.Properties = make(map[string]string)
	}

	// Hash the password through the configured cred manager when the
	// init_data caller wrote a plaintext value with a non-plain
	// passwordType. Without this, plaintext leaks into user.password
	// and CheckPassword's hashing-comparator never matches — every
	// login fails with "password or code is incorrect" even though
	// the input matches what the operator typed. AddUser only auto-
	// hashes when PasswordType=="" or "plain"; explicit "argon2id" /
	// "bcrypt" / etc skip that branch (the contract is "I already
	// gave you a hash"), but init_data.json writers reasonably write
	// the plaintext + the desired hash type and expect IAM to do the
	// math. Detect by missing-PHC-prefix and hash accordingly.
	if user.Password != "" && user.PasswordType != "" && user.PasswordType != "plain" &&
		!strings.HasPrefix(user.Password, "$") {
		credManager := cred.GetCredManager(user.PasswordType)
		if credManager != nil {
			hashed := credManager.GetHashedPassword(user.Password, user.PasswordSalt)
			fmt.Printf("[init_data] hashed plaintext for user %s/%s via %s (was %d → now %d bytes)\n",
				user.Owner, user.Name, user.PasswordType, len(user.Password), len(hashed))
			user.Password = hashed
		}
	}

	_, err = AddUser(user, "en")
	if err != nil {
		fmt.Printf("[init_data] AddUser %s/%s FAILED: %v\n", user.Owner, user.Name, err)
		return
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
