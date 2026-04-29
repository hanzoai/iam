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

// Package routers
// @APIVersion 1.503.0
// @Title IAM RESTful API
// @Description Swagger Docs of IAM Backend API
// @Contact support@hanzo.ai
// @SecurityDefinition AccessToken apiKey Authorization header
// @Schemes https,http
// @ExternalDocs Find out more about IAM
// @ExternalDocsUrl https://github.com/hanzoai/iam
package routers

import (
	"github.com/beego/beego/v2/server/web"
	"github.com/hanzoai/iam/controllers"
	"github.com/hanzoai/iam/mcpself"
)

func InitAPI() {
	ns := web.NewNamespace("/",
		web.NSNamespace("/v1/iam",
			web.NSInclude(
				&controllers.ApiController{},
			),
		),
		web.NSNamespace("",
			web.NSInclude(
				&controllers.RootController{},
			),
		),
	)
	web.AddNamespace(ns)

	web.Router("/v1/iam/signup", &controllers.ApiController{}, "POST:Signup")
	web.Router("/v1/iam/get-phone-user", &controllers.ApiController{}, "POST:GetPhoneUser")
	web.Router("/v1/iam/login", &controllers.ApiController{}, "POST:Login")
	web.Router("/v1/iam/get-app-login", &controllers.ApiController{}, "GET:GetApplicationLogin")
	web.Router("/v1/iam/get-dashboard", &controllers.ApiController{}, "GET:GetDashboard")
	web.Router("/v1/iam/logout", &controllers.ApiController{}, "GET,POST:Logout")
	web.Router("/v1/iam/sso-logout", &controllers.ApiController{}, "GET,POST:SsoLogout")
	web.Router("/v1/iam/get-account", &controllers.ApiController{}, "GET:GetAccount")
	web.Router("/v1/iam/userinfo", &controllers.ApiController{}, "GET:GetUserinfo")
	web.Router("/v1/iam/user", &controllers.ApiController{}, "GET:GetUserinfo2")
	web.Router("/v1/iam/unlink", &controllers.ApiController{}, "POST:Unlink")
	web.Router("/v1/iam/get-saml-login", &controllers.ApiController{}, "GET:GetSamlLogin")
	web.Router("/v1/iam/acs", &controllers.ApiController{}, "POST:HandleSamlLogin")
	web.Router("/v1/iam/saml/metadata", &controllers.ApiController{}, "GET:GetSamlMeta")
	web.Router("/v1/iam/saml/redirect/:owner/:application", &controllers.ApiController{}, "*:HandleSamlRedirect")
	web.Router("/v1/iam/webhook", &controllers.ApiController{}, "*:HandleOfficialAccountEvent")
	web.Router("/v1/iam/get-qrcode", &controllers.ApiController{}, "GET:GetQRCode")
	web.Router("/v1/iam/get-webhook-event", &controllers.ApiController{}, "GET:GetWebhookEventType")
	web.Router("/v1/iam/get-captcha-status", &controllers.ApiController{}, "GET:GetCaptchaStatus")
	web.Router("/v1/iam/callback", &controllers.ApiController{}, "POST:Callback")
	web.Router("/v1/iam/device-auth", &controllers.ApiController{}, "POST:DeviceAuth")
	web.Router("/v1/iam/kerberos-login", &controllers.ApiController{}, "GET:KerberosLogin")

	web.Router("/v1/iam/get-organizations", &controllers.ApiController{}, "GET:GetOrganizations")
	web.Router("/v1/iam/get-organization", &controllers.ApiController{}, "GET:GetOrganization")
	web.Router("/v1/iam/update-organization", &controllers.ApiController{}, "POST:UpdateOrganization")
	web.Router("/v1/iam/add-organization", &controllers.ApiController{}, "POST:AddOrganization")
	web.Router("/v1/iam/delete-organization", &controllers.ApiController{}, "POST:DeleteOrganization")
	web.Router("/v1/iam/get-default-application", &controllers.ApiController{}, "GET:GetDefaultApplication")
	web.Router("/v1/iam/get-organization-names", &controllers.ApiController{}, "GET:GetOrganizationNames")

	web.Router("/v1/iam/get-projects", &controllers.ApiController{}, "GET:GetProjects")
	web.Router("/v1/iam/get-project", &controllers.ApiController{}, "GET:GetProject")
	web.Router("/v1/iam/get-organization-projects", &controllers.ApiController{}, "GET:GetOrganizationProjects")
	web.Router("/v1/iam/add-project", &controllers.ApiController{}, "POST:AddProject")
	web.Router("/v1/iam/update-project", &controllers.ApiController{}, "POST:UpdateProject")
	web.Router("/v1/iam/delete-project", &controllers.ApiController{}, "POST:DeleteProject")

	web.Router("/v1/iam/get-groups", &controllers.ApiController{}, "GET:GetGroups")
	web.Router("/v1/iam/get-group", &controllers.ApiController{}, "GET:GetGroup")
	web.Router("/v1/iam/update-group", &controllers.ApiController{}, "POST:UpdateGroup")
	web.Router("/v1/iam/add-group", &controllers.ApiController{}, "POST:AddGroup")
	web.Router("/v1/iam/delete-group", &controllers.ApiController{}, "POST:DeleteGroup")
	web.Router("/v1/iam/upload-groups", &controllers.ApiController{}, "POST:UploadGroups")

	web.Router("/v1/iam/get-global-users", &controllers.ApiController{}, "GET:GetGlobalUsers")
	web.Router("/v1/iam/get-users", &controllers.ApiController{}, "GET:GetUsers")
	web.Router("/v1/iam/get-sorted-users", &controllers.ApiController{}, "GET:GetSortedUsers")
	web.Router("/v1/iam/get-user-count", &controllers.ApiController{}, "GET:GetUserCount")
	web.Router("/v1/iam/get-user", &controllers.ApiController{}, "GET:GetUser")
	web.Router("/v1/iam/update-user", &controllers.ApiController{}, "POST:UpdateUser")
	web.Router("/v1/iam/add-user", &controllers.ApiController{}, "POST:AddUser")
	web.Router("/v1/iam/delete-user", &controllers.ApiController{}, "POST:DeleteUser")
	web.Router("/v1/iam/upload-users", &controllers.ApiController{}, "POST:UploadUsers")
	web.Router("/v1/iam/remove-user-from-group", &controllers.ApiController{}, "POST:RemoveUserFromGroup")
	web.Router("/v1/iam/verify-identification", &controllers.ApiController{}, "POST:VerifyIdentification")
	web.Router("/v1/iam/impersonate-user", &controllers.ApiController{}, "POST:ImpersonateUser")
	web.Router("/v1/iam/exit-impersonate-user", &controllers.ApiController{}, "POST:ExitImpersonateUser")

	web.Router("/v1/iam/get-invitations", &controllers.ApiController{}, "GET:GetInvitations")
	web.Router("/v1/iam/get-invitation", &controllers.ApiController{}, "GET:GetInvitation")
	web.Router("/v1/iam/get-invitation-info", &controllers.ApiController{}, "GET:GetInvitationCodeInfo")
	web.Router("/v1/iam/update-invitation", &controllers.ApiController{}, "POST:UpdateInvitation")
	web.Router("/v1/iam/add-invitation", &controllers.ApiController{}, "POST:AddInvitation")
	web.Router("/v1/iam/delete-invitation", &controllers.ApiController{}, "POST:DeleteInvitation")
	web.Router("/v1/iam/verify-invitation", &controllers.ApiController{}, "GET:VerifyInvitation")
	web.Router("/v1/iam/send-invitation", &controllers.ApiController{}, "POST:SendInvitation")

	web.Router("/v1/iam/get-applications", &controllers.ApiController{}, "GET:GetApplications")
	web.Router("/v1/iam/get-application", &controllers.ApiController{}, "GET:GetApplication")
	web.Router("/v1/iam/get-user-application", &controllers.ApiController{}, "GET:GetUserApplication")
	web.Router("/v1/iam/get-organization-applications", &controllers.ApiController{}, "GET:GetOrganizationApplications")
	web.Router("/v1/iam/update-application", &controllers.ApiController{}, "POST:UpdateApplication")
	web.Router("/v1/iam/add-application", &controllers.ApiController{}, "POST:AddApplication")
	web.Router("/v1/iam/delete-application", &controllers.ApiController{}, "POST:DeleteApplication")

	// Operator-only bootstrap path. Auth via Authorization: Bootstrap <token>,
	// where the token comes from $IAM_BOOTSTRAP_TOKEN env (set by liquid-operator).
	// Used to wire service-account OAuth apps (KMS, BD signers, etc.) without
	// a human admin in the loop. Disabled (503) when env unset.
	web.Router("/v1/iam/admin/applications/upsert", &controllers.ApiController{}, "POST:BootstrapApplicationUpsert")

	web.Router("/v1/iam/get-providers", &controllers.ApiController{}, "GET:GetProviders")
	web.Router("/v1/iam/get-provider", &controllers.ApiController{}, "GET:GetProvider")
	web.Router("/v1/iam/get-global-providers", &controllers.ApiController{}, "GET:GetGlobalProviders")
	web.Router("/v1/iam/update-provider", &controllers.ApiController{}, "POST:UpdateProvider")
	web.Router("/v1/iam/add-provider", &controllers.ApiController{}, "POST:AddProvider")
	web.Router("/v1/iam/delete-provider", &controllers.ApiController{}, "POST:DeleteProvider")

	web.Router("/v1/iam/get-resources", &controllers.ApiController{}, "GET:GetResources")
	web.Router("/v1/iam/get-resource", &controllers.ApiController{}, "GET:GetResource")
	web.Router("/v1/iam/update-resource", &controllers.ApiController{}, "POST:UpdateResource")
	web.Router("/v1/iam/add-resource", &controllers.ApiController{}, "POST:AddResource")
	web.Router("/v1/iam/delete-resource", &controllers.ApiController{}, "POST:DeleteResource")
	web.Router("/v1/iam/upload-resource", &controllers.ApiController{}, "POST:UploadResource")

	web.Router("/v1/iam/get-global-sites", &controllers.ApiController{}, "GET:GetGlobalSites")
	web.Router("/v1/iam/get-sites", &controllers.ApiController{}, "GET:GetSites")
	web.Router("/v1/iam/get-site", &controllers.ApiController{}, "GET:GetSite")
	web.Router("/v1/iam/update-site", &controllers.ApiController{}, "POST:UpdateSite")
	web.Router("/v1/iam/add-site", &controllers.ApiController{}, "POST:AddSite")
	web.Router("/v1/iam/delete-site", &controllers.ApiController{}, "POST:DeleteSite")

	web.Router("/v1/iam/get-servers", &controllers.ApiController{}, "GET:GetServers")
	web.Router("/v1/iam/get-server", &controllers.ApiController{}, "GET:GetServer")
	web.Router("/v1/iam/update-server", &controllers.ApiController{}, "POST:UpdateServer")
	web.Router("/v1/iam/add-server", &controllers.ApiController{}, "POST:AddServer")
	web.Router("/v1/iam/delete-server", &controllers.ApiController{}, "POST:DeleteServer")
	web.Router("/v1/iam/server/:owner/:name", &controllers.ApiController{}, "POST:ProxyServer")

	web.Router("/v1/iam/get-rules", &controllers.ApiController{}, "GET:GetRules")
	web.Router("/v1/iam/get-rule", &controllers.ApiController{}, "GET:GetRule")
	web.Router("/v1/iam/add-rule", &controllers.ApiController{}, "POST:AddRule")
	web.Router("/v1/iam/update-rule", &controllers.ApiController{}, "POST:UpdateRule")
	web.Router("/v1/iam/delete-rule", &controllers.ApiController{}, "POST:DeleteRule")

	web.Router("/v1/iam/get-certs", &controllers.ApiController{}, "GET:GetCerts")
	web.Router("/v1/iam/get-global-certs", &controllers.ApiController{}, "GET:GetGlobalCerts")
	web.Router("/v1/iam/get-cert", &controllers.ApiController{}, "GET:GetCert")
	web.Router("/v1/iam/update-cert", &controllers.ApiController{}, "POST:UpdateCert")
	web.Router("/v1/iam/add-cert", &controllers.ApiController{}, "POST:AddCert")
	web.Router("/v1/iam/delete-cert", &controllers.ApiController{}, "POST:DeleteCert")
	web.Router("/v1/iam/update-cert-domain-expire", &controllers.ApiController{}, "POST:UpdateCertDomainExpire")

	web.Router("/v1/iam/get-keys", &controllers.ApiController{}, "GET:GetKeys")
	web.Router("/v1/iam/get-global-keys", &controllers.ApiController{}, "GET:GetGlobalKeys")
	web.Router("/v1/iam/get-key", &controllers.ApiController{}, "GET:GetKey")
	web.Router("/v1/iam/update-key", &controllers.ApiController{}, "POST:UpdateKey")
	web.Router("/v1/iam/add-key", &controllers.ApiController{}, "POST:AddKey")
	web.Router("/v1/iam/delete-key", &controllers.ApiController{}, "POST:DeleteKey")

	web.Router("/v1/iam/get-roles", &controllers.ApiController{}, "GET:GetRoles")
	web.Router("/v1/iam/get-role", &controllers.ApiController{}, "GET:GetRole")
	web.Router("/v1/iam/update-role", &controllers.ApiController{}, "POST:UpdateRole")
	web.Router("/v1/iam/add-role", &controllers.ApiController{}, "POST:AddRole")
	web.Router("/v1/iam/delete-role", &controllers.ApiController{}, "POST:DeleteRole")
	web.Router("/v1/iam/upload-roles", &controllers.ApiController{}, "POST:UploadRoles")

	web.Router("/v1/iam/get-permissions", &controllers.ApiController{}, "GET:GetPermissions")
	web.Router("/v1/iam/get-permissions-by-submitter", &controllers.ApiController{}, "GET:GetPermissionsBySubmitter")
	web.Router("/v1/iam/get-permissions-by-role", &controllers.ApiController{}, "GET:GetPermissionsByRole")
	web.Router("/v1/iam/get-permission", &controllers.ApiController{}, "GET:GetPermission")
	web.Router("/v1/iam/update-permission", &controllers.ApiController{}, "POST:UpdatePermission")
	web.Router("/v1/iam/add-permission", &controllers.ApiController{}, "POST:AddPermission")
	web.Router("/v1/iam/delete-permission", &controllers.ApiController{}, "POST:DeletePermission")
	web.Router("/v1/iam/upload-permissions", &controllers.ApiController{}, "POST:UploadPermissions")

	web.Router("/v1/iam/get-models", &controllers.ApiController{}, "GET:GetModels")
	web.Router("/v1/iam/get-model", &controllers.ApiController{}, "GET:GetModel")
	web.Router("/v1/iam/update-model", &controllers.ApiController{}, "POST:UpdateModel")
	web.Router("/v1/iam/add-model", &controllers.ApiController{}, "POST:AddModel")
	web.Router("/v1/iam/delete-model", &controllers.ApiController{}, "POST:DeleteModel")

	web.Router("/v1/iam/get-adapters", &controllers.ApiController{}, "GET:GetAdapters")
	web.Router("/v1/iam/get-adapter", &controllers.ApiController{}, "GET:GetAdapter")
	web.Router("/v1/iam/update-adapter", &controllers.ApiController{}, "POST:UpdateAdapter")
	web.Router("/v1/iam/add-adapter", &controllers.ApiController{}, "POST:AddAdapter")
	web.Router("/v1/iam/delete-adapter", &controllers.ApiController{}, "POST:DeleteAdapter")
	web.Router("/v1/iam/get-policies", &controllers.ApiController{}, "GET:GetPolicies")
	web.Router("/v1/iam/get-filtered-policies", &controllers.ApiController{}, "POST:GetFilteredPolicies")
	web.Router("/v1/iam/update-policy", &controllers.ApiController{}, "POST:UpdatePolicy")
	web.Router("/v1/iam/add-policy", &controllers.ApiController{}, "POST:AddPolicy")
	web.Router("/v1/iam/remove-policy", &controllers.ApiController{}, "POST:RemovePolicy")

	web.Router("/v1/iam/get-enforcers", &controllers.ApiController{}, "GET:GetEnforcers")
	web.Router("/v1/iam/get-enforcer", &controllers.ApiController{}, "GET:GetEnforcer")
	web.Router("/v1/iam/update-enforcer", &controllers.ApiController{}, "POST:UpdateEnforcer")
	web.Router("/v1/iam/add-enforcer", &controllers.ApiController{}, "POST:AddEnforcer")
	web.Router("/v1/iam/delete-enforcer", &controllers.ApiController{}, "POST:DeleteEnforcer")

	web.Router("/v1/iam/enforce", &controllers.ApiController{}, "POST:Enforce")
	web.Router("/v1/iam/batch-enforce", &controllers.ApiController{}, "POST:BatchEnforce")
	web.Router("/v1/iam/get-all-objects", &controllers.ApiController{}, "GET:GetAllObjects")
	web.Router("/v1/iam/get-all-actions", &controllers.ApiController{}, "GET:GetAllActions")
	web.Router("/v1/iam/get-all-roles", &controllers.ApiController{}, "GET:GetAllRoles")

	web.Router("/v1/iam/run-authz-command", &controllers.ApiController{}, "GET:RunAuthzCommand")
	web.Router("/v1/iam/refresh-engines", &controllers.ApiController{}, "POST:RefreshEngines")

	web.Router("/v1/iam/get-sessions", &controllers.ApiController{}, "GET:GetSessions")
	web.Router("/v1/iam/get-session", &controllers.ApiController{}, "GET:GetSingleSession")
	web.Router("/v1/iam/update-session", &controllers.ApiController{}, "POST:UpdateSession")
	web.Router("/v1/iam/add-session", &controllers.ApiController{}, "POST:AddSession")
	web.Router("/v1/iam/delete-session", &controllers.ApiController{}, "POST:DeleteSession")
	web.Router("/v1/iam/is-session-duplicated", &controllers.ApiController{}, "GET:IsSessionDuplicated")

	web.Router("/v1/iam/get-tokens", &controllers.ApiController{}, "GET:GetTokens")
	web.Router("/v1/iam/get-token", &controllers.ApiController{}, "GET:GetToken")
	web.Router("/v1/iam/update-token", &controllers.ApiController{}, "POST:UpdateToken")
	web.Router("/v1/iam/add-token", &controllers.ApiController{}, "POST:AddToken")
	web.Router("/v1/iam/delete-token", &controllers.ApiController{}, "POST:DeleteToken")

	// Billing routes removed: products, orders, payments, plans, pricings,
	// subscriptions, transactions, usage records are now handled by Commerce
	// (billing.hanzo.ai). See https://commerce.hanzo.ai/api/v1/billing

	web.Router("/v1/iam/get-system-info", &controllers.ApiController{}, "GET:GetSystemInfo")
	web.Router("/v1/iam/get-version-info", &controllers.ApiController{}, "GET:GetVersionInfo")
	web.Router("/healthz", &controllers.ApiController{}, "GET:Health")
	web.Router("/v1/iam/sync-init-data", &controllers.ApiController{}, "POST:SyncInitData")
	web.Router("/v1/iam/get-prometheus-info", &controllers.ApiController{}, "GET:GetPrometheusInfo")
	web.Router("/v1/iam/metrics", &controllers.ApiController{}, "GET:GetMetrics")

	web.Router("/v1/iam/get-global-forms", &controllers.ApiController{}, "GET:GetGlobalForms")
	web.Router("/v1/iam/get-forms", &controllers.ApiController{}, "GET:GetForms")
	web.Router("/v1/iam/get-form", &controllers.ApiController{}, "GET:GetForm")
	web.Router("/v1/iam/update-form", &controllers.ApiController{}, "POST:UpdateForm")
	web.Router("/v1/iam/add-form", &controllers.ApiController{}, "POST:AddForm")
	web.Router("/v1/iam/delete-form", &controllers.ApiController{}, "POST:DeleteForm")

	web.Router("/v1/iam/get-syncers", &controllers.ApiController{}, "GET:GetSyncers")
	web.Router("/v1/iam/get-syncer", &controllers.ApiController{}, "GET:GetSyncer")
	web.Router("/v1/iam/update-syncer", &controllers.ApiController{}, "POST:UpdateSyncer")
	web.Router("/v1/iam/add-syncer", &controllers.ApiController{}, "POST:AddSyncer")
	web.Router("/v1/iam/delete-syncer", &controllers.ApiController{}, "POST:DeleteSyncer")
	web.Router("/v1/iam/run-syncer", &controllers.ApiController{}, "GET:RunSyncer")
	web.Router("/v1/iam/test-syncer-db", &controllers.ApiController{}, "POST:TestSyncerDb")

	web.Router("/v1/iam/get-webhooks", &controllers.ApiController{}, "GET:GetWebhooks")
	web.Router("/v1/iam/get-webhook", &controllers.ApiController{}, "GET:GetWebhook")
	web.Router("/v1/iam/update-webhook", &controllers.ApiController{}, "POST:UpdateWebhook")
	web.Router("/v1/iam/add-webhook", &controllers.ApiController{}, "POST:AddWebhook")
	web.Router("/v1/iam/delete-webhook", &controllers.ApiController{}, "POST:DeleteWebhook")

	web.Router("/v1/iam/get-tickets", &controllers.ApiController{}, "GET:GetTickets")
	web.Router("/v1/iam/get-ticket", &controllers.ApiController{}, "GET:GetTicket")
	web.Router("/v1/iam/update-ticket", &controllers.ApiController{}, "POST:UpdateTicket")
	web.Router("/v1/iam/add-ticket", &controllers.ApiController{}, "POST:AddTicket")
	web.Router("/v1/iam/delete-ticket", &controllers.ApiController{}, "POST:DeleteTicket")
	web.Router("/v1/iam/add-ticket-message", &controllers.ApiController{}, "POST:AddTicketMessage")

	web.Router("/v1/iam/set-password", &controllers.ApiController{}, "POST:SetPassword")
	web.Router("/v1/iam/check-user-password", &controllers.ApiController{}, "POST:CheckUserPassword")
	web.Router("/v1/iam/get-email-and-phone", &controllers.ApiController{}, "GET:GetEmailAndPhone")
	web.Router("/v1/iam/send-verification-code", &controllers.ApiController{}, "POST:SendVerificationCode")
	web.Router("/v1/iam/verify-code", &controllers.ApiController{}, "POST:VerifyCode")
	web.Router("/v1/iam/verify-captcha", &controllers.ApiController{}, "POST:VerifyCaptcha")
	web.Router("/v1/iam/reset-email-or-phone", &controllers.ApiController{}, "POST:ResetEmailOrPhone")
	web.Router("/v1/iam/get-captcha", &controllers.ApiController{}, "GET:GetCaptcha")
	web.Router("/v1/iam/get-verifications", &controllers.ApiController{}, "GET:GetVerifications")

	web.Router("/v1/iam/get-ldap-users", &controllers.ApiController{}, "GET:GetLdapUsers")
	web.Router("/v1/iam/get-ldaps", &controllers.ApiController{}, "GET:GetLdaps")
	web.Router("/v1/iam/get-ldap", &controllers.ApiController{}, "GET:GetLdap")
	web.Router("/v1/iam/add-ldap", &controllers.ApiController{}, "POST:AddLdap")
	web.Router("/v1/iam/update-ldap", &controllers.ApiController{}, "POST:UpdateLdap")
	web.Router("/v1/iam/delete-ldap", &controllers.ApiController{}, "POST:DeleteLdap")
	web.Router("/v1/iam/sync-ldap-users", &controllers.ApiController{}, "POST:SyncLdapUsers")

	// /login/oauth/* — standard OAuth2 path with no prefix, mandated by the spec.
	web.Router("/login/oauth/authorize", &controllers.ApiController{}, "GET:OAuthAuthorizeRedirect")
	web.Router("/login/oauth/access_token", &controllers.ApiController{}, "POST:GetOAuthToken")
	web.Router("/login/oauth/refresh_token", &controllers.ApiController{}, "POST:RefreshToken")
	web.Router("/login/oauth/introspect", &controllers.ApiController{}, "POST:IntrospectToken")
	web.Router("/login/oauth/revoke", &controllers.ApiController{}, "POST:RevokeToken")

	// /oauth/* — Hanzo OAuth aliases for clean OIDC discovery paths.
	web.Router("/oauth/authorize", &controllers.ApiController{}, "GET:OAuthAuthorizeRedirect")
	web.Router("/oauth/token", &controllers.ApiController{}, "POST:GetOAuthToken")
	web.Router("/oauth/access_token", &controllers.ApiController{}, "POST:GetOAuthToken")
	web.Router("/oauth/refresh", &controllers.ApiController{}, "POST:RefreshToken")
	web.Router("/oauth/introspect", &controllers.ApiController{}, "POST:IntrospectToken")
	web.Router("/oauth/revoke", &controllers.ApiController{}, "POST:RevokeToken")
	web.Router("/oauth/userinfo", &controllers.ApiController{}, "GET:GetUserinfo")
	web.Router("/oauth/device", &controllers.ApiController{}, "POST:DeviceAuth")
	web.Router("/oauth/logout", &controllers.ApiController{}, "GET,POST:Logout")
	web.Router("/oauth/register", &controllers.ApiController{}, "POST:DynamicClientRegister")

	web.Router("/v1/iam/get-records", &controllers.ApiController{}, "GET:GetRecords")
	web.Router("/v1/iam/get-records-filter", &controllers.ApiController{}, "POST:GetRecordsByFilter")
	web.Router("/v1/iam/add-record", &controllers.ApiController{}, "POST:AddRecord")

	web.Router("/v1/iam/send-email", &controllers.ApiController{}, "POST:SendEmail")
	web.Router("/v1/iam/send-sms", &controllers.ApiController{}, "POST:SendSms")
	web.Router("/v1/iam/send-notification", &controllers.ApiController{}, "POST:SendNotification")

	web.Router("/v1/iam/webauthn/signup/begin", &controllers.ApiController{}, "GET:WebAuthnSignupBegin")
	web.Router("/v1/iam/webauthn/signup/finish", &controllers.ApiController{}, "POST:WebAuthnSignupFinish")
	web.Router("/v1/iam/webauthn/signin/begin", &controllers.ApiController{}, "GET:WebAuthnSigninBegin")
	web.Router("/v1/iam/webauthn/signin/finish", &controllers.ApiController{}, "POST:WebAuthnSigninFinish")

	web.Router("/v1/iam/mfa/setup/initiate", &controllers.ApiController{}, "POST:MfaSetupInitiate")
	web.Router("/v1/iam/mfa/setup/verify", &controllers.ApiController{}, "POST:MfaSetupVerify")
	web.Router("/v1/iam/mfa/setup/enable", &controllers.ApiController{}, "POST:MfaSetupEnable")
	web.Router("/v1/iam/delete-mfa", &controllers.ApiController{}, "POST:DeleteMfa")
	web.Router("/v1/iam/set-preferred-mfa", &controllers.ApiController{}, "POST:SetPreferredMfa")

	web.Router("/v1/iam/grant-consent", &controllers.ApiController{}, "POST:GrantConsent")
	web.Router("/v1/iam/revoke-consent", &controllers.ApiController{}, "POST:RevokeConsent")

	web.Router("/.well-known/openid-configuration", &controllers.RootController{}, "GET:GetOidcDiscovery")
	web.Router("/.well-known/:application/openid-configuration", &controllers.RootController{}, "GET:GetOidcDiscoveryByApplication")
	web.Router("/.well-known/oauth-authorization-server", &controllers.RootController{}, "GET:GetOAuthServerMetadata")
	web.Router("/.well-known/:application/oauth-authorization-server", &controllers.RootController{}, "GET:GetOAuthServerMetadataByApplication")
	web.Router("/.well-known/jwks", &controllers.RootController{}, "*:GetJwks")
	web.Router("/.well-known/:application/jwks", &controllers.RootController{}, "*:GetJwksByApplication")
	web.Router("/.well-known/webfinger", &controllers.RootController{}, "GET:GetWebFinger")
	web.Router("/.well-known/:application/webfinger", &controllers.RootController{}, "GET:GetWebFingerByApplication")
	web.Router("/.well-known/oauth-protected-resource", &controllers.RootController{}, "GET:GetOauthProtectedResourceMetadata")
	web.Router("/.well-known/:application/oauth-protected-resource", &controllers.RootController{}, "GET:GetOauthProtectedResourceMetadataByApplication")

	web.Router("/cas/:organization/:application/serviceValidate", &controllers.RootController{}, "GET:CasServiceValidate")
	web.Router("/cas/:organization/:application/proxyValidate", &controllers.RootController{}, "GET:CasProxyValidate")
	web.Router("/cas/:organization/:application/proxy", &controllers.RootController{}, "GET:CasProxy")
	web.Router("/cas/:organization/:application/validate", &controllers.RootController{}, "GET:CasValidate")

	web.Router("/cas/:organization/:application/p3/serviceValidate", &controllers.RootController{}, "GET:CasP3ServiceValidate")
	web.Router("/cas/:organization/:application/p3/proxyValidate", &controllers.RootController{}, "GET:CasP3ProxyValidate")
	web.Router("/cas/:organization/:application/samlValidate", &controllers.RootController{}, "POST:SamlValidate")

	web.Router("/scim/*", &controllers.RootController{}, "*:HandleScim")

	web.Router("/v1/iam/mcp", &mcpself.McpController{}, "POST:HandleMcp")

	web.Router("/v1/iam/faceid-signin-begin", &controllers.ApiController{}, "GET:FaceIDSigninBegin")

	web.Router("/v1/iam/registry/token", &controllers.ApiController{}, "GET:GetRegistryToken")
	web.Router("/v1/iam/registry/jwks", &controllers.ApiController{}, "GET:GetRegistryPublicKey")

	// IDV (Identity Verification) routes
	web.Router("/v1/iam/verify-identity", &controllers.ApiController{}, "POST:VerifyIdentity")
	web.Router("/v1/iam/verify-identity/webhook", &controllers.ApiController{}, "POST:VerifyIdentityWebhook")
	web.Router("/v1/iam/verify-identity/status", &controllers.ApiController{}, "GET:GetVerifyIdentityStatus")
	web.Router("/v1/iam/verify-accreditation", &controllers.ApiController{}, "POST:VerifyAccreditation")
}
