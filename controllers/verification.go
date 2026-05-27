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

package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/captcha"
	"github.com/hanzoai/iam/form"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

const (
	SignupVerification   = "signup"
	ResetVerification    = "reset"
	LoginVerification    = "login"
	ForgetVerification   = "forget"
	MfaSetupVerification = "mfaSetup"
	MfaAuthVerification  = "mfaAuth"
)

// GetVerifications
// @Title GetVerifications
// @Tag Verification API
// @Description get payments
// @Param   owner     query    string  true        "The owner of payments"
// @Success 200 {array} object.Verification The Response object
// @router /get-payments [get]
func (c *ApiController) GetVerifications() {
	organization, ok := c.RequireAdmin()
	if !ok {
		return
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	owner := c.Ctx.Input.Query("owner")
	// For global admin with organizationName parameter, use it to filter
	// For org admin, use their organization
	if c.IsGlobalAdmin() && owner != "" {
		organization = owner
	}

	if limit == "" || page == "" {
		payments, err := object.GetVerifications(organization)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(payments)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetVerificationCount(organization, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		payments, err := object.GetPaginationVerifications(organization, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(payments, paginator.Nums())
	}
}

// GetUserVerifications
// @Title GetUserVerifications
// @Tag Verification API
// @Description get payments for a user
// @Param   owner     query    string  true        "The owner of payments"
// @Param   organization    query   string  true   "The organization of the user"
// @Param   user    query   string  true           "The username of the user"
// @Success 200 {array} object.Verification The Response object
// @router /get-user-payments [get]
func (c *ApiController) GetUserVerifications() {
	owner := c.Ctx.Input.Query("owner")
	user := c.Ctx.Input.Query("user")

	payments, err := object.GetUserVerifications(owner, user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(payments)
}

// GetVerification
// @Title GetVerification
// @Tag Verification API
// @Description get payment
// @Param   id     query    string  true        "The id ( owner/name ) of the payment"
// @Success 200 {object} object.Verification The Response object
// @router /get-payment [get]
func (c *ApiController) GetVerification() {
	id := c.Ctx.Input.Query("id")

	payment, err := object.GetVerification(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(payment)
}

// SendVerificationCode ...
// @Title SendVerificationCode
// @Tag Verification API
// @router /send-verification-code [post]
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) SendVerificationCode() {
	var vform form.VerificationForm
	err := c.ParseForm(&vform)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)

	if msg := vform.CheckParameter(form.SendVerifyCode, c.GetAcceptLanguage()); msg != "" {
		c.ResponseError(msg)
		return
	}

	application, err := object.GetApplication(vform.ApplicationId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), vform.ApplicationId))
		return
	}

	// Check if "Forgot password?" signin item is visible when using forget verification
	if vform.Method == ForgetVerification {
		isForgotPasswordEnabled := false
		for _, item := range application.SigninItems {
			if item.Name == "Forgot password?" {
				isForgotPasswordEnabled = item.Visible
				break
			}
		}
		// Block access if the signin item is not found or is explicitly hidden
		if !isForgotPasswordEnabled {
			c.ResponseError(c.T("verification:The forgot password feature is disabled"))
			return
		}
	}

	organization, err := object.GetOrganization(util.GetId(application.Owner, application.Organization))
	if err != nil {
		c.ResponseError(c.T(err.Error()))
	}

	if organization == nil {
		c.ResponseError(c.T("check:Organization does not exist"))
		return
	}

	var user *object.User
	// Try to resolve user for CAPTCHA rule checking
	// checkUser != "", means method is ForgetVerification
	if vform.CheckUser != "" {
		owner := application.Organization
		user, err = object.GetUser(util.GetId(owner, vform.CheckUser))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if user == nil || user.IsDeleted {
			c.ResponseError(c.T("verification:the user does not exist, please sign up first"))
			return
		}

		if user.IsForbidden {
			c.ResponseError(c.T("check:The user is forbidden to sign in, please contact the administrator"))
			return
		}
	} else if mfaUserSession := c.getMfaUserSession(); mfaUserSession != "" {
		// mfaUserSession != "", means method is MfaAuthVerification
		user, err = object.GetUser(mfaUserSession)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	} else if vform.Method == ResetVerification {
		// For reset verification, get the current logged-in user
		user = c.getCurrentUser()
	} else if vform.Method == LoginVerification {
		// For login verification, try to find user by email/phone for CAPTCHA check
		// This is a preliminary lookup; the actual validation happens later in the switch statement
		if vform.Type == object.VerifyTypeEmail && util.IsEmailValid(vform.Dest) {
			user, err = object.GetUserByEmail(organization.Name, vform.Dest)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		} else if vform.Type == object.VerifyTypePhone {
			// Prefer resolving the user directly by phone, consistent with the later login switch,
			// so that Dynamic CAPTCHA is not skipped due to missing/invalid country code.
			user, err = object.GetUserByPhone(organization.Name, vform.Dest)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}
	}

	// Determine username for CAPTCHA check
	username := ""
	if user != nil {
		username = user.Name
	} else if vform.CheckUser != "" {
		username = vform.CheckUser
	}

	// Check if CAPTCHA should be enabled based on the rule (Dynamic/Always/Internet-Only)
	enableCaptcha, err := object.CheckToEnableCaptcha(application, organization.Name, username, clientIp)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Only verify CAPTCHA if it should be enabled
	if enableCaptcha {
		captchaProvider, err := object.GetCaptchaProviderByApplication(vform.ApplicationId, "false", c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if captchaProvider != nil {
			if vform.CaptchaType != captchaProvider.Type {
				c.ResponseError(c.T("verification:Turing test failed."))
				return
			}

			if captchaProvider.Type != "Default" {
				vform.ClientSecret = captchaProvider.ClientSecret
			}

			if vform.CaptchaType != "none" {
				if captchaService := captcha.GetCaptchaProvider(vform.CaptchaType); captchaService == nil {
					c.ResponseError(c.T("general:don't support captchaProvider: ") + vform.CaptchaType)
					return
				} else if isHuman, err := captchaService.VerifyCaptcha(vform.CaptchaToken, captchaProvider.ClientId, vform.ClientSecret, captchaProvider.ClientId2); err != nil {
					c.ResponseError(err.Error())
					return
				} else if !isHuman {
					c.ResponseError(c.T("verification:Turing test failed."))
					return
				}
			}
		}
	}

	sendResp := errors.New("invalid dest type")
	var provider *object.Provider

	switch vform.Type {
	case object.VerifyTypeEmail:
		if !util.IsEmailValid(vform.Dest) {
			c.ResponseError(c.T("check:Email is invalid"))
			return
		}

		if vform.Method == LoginVerification || vform.Method == ForgetVerification {
			if user != nil && util.GetMaskedEmail(user.Email) == vform.Dest {
				vform.Dest = user.Email
			}

			user, err = object.GetUserByEmail(organization.Name, vform.Dest)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if user == nil {
				if vform.Method == LoginVerification && application.EnableSignUp {
					user, err = autoCreateUserForVerification(application, organization, vform.Dest, "", "", c.GetAcceptLanguage())
					if err != nil {
						c.ResponseError(err.Error())
						return
					}
				} else {
					c.ResponseError(c.T("verification:the user does not exist, please sign up first"))
					return
				}
			}
		} else if vform.Method == ResetVerification {
			user = c.getCurrentUser()
		} else if vform.Method == MfaAuthVerification {
			mfaProps := user.GetMfaProps(object.EmailType, false)
			if user != nil && util.GetMaskedEmail(mfaProps.Secret) == vform.Dest {
				vform.Dest = mfaProps.Secret
			}
		}

		// Env-driven SendGrid override: when IAM_EMAIL_PROVIDER=sendgrid
		// is set (creds validated at boot), the DB-lookup short-circuit
		// on a missing per-application Provider row is bypassed.
		if envEmail := object.EnvEmailProvider(); envEmail != nil {
			provider = envEmail
		} else {
			provider, err = application.GetEmailProvider(vform.Method)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			if provider == nil {
				c.ResponseError(fmt.Sprintf(c.T("verification:please add an Email provider to the \"Providers\" list for the application: %s"), application.Name))
				return
			}
		}

		sendResp = object.SendVerificationCodeToEmail(organization, user, provider, clientIp, vform.Dest, vform.Method, c.getEffectiveHost(), application.Name, application)
	case object.VerifyTypePhone:
		if vform.Method == LoginVerification || vform.Method == ForgetVerification {
			if user != nil && util.GetMaskedPhone(user.Phone) == vform.Dest {
				vform.Dest = user.Phone
			}

			if user, err = object.GetUserByPhone(organization.Name, vform.Dest); err != nil {
				c.ResponseError(err.Error())
				return
			} else if user == nil {
				if vform.Method == LoginVerification && application.EnableSignUp {
					user, err = autoCreateUserForVerification(application, organization, "", vform.Dest, vform.CountryCode, c.GetAcceptLanguage())
					if err != nil {
						c.ResponseError(err.Error())
						return
					}
				} else {
					c.ResponseError(c.T("verification:the user does not exist, please sign up first"))
					return
				}
			}

			vform.CountryCode = user.GetCountryCode(vform.CountryCode)
		} else if vform.Method == ResetVerification || vform.Method == MfaSetupVerification {
			if vform.CountryCode == "" {
				if user = c.getCurrentUser(); user != nil {
					vform.CountryCode = user.GetCountryCode(vform.CountryCode)
				}
			}
		} else if vform.Method == MfaAuthVerification {
			mfaProps := user.GetMfaProps(object.SmsType, false)
			if user != nil && util.GetMaskedPhone(mfaProps.Secret) == vform.Dest {
				vform.Dest = mfaProps.Secret
			}

			vform.CountryCode = mfaProps.CountryCode
			vform.CountryCode = user.GetCountryCode(vform.CountryCode)
		}

		phone, ok := util.GetE164Number(vform.Dest, vform.CountryCode)
		if !ok {
			c.ResponseError(fmt.Sprintf(c.T("verification:Phone number is invalid in your region %s"), vform.CountryCode))
			return
		}

		// Look up user by phone if not already resolved (signup flow).
		if user == nil && phone != "" {
			if u, _ := object.GetUserByPhone(organization.Name, phone); u != nil {
				user = u
			}
		}

		// Per-user pinned OTP: skip SMS provider entirely.
		hasPinnedCode := user != nil && user.VerificationCode != ""
		// Env-driven Twilio override: when IAM_SMS_PROVIDER=twilio is set
		// (creds validated at boot), the DB-lookup short-circuit on a
		// missing per-application Provider row is bypassed. SendSms picks
		// up the env-built provider regardless of what's passed in here.
		envSMS := object.EnvSMSProvider()
		switch {
		case hasPinnedCode:
			sendResp = object.SendVerificationCodeToPhone(organization, user, nil, clientIp, phone, application)
		case envSMS != nil:
			sendResp = object.SendVerificationCodeToPhone(organization, user, envSMS, clientIp, phone, application)
		default:
			provider, err = application.GetSmsProvider(vform.Method, vform.CountryCode)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			if provider == nil {
				c.ResponseError(fmt.Sprintf(c.T("verification:please add a SMS provider to the \"Providers\" list for the application: %s"), application.Name))
				return
			}
			sendResp = object.SendVerificationCodeToPhone(organization, user, provider, clientIp, phone, application)
		}
	}

	if sendResp != nil {
		c.ResponseError(sendResp.Error())
	} else {
		c.ResponseOk()
	}
}

// VerifyCaptcha ...
// @Title VerifyCaptcha
// @Tag Verification API
// @router /verify-captcha [post]
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) VerifyCaptcha() {
	var vform form.VerificationForm
	err := c.ParseForm(&vform)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if msg := vform.CheckParameter(form.VerifyCaptcha, c.GetAcceptLanguage()); msg != "" {
		c.ResponseError(msg)
		return
	}

	captchaProvider, err := object.GetCaptchaProviderByOwnerName(vform.ApplicationId, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if captchaProvider.Type != "Default" {
		vform.ClientSecret = captchaProvider.ClientSecret
	}

	provider := captcha.GetCaptchaProvider(vform.CaptchaType)
	if provider == nil {
		c.ResponseError(c.T("verification:Invalid captcha provider."))
		return
	}

	isValid, err := provider.VerifyCaptcha(vform.CaptchaToken, captchaProvider.ClientId, vform.ClientSecret, captchaProvider.ClientId2)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(isValid)
}

// ResetEmailOrPhone ...
// @Tag Account API
// @Title ResetEmailOrPhone
// @router /reset-email-or-phone [post]
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) ResetEmailOrPhone() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	destType := c.Ctx.Request.Form.Get("type")
	dest := c.Ctx.Request.Form.Get("dest")
	code := c.Ctx.Request.Form.Get("code")

	if util.IsStringsEmpty(destType, dest, code) {
		c.ResponseError(c.T("general:Missing parameter"))
		return
	}

	checkDest := dest
	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(c.T(err.Error()))
		return
	}

	if destType == object.VerifyTypePhone {
		if object.HasUserByField(user.Owner, "phone", dest) {
			c.ResponseError(c.T("check:Phone already exists"))
			return
		}

		phoneItem := object.GetAccountItemByName("Phone", organization)
		if phoneItem == nil {
			c.ResponseError(c.T("verification:Unable to get the phone modify rule."))
			return
		}

		if pass, errMsg := object.CheckAccountItemModifyRule(phoneItem, user.IsAdminUser(), c.GetAcceptLanguage()); !pass {
			c.ResponseError(errMsg)
			return
		}
		if checkDest, ok = util.GetE164Number(dest, user.GetCountryCode("")); !ok {
			c.ResponseError(fmt.Sprintf(c.T("verification:Phone number is invalid in your region %s"), user.CountryCode))
			return
		}
	} else if destType == object.VerifyTypeEmail {
		if object.HasUserByField(user.Owner, "email", dest) {
			c.ResponseError(c.T("check:Email already exists"))
			return
		}

		emailItem := object.GetAccountItemByName("Email", organization)
		if emailItem == nil {
			c.ResponseError(c.T("verification:Unable to get the email modify rule."))
			return
		}

		if pass, errMsg := object.CheckAccountItemModifyRule(emailItem, user.IsAdminUser(), c.GetAcceptLanguage()); !pass {
			c.ResponseError(errMsg)
			return
		}
	}

	result, err := object.CheckVerificationCode(checkDest, code, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(c.T(err.Error()))
		return
	}
	if result.Code != object.VerificationSuccess {
		c.ResponseError(result.Msg)
		return
	}

	switch destType {
	case object.VerifyTypeEmail:
		id := user.GetId()
		user.Email = dest
		user.EmailVerified = true
		columns := []string{"email", "email_verified"}
		if organization.UseEmailAsUsername {
			user.Name = user.Email
			columns = append(columns, "name")
		}
		_, err = object.UpdateUser(id, user, columns, false)
	case object.VerifyTypePhone:
		user.Phone = dest
		_, err = object.SetUserField(user, "phone", user.Phone)
	default:
		c.ResponseError(c.T("verification:Unknown type"))
		return
	}
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if organization.UseEmailAsUsername {
		c.SetSessionUsername(user.GetId())
	}

	err = object.DisableVerificationCode(checkDest)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}

// VerifyCode
// @Tag Verification API
// @Title VerifyCode
// @router /verify-code [post]
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) VerifyCode() {
	var authForm form.AuthForm
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &authForm)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	var user *object.User
	if authForm.Name != "" {
		user, err = object.GetUserByFields(authForm.Organization, authForm.Name)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	var checkDest string
	if strings.Contains(authForm.Username, "@") {
		if user != nil && util.GetMaskedEmail(user.Email) == authForm.Username {
			authForm.Username = user.Email
		}
		checkDest = authForm.Username
	} else {
		if user != nil && util.GetMaskedPhone(user.Phone) == authForm.Username {
			authForm.Username = user.Phone
		}
	}

	if user, err = object.GetUserByFields(authForm.Organization, authForm.Username); err != nil {
		c.ResponseError(err.Error())
		return
	} else if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(authForm.Organization, authForm.Username)))
		return
	}

	verificationCodeType := object.GetVerifyType(authForm.Username)
	if verificationCodeType == object.VerifyTypePhone {
		authForm.CountryCode = user.GetCountryCode(authForm.CountryCode)
		var ok bool
		if checkDest, ok = util.GetE164Number(authForm.Username, authForm.CountryCode); !ok {
			c.ResponseError(fmt.Sprintf(c.T("verification:Phone number is invalid in your region %s"), authForm.CountryCode))
			return
		}
	}

	passed, err := c.checkOrgMasterVerificationCode(user, authForm.Code)
	if err != nil {
		c.ResponseError(c.T(err.Error()))
		return
	}

	if !passed {
		err = object.CheckVerifyCodeWithLimit(user, checkDest, authForm.Code, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		err = object.DisableVerificationCode(checkDest)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	c.SetSession("verifiedCode", authForm.Code)
	c.SetSession("verifiedUserId", user.GetId())
	c.ResponseOk()
}

// autoCreateUserForVerification creates a minimal user record so a Send Code
// request for an unknown phone/email can proceed when the application allows
// signup. Caller must already have checked application.EnableSignUp.
// Exactly one of email or phone must be non-empty.
func autoCreateUserForVerification(application *object.Application, organization *object.Organization, email, phone, countryCode, lang string) (*object.User, error) {
	id, err := object.GenerateIdForNewUser(application)
	if err != nil {
		return nil, err
	}

	// Identity rules per ops:
	//   email — MUST be unique (one account per email forever)
	//   phone — MAY be reused across multiple accounts (family sharing,
	//           reassigned numbers, sandbox demos with the same dev phone)
	//
	// Username derivation reflects this:
	//   email path → name = local-part of email (no suffix). AddUser
	//                relies on UNIQUE(owner,name) to reject duplicates;
	//                the second signup with the same email fails fast
	//                with a clear "already registered" error and the
	//                caller should sign in instead.
	//   phone path → name = "user_<last10digits>_<8-char-random>".
	//                The random suffix lets multiple users share one
	//                phone without colliding on the username PK.
	//                Phone lookup (GetUserByPhone) still finds the
	//                most-recent owner for OTP-only sign-in.
	var name string
	switch {
	case phone != "":
		// Canonicalize before deriving the username suffix so two
		// callers passing the same number in different shapes (raw
		// national vs. E.164) generate username prefixes from the
		// same digit string. AddUser will normalize again — that's
		// fine, the second normalization is idempotent.
		e164, normErr := util.NormalizeE164(phone, countryCode)
		if normErr != nil {
			return nil, fmt.Errorf("autoCreateUserForVerification: %w", normErr)
		}
		phone = e164
		stored := strings.TrimPrefix(e164, "+")
		var prefix string
		if n := len(stored); n > 10 {
			prefix = "user_" + stored[n-10:]
		} else {
			prefix = "user_" + stored
		}
		name = prefix + "_" + util.GenerateId()[:8]
	case email != "":
		name = strings.SplitN(strings.ToLower(email), "@", 2)[0]
	default:
		return nil, errors.New("autoCreateUserForVerification requires email or phone")
	}

	user := &object.User{
		Owner:             organization.Name,
		Name:              name,
		CreatedTime:       util.GetCurrentTime(),
		Id:                id,
		Type:              "normal-user",
		DisplayName:       name,
		Avatar:            organization.DefaultAvatar,
		Email:             strings.ToLower(email),
		Phone:             phone,
		CountryCode:       countryCode,
		Address:           []string{},
		SignupApplication: application.Name,
		Properties:        map[string]string{},
		EmailVerified:     false,
		RegisterType:      "Code Sign-in Auto-Signup",
		RegisterSource:    fmt.Sprintf("%s/%s", organization.Name, application.Name),
	}

	if application.DefaultGroup != "" {
		user.Groups = []string{application.DefaultGroup}
	}

	affected, err := object.AddUser(user, lang)
	if err != nil {
		return nil, err
	}
	if !affected {
		return nil, errors.New("failed to auto-create user for verification")
	}

	// Re-load to pick up server-side fields written by AddUser.
	created, err := object.GetUser(user.GetId())
	if err != nil {
		return nil, err
	}
	if created == nil {
		return user, nil
	}
	return created, nil
}
