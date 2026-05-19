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

// @ts-nocheck
import React, {useCallback, useEffect, useState} from "react";
import {UserPlus} from "lucide-react";
import {Input} from "../components/ui/input";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "../components/ui/select";
import {Popover, PopoverContent, PopoverTrigger} from "../components/ui/popover";
import {toast} from "sonner";
import * as Setting from "../Setting";
import * as AuthBackend from "./AuthBackend";
import * as ProviderButton from "./ProviderButton";
import i18next from "i18next";
import * as Util from "./Util";
import {authConfig} from "./Auth";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as AgreementModal from "../common/modal/AgreementModal";
import {SendCodeInput} from "../common/SendCodeInput";
import RegionSelect from "../common/select/RegionSelect";
import LanguageSelect from "../common/select/LanguageSelect";
import {withRouter} from "react-router-dom";
import {CountryCodeSelect} from "../common/select/CountryCodeSelect";
import * as PasswordChecker from "../common/PasswordChecker";
import * as InvitationBackend from "../backend/InvitationBackend";

// Field wrapper: label, error, and child input.
function Field({label, required, error, children, className = ""}) {
  return (
    <div className={`mb-3 ${className}`}>
      {label && (
        <label className="block text-sm text-neutral-300 mb-1">
          {label}{required ? <span className="text-red-400 ml-0.5">*</span> : null}
        </label>
      )}
      {children}
      {error && <p className="text-sm text-red-500 mt-1">{error}</p>}
    </div>
  );
}

function SignupPage(props) {
  const [applicationName] = useState((props.applicationName ?? props.match?.params?.applicationName) ?? null);
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [emailOrPhoneMode, setEmailOrPhoneMode] = useState("");
  const [validEmail, setValidEmail] = useState(false);
  const [validPhone, setValidPhone] = useState(false);
  const [region, setRegion] = useState("");
  const [invitationCode, setInvitationCode] = useState(undefined);
  const [invitation, setInvitation] = useState(undefined);
  const [displayNameRule, setDisplayNameRule] = useState(undefined);
  const [passwordPopover, setPasswordPopover] = useState(null);
  const [passwordPopoverOpen, setPasswordPopoverOpen] = useState(false);
  const [msgState, setMsgState] = useState(null);

  const [values, setValues] = useState({});
  const [errors, setErrors] = useState({});

  const setField = (name, value) => {
    setValues((prev) => ({...prev, [name]: value}));
    setErrors((prev) => ({...prev, [name]: ""}));
  };

  const getApplicationObj = useCallback(() => props.application, [props.application]);
  const onUpdateAccount = useCallback((account) => props.onUpdateAccount(account), [props.onUpdateAccount]);
  const onUpdateApplication = useCallback((application) => props.onUpdateApplication(application), [props.onUpdateApplication]);

  const getApplication = useCallback((appName) => {
    if (appName === undefined) {return;}
    ApplicationBackend.getApplication("admin", appName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }
        onUpdateApplication(res.data);
      });
  }, [onUpdateApplication]);

  const getInvitationCodeInfo = useCallback((code, application) => {
    InvitationBackend.getInvitationCodeInfo(code, application)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }
        setInvitation(res.data);
        if (res.data.email) {
          setValidEmail(true);
          setEmail(res.data.email);
        }
        if (res.data.phone) {
          setValidPhone(true);
          setPhone(res.data.phone);
        }
      });
  }, []);

  const setInvitationCodeFromUrl = useCallback((application = null) => {
    const sp = new URLSearchParams(window.location.search);
    if (sp.has("invitationCode")) {
      const code = sp.get("invitationCode");
      setInvitationCode(code);
      if (code !== "") {
        let appName = applicationName;
        if (application) {appName = application.name;}
        getInvitationCodeInfo(code, "admin/" + appName);
      }
    }
  }, [applicationName, getInvitationCodeInfo]);

  const getApplicationLogin = useCallback((oAuthParams) => {
    AuthBackend.getApplicationLogin(oAuthParams)
      .then((res) => {
        if (res.status === "ok") {
          onUpdateApplication(res.data);
          setInvitationCodeFromUrl(res.data);
        } else {
          onUpdateApplication(null);
          setMsgState(res.msg);
        }
      });
  }, [onUpdateApplication, setInvitationCodeFromUrl]);

  useEffect(() => {
    const oAuthParams = Util.getOAuthGetParameters();
    if (oAuthParams !== null) {
      const signinUrl = window.location.pathname.replace("/signup/oauth/authorize", "/login/oauth/authorize");
      sessionStorage.setItem("signinUrl", signinUrl + window.location.search);
    }
    if (getApplicationObj() === undefined) {
      if (applicationName !== null) {
        getApplication(applicationName);
        setInvitationCodeFromUrl();
      } else if (oAuthParams !== null) {
        getApplicationLogin(oAuthParams);
      } else {
        Setting.showMessage("error", `${i18next.t("general:Unknown application name")}: ${applicationName}`);
        onUpdateApplication(null);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Seed values from application + invitation.
  useEffect(() => {
    const app = getApplicationObj();
    if (!app) {return;}
    const init = {
      application: app.name,
      organization: app.organization,
      countryCode: (app.organizationObj?.countryCodes ?? ["US"])?.[0],
    };
    if (invitation !== undefined) {
      if (invitation.username !== "") {init.username = invitation.username;}
      if (invitation.email !== "") {init.email = invitation.email;}
      if (invitation.phone !== "") {init.phone = invitation.phone;}
      if (invitationCode !== "") {init.invitationCode = invitationCode;}
    }
    setValues((prev) => ({...init, ...prev}));
  }, [props.application, invitation, invitationCode]); // eslint-disable-line react-hooks/exhaustive-deps

  const parseOffset = (offset) => {
    if (offset === 2 || offset === 4 || Setting.inIframe() || Setting.isMobile()) {return "0 auto";}
    if (offset === 1) {return "0 10%";}
    if (offset === 3) {return "0 60%";}
  };

  const getResultPath = (application, signupParams) => {
    if (signupParams?.plan && signupParams?.pricing) {
      return `/buy-plan/${application.organization}/${signupParams?.pricing}?user=${signupParams.username}&plan=${signupParams.plan}`;
    }
    if (authConfig.appName === application.name) {return "/result";}
    const oAuthParams = Util.getOAuthGetParameters();
    if (Setting.hasPromptPage(application)) {
      return `/prompt/${application.name}?oauth=${oAuthParams !== null}`;
    }
    return `/result/${application.name}`;
  };

  const validate = (application) => {
    const next = {};
    const get = (k) => values[k];
    (application.signupItems || []).forEach((signupItem) => {
      if (!signupItem.visible) {return;}
      const required = signupItem.required;
      const name = signupItem.name;
      if (name === "Username") {
        if (required && !(get("username") || "").trim()) {next.username = i18next.t("forget:Please input your username!");}
        else if (signupItem.regex && get("username") && !new RegExp(signupItem.regex).test(get("username"))) {next.username = i18next.t("signup:The input doesn't match the signup item regex!");}
      } else if (name === "Display name") {
        if (signupItem.rule === "First, last" && Setting.getLanguage() !== "zh") {
          if (required && !(get("firstName") || "").trim()) {next.firstName = i18next.t("signup:Please input your first name!");}
          if (required && !(get("lastName") || "").trim()) {next.lastName = i18next.t("signup:Please input your last name!");}
        } else if (required && !(get("name") || "").trim()) {
          next.name = (signupItem.rule === "Real name" || signupItem.rule === "First, last") ? i18next.t("signup:Please input your real name!") : i18next.t("signup:Please input your display name!");
        }
      } else if (name === "First name" && displayNameRule !== "First, last") {
        if (required && !(get("firstName") || "").trim()) {next.firstName = i18next.t("signup:Please input your first name!");}
      } else if (name === "Last name" && displayNameRule !== "First, last") {
        if (required && !(get("lastName") || "").trim()) {next.lastName = i18next.t("signup:Please input your last name!");}
      } else if (name === "Affiliation") {
        if (required && !(get("affiliation") || "").trim()) {next.affiliation = i18next.t("signup:Please input your affiliation!");}
      } else if (name === "ID card") {
        const v = get("idCard");
        if (required && !v) {next.idCard = i18next.t("signup:Please input your ID card number!");}
        else if (v && !/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9X]$/.test(v)) {
          next.idCard = i18next.t("signup:Please input the correct ID card number!");
        }
      } else if (name === "Country/Region") {
        if (required && !get("country_region")) {next.country_region = i18next.t("signup:Please select your country/region!");}
      } else if (name === "Email") {
        if (required && !get("email")) {next.email = i18next.t("login:Please input your Email!");}
        else if (get("email") && !Setting.isValidEmail(get("email"))) {next.email = i18next.t("login:The input is not valid Email!");}
        if (signupItem.rule !== "No verification" && required && !get("emailCode")) {next.emailCode = i18next.t("code:Please input your verification code!");}
      } else if (name === "Phone") {
        if (required && !get("phone")) {next.phone = i18next.t("signup:Please input your phone number!");}
        else if (get("phone") && !Setting.isValidPhone(get("phone"), get("countryCode"))) {next.phone = i18next.t("signup:The input is not valid Phone!");}
        if (signupItem.rule !== "No verification" && required && !get("phoneCode")) {next.phoneCode = i18next.t("code:Please input your phone verification code!");}
      } else if (name === "Password") {
        const err = PasswordChecker.checkPasswordComplexity(get("password"), application.organizationObj?.passwordOptions ?? []);
        if (err) {next.password = err;}
      } else if (name === "Confirm password") {
        if (required && !get("confirm")) {next.confirm = i18next.t("signup:Please confirm your password!");}
        else if (get("confirm") && get("confirm") !== get("password")) {next.confirm = i18next.t("signup:Your confirmed password is inconsistent with the password!");}
      } else if (name === "Invitation code") {
        if (required && !get("invitationCode")) {next.invitationCode = i18next.t("signup:Please input your invitation code!");}
      }
    });
    setErrors(next);
    return Object.keys(next).length === 0;
  };

  const onFinish = (application) => {
    const v = {...values};
    if (Array.isArray(v.gender)) {v.gender = v.gender.join(", ");}
    if (Array.isArray(v.bio)) {v.bio = v.bio.join(", ");}
    if (Array.isArray(v.tag)) {v.tag = v.tag.join(", ");}
    if (Array.isArray(v.education)) {v.education = v.education.join(", ");}
    if (invitationCode && !v.invitationCode) {v.invitationCode = invitationCode;}
    const params = new URLSearchParams(window.location.search);
    v.plan = params.get("plan");
    v.pricing = params.get("pricing");
    const oAuthParams = Util.getOAuthGetParameters();
    AuthBackend.signup(v, oAuthParams)
      .then((res) => {
        if (res.status === "ok") {
          if (oAuthParams && res.data && typeof res.data === "string" && !res.data.includes("/")) {
            const code = res.data;
            const redirectUrl = `${oAuthParams.redirectUri}${oAuthParams.redirectUri.includes("?") ? "&" : "?"}code=${code}&state=${oAuthParams.state}`;
            Setting.goToLink(redirectUrl);
            return;
          }
          if (oAuthParams && res.data && typeof res.data === "object" && res.data.required === true) {
            Setting.goToLink(`/consent/${application.name}?${window.location.search.substring(1)}`);
            return;
          }
          if (typeof res.data === "string") {v.username = res.data.split("/")[1];}
          if (Setting.hasPromptPage(application) && (!v.plan || !v.pricing)) {
            AuthBackend.getAccount("")
              .then((res) => {
                if (res.status === "ok") {
                  const account = res.data;
                  account.organization = res.data2;
                  onUpdateAccount(account);
                  Setting.goToLinkSoft({props}, getResultPath(application, v));
                } else {
                  Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
                }
              });
          } else {
            Setting.goToLinkSoft({props}, getResultPath(application, v));
          }
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  };

  const isProviderVisible = (providerItem) => Setting.isProviderVisibleForSignUp(providerItem);

  const renderSignupFormItem = (application, signupItem) => {
    if (!signupItem.visible) {return null;}
    const required = signupItem.required;
    const label = signupItem.label || signupItem.name;

    if (signupItem.name === "Username") {
      return (
        <Field key="username" label={label} required={required} error={errors.username}>
          <Input
            value={values.username ?? ""}
            onChange={(e) => setField("username", e.target.value)}
            placeholder={signupItem.placeholder}
            disabled={invitation !== undefined && invitation.username !== ""}
          />
        </Field>
      );
    } else if (signupItem.name === "Display name") {
      if (signupItem.rule === "First, last" && Setting.getLanguage() !== "zh") {
        return (
          <React.Fragment key="display-name">
            <Field label={i18next.t("general:First name")} required={required} error={errors.firstName}>
              <Input value={values.firstName ?? ""} onChange={(e) => setField("firstName", e.target.value)} placeholder={signupItem.placeholder} />
            </Field>
            <Field label={i18next.t("general:Last name")} required={required} error={errors.lastName}>
              <Input value={values.lastName ?? ""} onChange={(e) => setField("lastName", e.target.value)} placeholder={signupItem.placeholder} />
            </Field>
          </React.Fragment>
        );
      }
      return (
        <Field key="name" label={label} required={required} error={errors.name}>
          <Input value={values.name ?? ""} onChange={(e) => setField("name", e.target.value)} placeholder={signupItem.placeholder} />
        </Field>
      );
    } else if (signupItem.name === "First name" && displayNameRule !== "First, last") {
      return (
        <Field key="firstName" label={label} required={required} error={errors.firstName}>
          <Input value={values.firstName ?? ""} onChange={(e) => setField("firstName", e.target.value)} placeholder={signupItem.placeholder} />
        </Field>
      );
    } else if (signupItem.name === "Last name" && displayNameRule !== "First, last") {
      return (
        <Field key="lastName" label={label} required={required} error={errors.lastName}>
          <Input value={values.lastName ?? ""} onChange={(e) => setField("lastName", e.target.value)} placeholder={signupItem.placeholder} />
        </Field>
      );
    } else if (signupItem.name === "Affiliation") {
      return (
        <Field key="affiliation" label={label} required={required} error={errors.affiliation}>
          <Input value={values.affiliation ?? ""} onChange={(e) => setField("affiliation", e.target.value)} placeholder={signupItem.placeholder} />
        </Field>
      );
    } else if (signupItem.name === "ID card") {
      return (
        <Field key="idCard" label={label} required={required} error={errors.idCard}>
          <Input value={values.idCard ?? ""} onChange={(e) => setField("idCard", e.target.value)} placeholder={signupItem.placeholder} />
        </Field>
      );
    } else if (signupItem.name === "Country/Region") {
      return (
        <Field key="country_region" label={label} required={required} error={errors.country_region}>
          <RegionSelect onChange={(v) => { setRegion(v); setField("country_region", v); }} />
        </Field>
      );
    } else if (["Email", "Phone", "Email or Phone", "Phone or Email"].includes(signupItem.name)) {
      const renderEmailItem = () => (
        <React.Fragment>
          <Field label={i18next.t("general:Email")} required={required} error={errors.email}>
            <Input
              value={values.email ?? ""}
              onChange={(e) => {
                setField("email", e.target.value);
                setEmail(e.target.value);
                setValidEmail(Setting.isValidEmail(e.target.value));
              }}
              placeholder={signupItem.placeholder}
              disabled={invitation !== undefined && invitation.email !== ""}
            />
          </Field>
          {signupItem.rule !== "No verification" && (
            <Field label={i18next.t("code:Email code")} required={required} error={errors.emailCode}>
              <SendCodeInput
                value={values.emailCode ?? ""}
                onChange={(v) => setField("emailCode", v)}
                disabled={!validEmail}
                method={"signup"}
                onButtonClickArgs={[email, "email", Setting.getApplicationName(application)]}
                application={application}
              />
            </Field>
          )}
        </React.Fragment>
      );
      const renderPhoneItem = () => (
        <React.Fragment>
          <Field label={i18next.t("general:Phone")} required={required} error={errors.phone}>
            <div className="flex gap-2">
              <CountryCodeSelect
                initValue={values.countryCode}
                onChange={(v) => setField("countryCode", v)}
                style={{width: "35%"}}
                countryCodes={getApplicationObj().organizationObj?.countryCodes ?? ["US"]}
              />
              <Input
                value={values.phone ?? ""}
                onChange={(e) => {
                  setField("phone", e.target.value);
                  setPhone(e.target.value);
                  setValidPhone(Setting.isValidPhone(e.target.value, values.countryCode));
                }}
                placeholder={signupItem.placeholder}
                style={{width: "65%"}}
                disabled={invitation !== undefined && invitation.phone !== ""}
              />
            </div>
          </Field>
          {signupItem.rule !== "No verification" && (
            <Field label={i18next.t("code:Phone code")} required={required} error={errors.phoneCode}>
              <SendCodeInput
                value={values.phoneCode ?? ""}
                onChange={(v) => setField("phoneCode", v)}
                disabled={!validPhone}
                method={"signup"}
                onButtonClickArgs={[phone, "phone", Setting.getApplicationName(application)]}
                application={application}
                countryCode={values.countryCode}
              />
            </Field>
          )}
        </React.Fragment>
      );
      if (signupItem.name === "Email") {return <React.Fragment key="email-grp">{renderEmailItem()}</React.Fragment>;}
      if (signupItem.name === "Phone") {return <React.Fragment key="phone-grp">{renderPhoneItem()}</React.Fragment>;}
      if (signupItem.name === "Email or Phone" || signupItem.name === "Phone or Email") {
        let mode = emailOrPhoneMode;
        if (mode === "") {mode = signupItem.name === "Email or Phone" ? "Email" : "Phone";}
        const options = signupItem.name === "Email or Phone" ? ["Email", "Phone"] : ["Phone", "Email"];
        return (
          <React.Fragment key="email-or-phone">
            <div className="flex justify-center my-6 gap-2">
              {options.map((opt) => (
                <button key={opt} type="button"
                  onClick={() => setEmailOrPhoneMode(opt)}
                  className={`px-4 py-1.5 rounded-md text-sm ${mode === opt ? "bg-white text-black" : "bg-white/10 text-white"}`}>
                  {i18next.t(`general:${opt}`)}
                </button>
              ))}
            </div>
            {mode === "Email" ? renderEmailItem() : renderPhoneItem()}
          </React.Fragment>
        );
      }
      return null;
    } else if (signupItem.name === "Password") {
      return (
        <Popover key="password" open={passwordPopoverOpen} onOpenChange={setPasswordPopoverOpen}>
          <PopoverTrigger asChild>
            <div>
              <Field label={label} required={required} error={errors.password}>
                <Input
                  type="password"
                  value={values.password ?? ""}
                  onChange={(e) => {
                    setField("password", e.target.value);
                    setPasswordPopover(PasswordChecker.renderPasswordPopover(application.organizationObj?.passwordOptions ?? [], e.target.value));
                  }}
                  onFocus={() => {
                    setPasswordPopoverOpen((application.organizationObj?.passwordOptions ?? [])?.length > 0);
                    setPasswordPopover(PasswordChecker.renderPasswordPopover(application.organizationObj?.passwordOptions ?? [], values.password ?? ""));
                  }}
                  onBlur={() => setPasswordPopoverOpen(false)}
                  placeholder={signupItem.placeholder}
                />
              </Field>
            </div>
          </PopoverTrigger>
          <PopoverContent side="top">{passwordPopover}</PopoverContent>
        </Popover>
      );
    } else if (signupItem.name === "Confirm password") {
      return (
        <Field key="confirm" label={label} required={required} error={errors.confirm}>
          <Input
            type="password"
            value={values.confirm ?? ""}
            onChange={(e) => setField("confirm", e.target.value)}
            placeholder={signupItem.placeholder}
          />
        </Field>
      );
    } else if (signupItem.name === "Invitation code") {
      return (
        <Field key="invitationCode" label={label} required={required} error={errors.invitationCode}>
          <Input
            value={values.invitationCode ?? ""}
            onChange={(e) => setField("invitationCode", e.target.value)}
            placeholder={signupItem.placeholder}
            disabled={invitation !== undefined && invitation !== ""}
          />
        </Field>
      );
    } else if (signupItem.name === "Agreement") {
      // TODO(rip-antd): AgreementModal.renderAgreementFormItem still expects antd Form.Item context.
      return (
        <div key="agreement">
          {AgreementModal.renderAgreementFormItem(application, required, {}, {props, form: {current: {getFieldValue: () => values.agreement, setFieldValue: (k, v) => setField(k, v)}}, state: {}, setState: () => {}})}
        </div>
      );
    } else if (signupItem.name.startsWith("Text ")) {
      return (<div key={`text-${signupItem.label}`} dangerouslySetInnerHTML={{__html: signupItem.label}} />);
    } else if (signupItem.name === "Signup button") {
      return (
        <div key="signup-btn" className="mt-4">
          <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
            <UserPlus className="w-4 h-4" />
            {i18next.t("account:Sign Up")}
          </button>
          <div className="mt-4 text-center text-sm text-neutral-400">
            {i18next.t("signup:Have account?")}&nbsp;
            <a className="text-white hover:text-neutral-300 transition-colors cursor-pointer" onClick={() => {
              const linkInStorage = sessionStorage.getItem("signinUrl");
              if (linkInStorage !== null && linkInStorage !== "") {
                Setting.goToLinkSoft({props}, linkInStorage);
              } else {
                Setting.redirectToLoginPage(application, props.history);
              }
            }}>
              {i18next.t("signup:sign in now")}
            </a>
          </div>
        </div>
      );
    } else if (signupItem.name === "Providers") {
      const showForm = Setting.isPasswordEnabled(application) || Setting.isCodeSigninEnabled(application) || Setting.isWebAuthnEnabled(application) || Setting.isLdapEnabled(application);
      if (signupItem.rule === "None" || signupItem.rule === "") {
        signupItem.rule = showForm ? "small" : "big";
      }
      return (
        <div key="providers">
          {application.providers.filter(providerItem => isProviderVisible(providerItem)).map((providerItem, id) => (
            <span key={id} onClick={(e) => {
              const agreementChecked = values.agreement;
              if (agreementChecked !== undefined && typeof agreementChecked === "boolean" && !agreementChecked) {
                e.preventDefault();
                toast.error(i18next.t("signup:Please accept the agreement!"));
              }
            }}>
              {ProviderButton.renderProviderLogo(providerItem.provider, application, null, null, signupItem.rule, props.location)}
            </span>
          ))}
        </div>
      );
    } else if (["Gender", "Bio", "Tag", "Education"].includes(signupItem.name)) {
      const fieldName = signupItem.name.toLowerCase();
      if (!signupItem.type || signupItem.type === "Input") {
        return (
          <Field key={fieldName} label={label} required={required} error={errors[fieldName]}>
            <Input value={values[fieldName] ?? ""} onChange={(e) => setField(fieldName, e.target.value)} placeholder={signupItem.placeholder} />
          </Field>
        );
      } else if (signupItem.type === "Multiple Choices") {
        return (
          <Field key={fieldName} label={label} required={required} error={errors[fieldName]}>
            <select
              multiple
              value={Array.isArray(values[fieldName]) ? values[fieldName] : []}
              onChange={(e) => {
                const next = Array.from(e.target.selectedOptions).map(o => o.value);
                setField(fieldName, next);
              }}
              className="w-full px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none"
            >
              {signupItem.options.map((opt) => <option key={opt} value={opt}>{opt}</option>)}
            </select>
          </Field>
        );
      } else if (signupItem.type === "Single Choice") {
        return (
          <Field key={fieldName} label={label} required={required} error={errors[fieldName]}>
            <Select value={values[fieldName]} onValueChange={(v) => setField(fieldName, v)}>
              <SelectTrigger><SelectValue placeholder={signupItem.placeholder} /></SelectTrigger>
              <SelectContent>
                {signupItem.options.map((opt) => <SelectItem key={opt} value={opt}>{opt}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
        );
      }
    }
    return null;
  };

  const renderForm = (application) => {
    if (!application.enableSignUp) {
      return (
        <div className="flex flex-col items-center gap-4 py-8">
          <div className="text-red-400 text-lg font-medium">{i18next.t("application:Sign Up Error")}</div>
          <div className="text-neutral-400 text-sm text-center">{i18next.t("application:The application does not allow to sign up new account")}</div>
          <button className="px-6 py-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors"
            onClick={() => Setting.redirectToLoginPage(application, props.history)}>
            {i18next.t("login:Sign In")}
          </button>
        </div>
      );
    }
    const displayNameItem = application.signupItems?.find(item => item.name === "Display name");
    if (displayNameItem && !displayNameRule) {setDisplayNameRule(displayNameItem.rule);}
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (validate(application)) {onFinish(application);}
        }}
        style={{width: Setting.isMobile() ? "300px" : "400px"}}
      >
        {application.signupItems?.map((signupItem, idx) => (
          <div key={idx}>
            <div dangerouslySetInnerHTML={{__html: ("<style>" + signupItem.customCss + "</style>")}} />
            {renderSignupFormItem(application, signupItem)}
          </div>
        ))}
      </form>
    );
  };

  const application = getApplicationObj();
  if (application === undefined || application === null) {return null;}
  let existSignupButton = false;
  application.signupItems?.map(item => {
    item.name === "Signup button" ? existSignupButton = true : null;
  });
  if (!existSignupButton) {
    application.signupItems?.push({customCss: "", label: "", name: "Signup button", placeholder: "", visible: true});
  }
  if (application.signupHtml !== "") {
    return (<div dangerouslySetInnerHTML={{__html: application.signupHtml}} />);
  }
  return (
    <React.Fragment>
      <div className="login-content" style={{margin: props.preview ?? parseOffset(application.formOffset)}}>
        {Setting.inIframe() || Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCss}} />}
        {Setting.inIframe() || !Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCssMobile}} />}
        <div className={Setting.isDarkTheme(props.themeAlgorithm) ? "login-panel-dark" : "login-panel"}>
          <div className="side-image" style={{display: application.formOffset !== 4 ? "none" : null}}>
            <div dangerouslySetInnerHTML={{__html: application.formSideHtml}} />
          </div>
          <div className="login-form">
            {Setting.renderHelmet(application)}
            {Setting.renderLogo(application)}
            <LanguageSelect languages={application.organizationObj?.languages ?? ["en"]} style={{top: "55px", right: "5px", position: "absolute"}} />
            {renderForm(application)}
          </div>
        </div>
      </div>
    </React.Fragment>
  );
}

export default withRouter(SignupPage);
