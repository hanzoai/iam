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
import React, {useCallback, useEffect, useRef, useState} from "react";
import {Form, Input, Popover, Radio, Select, message} from "antd";
import {UserPlus, Loader2} from "lucide-react";
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

const formItemLayout = {
  labelCol: {xs: {span: 24}, sm: {span: 8}},
  wrapperCol: {xs: {span: 24}, sm: {span: 16}},
};

const renderFormItem = (signupItem) => {
  const commonRules = [
    {
      required: signupItem.required,
      message: i18next.t("signup:Please input your {label}!").replace("{label}", signupItem.label || signupItem.name),
    },
  ];

  if (!signupItem.type || signupItem.type === "Input") {
    const inputRules = [...commonRules];
    if (signupItem.regex) {
      inputRules.push({
        pattern: new RegExp(signupItem.regex),
        message: i18next.t("signup:The input doesn't match the signup item regex!"),
      });
    }
    return (
      <Form.Item name={signupItem.name.toLowerCase()} label={signupItem.label || signupItem.name} rules={inputRules}>
        <Input placeholder={signupItem.placeholder} />
      </Form.Item>
    );
  } else if (signupItem.type === "Single Choice" || signupItem.type === "Multiple Choices") {
    return (
      <Form.Item name={signupItem.name.toLowerCase()} label={signupItem.label || signupItem.name} rules={commonRules}>
        <Select
          mode={signupItem.type === "Multiple Choices" ? "multiple" : "single"}
          placeholder={signupItem.placeholder}
          showSearch={false}
          options={signupItem.options.map(option => ({label: option, value: option}))}
        />
      </Form.Item>
    );
  }
};

export const tailFormItemLayout = {
  wrapperCol: {xs: {span: 24, offset: 0}, sm: {span: 16, offset: 8}},
};

function SignupPage(props) {
  const formRef = useRef(null);
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
        if (application) {
          appName = application.name;
        }
        getInvitationCodeInfo(code, "admin/" + appName);
      }
    }
  }, [applicationName, getInvitationCodeInfo]);

  const getApplicationLogin = useCallback((oAuthParams) => {
    AuthBackend.getApplicationLogin(oAuthParams)
      .then((res) => {
        if (res.status === "ok") {
          const application = res.data;
          onUpdateApplication(application);
          setInvitationCodeFromUrl(application);
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

  const parseOffset = (offset) => {
    if (offset === 2 || offset === 4 || Setting.inIframe() || Setting.isMobile()) {
      return "0 auto";
    }
    if (offset === 1) {return "0 10%";}
    if (offset === 3) {return "0 60%";}
  };

  const getResultPath = (application, signupParams) => {
    if (signupParams?.plan && signupParams?.pricing) {
      return `/buy-plan/${application.organization}/${signupParams?.pricing}?user=${signupParams.username}&plan=${signupParams.plan}`;
    }
    if (authConfig.appName === application.name) {
      return "/result";
    } else {
      const oAuthParams = Util.getOAuthGetParameters();
      if (Setting.hasPromptPage(application)) {
        return `/prompt/${application.name}?oauth=${oAuthParams !== null}`;
      } else {
        return `/result/${application.name}`;
      }
    }
  };

  const onFinish = (values) => {
    const application = getApplicationObj();

    if (Array.isArray(values.gender)) {values.gender = values.gender.join(", ");}
    if (Array.isArray(values.bio)) {values.bio = values.bio.join(", ");}
    if (Array.isArray(values.tag)) {values.tag = values.tag.join(", ");}
    if (Array.isArray(values.education)) {values.education = values.education.join(", ");}

    if (invitationCode && !values.invitationCode) {
      values.invitationCode = invitationCode;
    }

    const params = new URLSearchParams(window.location.search);
    values.plan = params.get("plan");
    values.pricing = params.get("pricing");

    const oAuthParams = Util.getOAuthGetParameters();

    AuthBackend.signup(values, oAuthParams)
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

          if (typeof res.data === "string") {
            values.username = res.data.split("/")[1];
          }
          if (Setting.hasPromptPage(application) && (!values.plan || !values.pricing)) {
            AuthBackend.getAccount("")
              .then((res) => {
                let account = null;
                if (res.status === "ok") {
                  account = res.data;
                  account.organization = res.data2;
                  onUpdateAccount(account);
                  Setting.goToLinkSoft({props}, getResultPath(application, values));
                } else {
                  Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
                }
              });
          } else {
            Setting.goToLinkSoft({props}, getResultPath(application, values));
          }
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  };

  const onFinishFailed = (values, errorFields) => {
    formRef.current?.scrollToField(errorFields[0].name);
  };

  const isProviderVisible = (providerItem) => {
    return Setting.isProviderVisibleForSignUp(providerItem);
  };

  const renderSignupFormItem = (application, signupItem) => {
    const validItems = ["Gender", "Bio", "Tag", "Education"];
    if (!signupItem.visible) {return null;}
    const required = signupItem.required;

    if (signupItem.name === "Username") {
      const usernameRules = [{required: required, message: i18next.t("forget:Please input your username!"), whitespace: true}];
      if (signupItem.regex) {
        usernameRules.push({pattern: new RegExp(signupItem.regex), message: i18next.t("signup:The input doesn't match the signup item regex!")});
      }
      return (
        <Form.Item name="username" className="signup-username" label={signupItem.label ? signupItem.label : i18next.t("signup:Username")} rules={usernameRules}>
          <Input className="signup-username-input" placeholder={signupItem.placeholder}
            disabled={invitation !== undefined && invitation.username !== ""} />
        </Form.Item>
      );
    } else if (signupItem.name === "Display name") {
      if (signupItem.rule === "First, last" && Setting.getLanguage() !== "zh") {
        const firstNameRules = [{required: required, message: i18next.t("signup:Please input your first name!"), whitespace: true}];
        const lastNameRules = [{required: required, message: i18next.t("signup:Please input your last name!"), whitespace: true}];
        if (signupItem.regex) {
          const regexRule = {pattern: new RegExp(signupItem.regex), message: i18next.t("signup:The input doesn't match the signup item regex!")};
          firstNameRules.push(regexRule);
          lastNameRules.push(regexRule);
        }
        return (
          <React.Fragment>
            <Form.Item name="firstName" className="signup-first-name" label={signupItem.label ? signupItem.label : i18next.t("general:First name")} rules={firstNameRules}>
              <Input className="signup-first-name-input" placeholder={signupItem.placeholder} />
            </Form.Item>
            <Form.Item name="lastName" className="signup-last-name" label={signupItem.label ? signupItem.label : i18next.t("general:Last name")} rules={lastNameRules}>
              <Input className="signup-last-name-input" placeholder={signupItem.placeholder} />
            </Form.Item>
          </React.Fragment>
        );
      }

      const displayNameRules = [{
        required: required,
        message: (signupItem.rule === "Real name" || signupItem.rule === "First, last") ? i18next.t("signup:Please input your real name!") : i18next.t("signup:Please input your display name!"),
        whitespace: true,
      }];
      if (signupItem.regex) {
        displayNameRules.push({pattern: new RegExp(signupItem.regex), message: i18next.t("signup:The input doesn't match the signup item regex!")});
      }
      return (
        <Form.Item name="name" className="signup-name"
          label={(signupItem.label ? signupItem.label : (signupItem.rule === "Real name" || signupItem.rule === "First, last") ? i18next.t("application:Real name") : i18next.t("general:Display name"))}
          rules={displayNameRules}>
          <Input className="signup-name-input" placeholder={signupItem.placeholder} />
        </Form.Item>
      );
    } else if (signupItem.name === "First name" && displayNameRule !== "First, last") {
      const firstNameRules = [{required: required, message: i18next.t("signup:Please input your first name!"), whitespace: true}];
      if (signupItem.regex) {
        firstNameRules.push({pattern: new RegExp(signupItem.regex), message: i18next.t("signup:The input doesn't match the signup item regex!")});
      }
      return (
        <Form.Item name="firstName" className="signup-first-name" label={signupItem.label ? signupItem.label : i18next.t("general:First name")} rules={firstNameRules}>
          <Input className="signup-first-name-input" placeholder={signupItem.placeholder} />
        </Form.Item>
      );
    } else if (signupItem.name === "Last name" && displayNameRule !== "First, last") {
      const lastNameRules = [{required: required, message: i18next.t("signup:Please input your last name!"), whitespace: true}];
      if (signupItem.regex) {
        lastNameRules.push({pattern: new RegExp(signupItem.regex), message: i18next.t("signup:The input doesn't match the signup item regex!")});
      }
      return (
        <Form.Item name="lastName" className="signup-last-name" label={signupItem.label ? signupItem.label : i18next.t("general:Last name")} rules={lastNameRules}>
          <Input className="signup-last-name-input" placeholder={signupItem.placeholder} />
        </Form.Item>
      );
    } else if (signupItem.name === "Affiliation") {
      const affiliationRules = [{required: required, message: i18next.t("signup:Please input your affiliation!"), whitespace: true}];
      if (signupItem.regex) {
        affiliationRules.push({pattern: new RegExp(signupItem.regex), message: i18next.t("signup:The input doesn't match the signup item regex!")});
      }
      return (
        <Form.Item name="affiliation" className="signup-affiliation" label={signupItem.label ? signupItem.label : i18next.t("user:Affiliation")} rules={affiliationRules}>
          <Input className="signup-affiliation-input" placeholder={signupItem.placeholder} />
        </Form.Item>
      );
    } else if (signupItem.name === "ID card") {
      return (
        <Form.Item name="idCard" className="signup-idcard" label={signupItem.label ? signupItem.label : i18next.t("user:ID card")}
          rules={[
            {required: required, message: i18next.t("signup:Please input your ID card number!"), whitespace: true},
            {required: required, pattern: new RegExp(/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9X]$/, "g"), message: i18next.t("signup:Please input the correct ID card number!")},
          ]}>
          <Input className="signup-idcard-input" placeholder={signupItem.placeholder} />
        </Form.Item>
      );
    } else if (signupItem.name === "Country/Region") {
      return (
        <Form.Item name="country_region" className="signup-country-region" label={signupItem.label ? signupItem.label : i18next.t("user:Country/Region")}
          rules={[{required: required, message: i18next.t("signup:Please select your country/region!")}]}>
          <RegionSelect className="signup-region-select" onChange={(value) => { setRegion(value); }} />
        </Form.Item>
      );
    } else if (signupItem.name === "Email" || signupItem.name === "Phone" || signupItem.name === "Email or Phone" || signupItem.name === "Phone or Email") {
      const renderEmailItem = () => (
        <React.Fragment>
          <Form.Item name="email" className="signup-email" label={signupItem.label ? signupItem.label : i18next.t("general:Email")}
            rules={[
              {required: required, message: i18next.t("login:Please input your Email!")},
              {
                validator: (_, value) => {
                  if (email !== "" && !Setting.isValidEmail(email)) {
                    setValidEmail(false);
                    return Promise.reject(i18next.t("login:The input is not valid Email!"));
                  }
                  if (signupItem.regex) {
                    const reg = new RegExp(signupItem.regex);
                    if (!reg.test(email)) {
                      setValidEmail(false);
                      return Promise.reject(i18next.t("signup:The input Email doesn't match the signup item regex!"));
                    }
                  }
                  setValidEmail(true);
                  return Promise.resolve();
                },
              },
            ]}>
            <Input className="signup-email-input" placeholder={signupItem.placeholder} disabled={invitation !== undefined && invitation.email !== ""} onChange={e => setEmail(e.target.value)} />
          </Form.Item>
          {signupItem.rule !== "No verification" &&
            <Form.Item name="emailCode" className="signup-email-code" label={signupItem.label ? signupItem.label : i18next.t("code:Email code")}
              rules={[{required: required, message: i18next.t("code:Please input your verification code!")}]}>
              <SendCodeInput className="signup-email-code-input" disabled={!validEmail} method={"signup"}
                onButtonClickArgs={[email, "email", Setting.getApplicationName(application)]} application={application} />
            </Form.Item>
          }
        </React.Fragment>
      );

      const renderPhoneItem = () => (
        <React.Fragment>
          <Form.Item className="signup-phone" label={signupItem.label ? signupItem.label : i18next.t("general:Phone")} required={required}>
            <Input.Group compact>
              <Form.Item name="countryCode" noStyle rules={[{required: required, message: i18next.t("signup:Please select your country code!")}]}>
                <CountryCodeSelect style={{width: "35%"}} countryCodes={getApplicationObj().organizationObj.countryCodes} />
              </Form.Item>
              <Form.Item name="phone" dependencies={["countryCode"]} noStyle
                rules={[
                  {required: required, message: i18next.t("signup:Please input your phone number!")},
                  ({getFieldValue}) => ({
                    validator: (_, value) => {
                      if (!required && !value) {return Promise.resolve();}
                      if (value && !Setting.isValidPhone(value, getFieldValue("countryCode"))) {
                        setValidPhone(false);
                        return Promise.reject(i18next.t("signup:The input is not valid Phone!"));
                      }
                      setValidPhone(true);
                      return Promise.resolve();
                    },
                  }),
                ]}>
                <Input className="signup-phone-input" placeholder={signupItem.placeholder} style={{width: "65%"}}
                  disabled={invitation !== undefined && invitation.phone !== ""} onChange={e => setPhone(e.target.value)} />
              </Form.Item>
            </Input.Group>
          </Form.Item>
          {signupItem.rule !== "No verification" &&
            <Form.Item name="phoneCode" className="phone-code" label={signupItem.label ? signupItem.label : i18next.t("code:Phone code")}
              rules={[{required: required, message: i18next.t("code:Please input your phone verification code!")}]}>
              <SendCodeInput className="signup-phone-code-input" disabled={!validPhone} method={"signup"}
                onButtonClickArgs={[phone, "phone", Setting.getApplicationName(application)]} application={application}
                countryCode={formRef.current?.getFieldValue("countryCode")} />
            </Form.Item>
          }
        </React.Fragment>
      );

      if (signupItem.name === "Email") {return renderEmailItem();}
      else if (signupItem.name === "Phone") {return renderPhoneItem();}
      else if (signupItem.name === "Email or Phone" || signupItem.name === "Phone or Email") {
        let mode = emailOrPhoneMode;
        if (mode === "") {
          mode = signupItem.name === "Email or Phone" ? "Email" : "Phone";
        }
        return (
          <React.Fragment>
            <div className="flex justify-center my-6">
              <Radio.Group buttonStyle="solid" onChange={e => setEmailOrPhoneMode(e.target.value)} value={mode}>
                {signupItem.name === "Email or Phone" ? (
                  <React.Fragment>
                    <Radio.Button value={"Email"}>{i18next.t("general:Email")}</Radio.Button>
                    <Radio.Button value={"Phone"}>{i18next.t("general:Phone")}</Radio.Button>
                  </React.Fragment>
                ) : (
                  <React.Fragment>
                    <Radio.Button value={"Phone"}>{i18next.t("general:Phone")}</Radio.Button>
                    <Radio.Button value={"Email"}>{i18next.t("general:Email")}</Radio.Button>
                  </React.Fragment>
                )}
              </Radio.Group>
            </div>
            {mode === "Email" ? renderEmailItem() : renderPhoneItem()}
          </React.Fragment>
        );
      } else {
        return null;
      }
    } else if (signupItem.name === "Password") {
      return (
        <Popover placement={"top"} content={passwordPopover} open={passwordPopoverOpen}>
          <Form.Item name="password" className="signup-password" label={signupItem.label ? signupItem.label : i18next.t("general:Password")}
            rules={[{
              required: required,
              validateTrigger: "onChange",
              validator: (rule, value) => {
                const errorMsg = PasswordChecker.checkPasswordComplexity(value, application.organizationObj.passwordOptions);
                if (errorMsg === "") {return Promise.resolve();}
                else {return Promise.reject(errorMsg);}
              },
            }]}
            hasFeedback>
            <Input.Password className="signup-password-input" placeholder={signupItem.placeholder} onChange={(e) => {
              setPasswordPopover(PasswordChecker.renderPasswordPopover(application.organizationObj.passwordOptions, e.target.value));
            }}
            onFocus={() => {
              setPasswordPopoverOpen(application.organizationObj.passwordOptions?.length > 0);
              setPasswordPopover(PasswordChecker.renderPasswordPopover(application.organizationObj.passwordOptions, formRef.current?.getFieldValue("password") ?? ""));
            }}
            onBlur={() => { setPasswordPopoverOpen(false); }} />
          </Form.Item>
        </Popover>
      );
    } else if (signupItem.name === "Confirm password") {
      return (
        <Form.Item name="confirm" className="signup-confirm" label={signupItem.label ? signupItem.label : i18next.t("general:Confirm")}
          dependencies={["password"]} hasFeedback
          rules={[
            {required: required, message: i18next.t("signup:Please confirm your password!")},
            ({getFieldValue}) => ({
              validator(rule, value) {
                if (!value || getFieldValue("password") === value) {return Promise.resolve();}
                return Promise.reject(i18next.t("signup:Your confirmed password is inconsistent with the password!"));
              },
            }),
          ]}>
          <Input.Password placeholder={signupItem.placeholder} />
        </Form.Item>
      );
    } else if (signupItem.name === "Invitation code") {
      return (
        <Form.Item name="invitationCode" className="signup-invitation-code" label={signupItem.label ? signupItem.label : i18next.t("application:Invitation code")}
          rules={[{required: required, message: i18next.t("signup:Please input your invitation code!")}]}>
          <Input className="signup-invitation-code-input" placeholder={signupItem.placeholder} disabled={invitation !== undefined && invitation !== ""} />
        </Form.Item>
      );
    } else if (signupItem.name === "Agreement") {
      return AgreementModal.renderAgreementFormItem(application, required, tailFormItemLayout, {props, form: formRef, state: {}, setState: () => {}});
    } else if (signupItem.name.startsWith("Text ")) {
      return (<div dangerouslySetInnerHTML={{__html: signupItem.label}} />);
    } else if (signupItem.name === "Signup button") {
      return (
        <Form.Item {...tailFormItemLayout}>
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
        </Form.Item>
      );
    } else if (signupItem.name === "Providers") {
      const showForm = Setting.isPasswordEnabled(application) || Setting.isCodeSigninEnabled(application) || Setting.isWebAuthnEnabled(application) || Setting.isLdapEnabled(application);
      if (signupItem.rule === "None" || signupItem.rule === "") {
        signupItem.rule = showForm ? "small" : "big";
      }
      return (
        application.providers.filter(providerItem => isProviderVisible(providerItem)).map((providerItem, id) => {
          return (
            <span key={id} onClick={(e) => {
              const agreementChecked = formRef.current.getFieldValue("agreement");
              if (agreementChecked !== undefined && typeof agreementChecked === "boolean" && !agreementChecked) {
                e.preventDefault();
                message.error(i18next.t("signup:Please accept the agreement!"));
              }
            }}>
              {ProviderButton.renderProviderLogo(providerItem.provider, application, null, null, signupItem.rule, props.location)}
            </span>
          );
        })
      );
    } else if (validItems.includes(signupItem.name)) {
      return renderFormItem(signupItem);
    }
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

    if (invitation !== undefined) {
      if (invitation.username !== "") {formRef.current?.setFieldValue("username", invitation.username);}
      if (invitation.email !== "") {formRef.current?.setFieldValue("email", invitation.email);}
      if (invitation.phone !== "") {formRef.current?.setFieldValue("phone", invitation.phone);}
      if (invitationCode !== "") {formRef.current?.setFieldValue("invitationCode", invitationCode);}
    }

    const displayNameItem = application.signupItems?.find(item => item.name === "Display name");
    if (displayNameItem && !displayNameRule) {
      setDisplayNameRule(displayNameItem.rule);
    }

    return (
      <Form
        {...formItemLayout}
        ref={formRef}
        name="signup"
        onFinish={(values) => onFinish(values)}
        onFinishFailed={(errorInfo) => onFinishFailed(errorInfo.values, errorInfo.errorFields)}
        initialValues={{
          application: application.name,
          organization: application.organization,
          countryCode: application.organizationObj.countryCodes?.[0],
        }}
        size="large"
        layout={Setting.isMobile() ? "vertical" : "horizontal"}
        style={{width: Setting.isMobile() ? "300px" : "400px"}}
      >
        <Form.Item name="application" hidden={true} rules={[{required: true, message: "Please input your application!"}]} />
        <Form.Item name="organization" hidden={true} rules={[{required: true, message: "Please input your organization!"}]} />
        {
          application.signupItems?.map((signupItem, idx) => (
            <div key={idx}>
              <div dangerouslySetInnerHTML={{__html: ("<style>" + signupItem.customCss + "</style>")}} />
              {renderSignupFormItem(application, signupItem)}
            </div>
          ))
        }
      </Form>
    );
  };

  // --- Main render ---

  const application = getApplicationObj();
  if (application === undefined || application === null) {
    return null;
  }

  let existSignupButton = false;
  application.signupItems?.map(item => {
    item.name === "Signup button" ? existSignupButton = true : null;
  });
  if (!existSignupButton) {
    application.signupItems?.push({
      customCss: "",
      label: "",
      name: "Signup button",
      placeholder: "",
      visible: true,
    });
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
            <LanguageSelect languages={application.organizationObj.languages} style={{top: "55px", right: "5px", position: "absolute"}} />
            {renderForm(application)}
          </div>
        </div>
      </div>
    </React.Fragment>
  );
}

export default withRouter(SignupPage);
