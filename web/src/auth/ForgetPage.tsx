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
import {Form, Input, Select} from "antd";
import {ArrowLeft, User, Lock, CheckCircle, KeyRound} from "lucide-react";
import * as AuthBackend from "./AuthBackend";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Util from "./Util";
import * as Setting from "../Setting";
import i18next from "i18next";
import {SendCodeInput} from "../common/SendCodeInput";
import * as UserBackend from "../backend/UserBackend";
import {withRouter} from "react-router-dom";
import * as PasswordChecker from "../common/PasswordChecker";
import * as Obfuscator from "./Obfuscator";

const {Option} = Select;

function ForgetPage(props) {
  const queryParams = new URLSearchParams(location.search);
  const formRef = useRef(null);

  const [applicationName] = useState(props.applicationName ?? props.match.params?.applicationName);
  const [msg, setMsg] = useState(null);
  const [name, setName] = useState(props.account ? props.account.name : queryParams.get("username"));
  const [phone, setPhone] = useState("");
  const [email, setEmail] = useState("");
  const [dest, setDest] = useState("");
  const [isVerifyTypeFixed, setIsVerifyTypeFixed] = useState(false);
  const [verifyType, setVerifyType] = useState("");
  const [current, setCurrent] = useState(queryParams.get("code") ? 2 : 0);
  const [code, setCode] = useState(queryParams.get("code"));
  const [passwordPopover, setPasswordPopover] = useState(null);
  const [passwordPopoverOpen, setPasswordPopoverOpen] = useState(false);

  const getApplicationObj = useCallback(() => props.application, [props.application]);
  const onUpdateApplication = useCallback((application) => props.onUpdateApplication(application), [props.onUpdateApplication]);

  useEffect(() => {
    if (getApplicationObj() === undefined) {
      if (applicationName !== undefined) {
        ApplicationBackend.getApplication("admin", applicationName)
          .then((res) => {
            if (res.status === "error") {
              Setting.showMessage("error", res.msg);
              return;
            }
            onUpdateApplication(res.data);
          });
      } else {
        Setting.showMessage("error", i18next.t("forget:Unknown forget type") + ": " + applicationName);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const onFormFinish = (formName, info, forms) => {
    switch (formName) {
    case "step1": {
      const username = forms.step1.getFieldValue("username");
      AuthBackend.getEmailAndPhone(forms.step1.getFieldValue("organization"), username)
        .then((res) => {
          if (res.status === "ok") {
            const p = res.data.phone;
            const e = res.data.email;

            if (!p && !e) {
              Setting.showMessage("error", i18next.t("general:No verification method"));
            } else {
              setName(res.data.name);
              setPhone(p);
              setEmail(e);

              const saveFields = (type, dest, fixed) => {
                setVerifyType(type);
                setIsVerifyTypeFixed(fixed);
                setDest(dest);
              };

              switch (res.data2) {
              case "email":
                saveFields("email", e, true);
                break;
              case "phone":
                saveFields("phone", p, true);
                break;
              case "username":
                p !== "" ? saveFields("phone", p, false) : saveFields("email", e, false);
              }

              setCurrent(1);
            }
          } else {
            Setting.showMessage("error", res.msg);
          }
        });
      break;
    }
    case "step2":
      UserBackend.verifyCode({
        application: forms.step2.getFieldValue("application"),
        organization: forms.step2.getFieldValue("organization"),
        username: forms.step2.getFieldValue("dest"),
        name: name,
        code: forms.step2.getFieldValue("code"),
        type: "login",
      }).then(res => {
        if (res.status === "ok") {
          setCurrent(2);
          setCode(forms.step2.getFieldValue("code"));
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
      break;
    default:
      break;
    }
  };

  const onFinish = async (values) => {
    values.username = name;
    values.userOwner = getApplicationObj()?.organizationObj?.name ?? "built-in";

    if (queryParams.get("code")) {
      const res = await UserBackend.verifyCode({
        application: getApplicationObj().name,
        organization: values.userOwner,
        username: queryParams.get("dest"),
        name: name,
        code: code,
        type: "login",
      });

      if (res.status !== "ok") {
        Setting.showMessage("error", res.msg);
        return;
      }
    }

    let encryptedNewPassword = values?.newPassword;
    const organization = getApplicationObj()?.organizationObj;

    if (organization?.passwordObfuscatorType && organization.passwordObfuscatorType !== "Plain") {
      const [passwordCipher, errorMessage] = Obfuscator.encryptByPasswordObfuscator(
        organization.passwordObfuscatorType,
        organization.passwordObfuscatorKey,
        values?.newPassword
      );
      if (errorMessage.length > 0) {
        Setting.showMessage("error", errorMessage);
        return;
      }
      encryptedNewPassword = passwordCipher;
    }

    UserBackend.setPassword(values.userOwner, values.username, "", encryptedNewPassword, code).then(res => {
      if (res.status === "ok") {
        const linkInStorage = sessionStorage.getItem("signinUrl");
        if (linkInStorage !== null && linkInStorage !== "") {
          Setting.goToLinkSoft({props}, linkInStorage);
        } else {
          Setting.redirectToLoginPage(getApplicationObj(), props.history);
        }
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  };

  const stepBack = () => {
    if (current > 0) {
      setCurrent(current - 1);
    } else if (props.history.length > 1) {
      props.history.goBack();
    } else {
      Setting.redirectToLoginPage(getApplicationObj(), props.history);
    }
  };

  const renderOptions = () => {
    const options = [];
    if (phone !== "") {
      options.push(<Option key={"phone"} value={phone}>&nbsp;&nbsp;{phone}</Option>);
    }
    if (email !== "") {
      options.push(<Option key={"email"} value={email}>&nbsp;&nbsp;{email}</Option>);
    }
    return options;
  };

  const renderStepIndicator = () => {
    const steps = [
      {label: i18next.t("forget:Account"), icon: <User className="w-4 h-4" />},
      {label: i18next.t("forget:Verify"), icon: <KeyRound className="w-4 h-4" />},
      {label: i18next.t("forget:Reset"), icon: <Lock className="w-4 h-4" />},
    ];

    return (
      <div className="flex items-center justify-center gap-2 my-8">
        {steps.map((step, idx) => (
          <React.Fragment key={idx}>
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              idx === current
                ? "bg-white/10 text-white"
                : idx < current
                  ? "text-white/60"
                  : "text-white/30"
            }`}>
              <div className={`flex items-center justify-center w-6 h-6 rounded-full text-xs ${
                idx === current
                  ? "bg-white text-black"
                  : idx < current
                    ? "bg-white/30 text-white"
                    : "bg-white/10 text-white/30"
              }`}>
                {idx < current ? <CheckCircle className="w-3.5 h-3.5" /> : idx + 1}
              </div>
              <span className="hidden sm:inline">{step.label}</span>
            </div>
            {idx < steps.length - 1 && (
              <div className={`w-8 h-px ${idx < current ? "bg-white/30" : "bg-white/10"}`} />
            )}
          </React.Fragment>
        ))}
      </div>
    );
  };

  const renderForm = (application) => {
    return (
      <Form.Provider onFormFinish={(formName, {info, forms}) => {
        onFormFinish(formName, info, forms);
      }}>
        {/* STEP 1: input username */}
        {current === 0 ?
          <Form
            ref={formRef}
            name="step1"
            onFinishFailed={(errorInfo) => console.log(errorInfo)}
            initialValues={{
              application: application.name,
              organization: application.organization,
              username: name,
            }}
            style={{width: "300px"}}
            size="large"
          >
            <Form.Item hidden name="application" rules={[{required: true, message: i18next.t("application:Please input your application!")}]} />
            <Form.Item hidden name="organization" rules={[{required: true, message: i18next.t("application:Please input your organization!")}]} />
            <Form.Item name="username" rules={[{required: true, message: i18next.t("forget:Please input your username!"), whitespace: true}]}>
              <Input prefix={<User className="w-4 h-4 text-neutral-500" />} placeholder={i18next.t("login:username, Email or phone")} />
            </Form.Item>
            <br />
            <Form.Item>
              <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
                {i18next.t("forget:Next Step")}
              </button>
            </Form.Item>
          </Form> : null}

        {/* STEP 2: verify email or phone */}
        {current === 1 ? <Form
          ref={formRef}
          name="step2"
          onFinishFailed={(errorInfo) => console.log(errorInfo)}
          onValuesChange={(changedValues) => {
            if (!changedValues.dest) {return;}
            const vt = changedValues.dest?.indexOf("@") === -1 ? "phone" : "email";
            setDest(changedValues.dest);
            setVerifyType(vt);
          }}
          initialValues={{
            application: application.name,
            organization: application.organization,
            dest: dest,
          }}
          style={{width: "300px"}}
          size="large"
        >
          <Form.Item style={{height: 0, visibility: "hidden"}} name="application" rules={[{required: true, message: i18next.t("application:Please input your application!")}]} />
          <Form.Item hidden name="organization" rules={[{required: true, message: i18next.t("application:Please input your organization!")}]} />
          <Form.Item name="dest" validateFirst hasFeedback>
            <Select virtual={false} disabled={isVerifyTypeFixed} style={{textAlign: "left"}} placeholder={i18next.t("forget:Choose email or phone")}>
              {renderOptions()}
            </Select>
          </Form.Item>
          <Form.Item name="code" rules={[{required: true, message: i18next.t("code:Please input your verification code!")}]}>
            <SendCodeInput disabled={dest === ""} method={"forget"}
              onButtonClickArgs={[dest, verifyType, Setting.getApplicationName(getApplicationObj()), name]}
              application={application} />
          </Form.Item>
          <br />
          <Form.Item>
            <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
              {i18next.t("forget:Next Step")}
            </button>
          </Form.Item>
        </Form> : null}

        {/* STEP 3: new password */}
        {current === 2 ?
          <Form
            ref={formRef}
            name="step3"
            onFinish={(values) => onFinish(values)}
            onFinishFailed={(errorInfo) => console.log(errorInfo)}
            initialValues={{
              application: application.name,
              organization: application.organization,
            }}
            style={{width: "300px"}}
            size="large"
          >
            <Form.Item hidden name="application" rules={[{required: true, message: i18next.t("application:Please input your application!")}]} />
            <Form.Item hidden name="organization" rules={[{required: true, message: i18next.t("application:Please input your organization!")}]} />
            <Form.Item name="newPassword" hidden={current !== 2}
              rules={[{
                required: true,
                validateTrigger: "onChange",
                validator: (rule, value) => {
                  const errorMsg = PasswordChecker.checkPasswordComplexity(value, application.organizationObj?.passwordOptions ?? []);
                  if (errorMsg === "") {return Promise.resolve();}
                  else {return Promise.reject(errorMsg);}
                },
              }]}
              hasFeedback>
              <Input.Password
                prefix={<Lock className="w-4 h-4 text-neutral-500" />}
                placeholder={i18next.t("general:Password")}
                onChange={(e) => {
                  setPasswordPopover(PasswordChecker.renderPasswordPopover(application.organizationObj?.passwordOptions ?? [], e.target.value));
                }}
                onFocus={() => {
                  setPasswordPopoverOpen(application.organizationObj?.passwordOptions ?? []?.length > 0);
                  setPasswordPopover(PasswordChecker.renderPasswordPopover(application.organizationObj?.passwordOptions ?? [], formRef.current?.getFieldValue("newPassword") ?? ""));
                }}
                onBlur={() => { setPasswordPopoverOpen(false); }}
              />
            </Form.Item>
            <Form.Item name="confirm" dependencies={["newPassword"]} hasFeedback
              rules={[
                {required: true, message: i18next.t("signup:Please confirm your password!")},
                ({getFieldValue}) => ({
                  validator(rule, value) {
                    if (!value || getFieldValue("newPassword") === value) {return Promise.resolve();}
                    return Promise.reject(i18next.t("signup:Your confirmed password is inconsistent with the password!"));
                  },
                }),
              ]}>
              <Input.Password prefix={<CheckCircle className="w-4 h-4 text-neutral-500" />} placeholder={i18next.t("general:Confirm")} />
            </Form.Item>
            <br />
            <Form.Item hidden={current !== 2}>
              <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
                {i18next.t("forget:Change Password")}
              </button>
            </Form.Item>
          </Form> : null}
      </Form.Provider>
    );
  };

  // --- Main render ---

  const application = getApplicationObj();
  if (application === undefined) {
    return null;
  }
  if (application === null) {
    return Util.renderMessageLarge({props}, msg);
  }

  return (
    <React.Fragment>
      <div className="forget-content" style={{padding: Setting.isMobile() ? "0" : null, boxShadow: Setting.isMobile() ? "none" : null}}>
        {Setting.inIframe() || Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCss}} />}
        {Setting.inIframe() || !Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCssMobile}} />}
        <button
          type="button"
          className="flex items-center justify-center w-10 h-10 rounded-lg border border-white/10 bg-transparent text-neutral-400 hover:text-white hover:border-white/20 transition-colors"
          style={{position: "relative", left: Setting.isMobile() ? "10px" : "-90px", top: 0}}
          onClick={() => stepBack()}
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex flex-col items-center justify-center">
          <div className="mt-20 mb-3 text-center">
            {Setting.renderHelmet(application)}
            {Setting.renderLogo(application)}
          </div>
          <div className="text-center text-2xl font-semibold text-white mb-2">
            {i18next.t("forget:Reset password")}
          </div>
          {renderStepIndicator()}
          <div className="mt-4 text-center">
            {renderForm(application)}
          </div>
        </div>
      </div>
    </React.Fragment>
  );
}

export default withRouter(ForgetPage);
