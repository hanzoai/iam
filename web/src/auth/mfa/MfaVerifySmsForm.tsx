// @ts-nocheck
import {User} from "lucide-react";
import {Button} from "../../components/ui/button";
import {Checkbox} from "../../components/ui/checkbox";
import {Input} from "../../components/ui/input";
import i18next from "i18next";
import React, {useEffect, useState} from "react";
import {CountryCodeSelect} from "../../common/select/CountryCodeSelect";
import {SendCodeInput} from "../../common/SendCodeInput";
import * as Setting from "../../Setting";
import {EmailMfaType, SmsMfaType} from "../MfaSetupPage";
import {mfaAuth} from "./MfaVerifyForm";

export const MfaVerifySmsForm = ({mfaProps, application, onFinish, method, user}) => {
  const [dest, setDest] = useState("");
  const [countryCode, setCountryCode] = useState(mfaProps.countryCode);
  const [passcode, setPasscode] = useState("");
  const [enableMfaRemember, setEnableMfaRemember] = useState(false);
  const [errors, setErrors] = useState({});

  useEffect(() => {
    if (method === mfaAuth) {
      setDest(mfaProps.secret);
      return;
    }
    if (mfaProps.mfaType === SmsMfaType) {
      setDest(user.phone);
      return;
    }
    if (mfaProps.mfaType === EmailMfaType) {
      setDest(user.email);
    }
  }, [mfaProps.mfaType]);

  const isShowText = () => {
    if (method === mfaAuth) {return true;}
    if (mfaProps.mfaType === SmsMfaType && user.phone !== "") {return true;}
    if (mfaProps.mfaType === EmailMfaType && user.email !== "") {return true;}
    return false;
  };

  const isEmail = () => mfaProps.mfaType === EmailMfaType;

  const submit = (e) => {
    e.preventDefault();
    const next = {};
    if (!isShowText() && !dest) {
      next.dest = i18next.t("login:Please input your Email or Phone!");
    }
    if (!passcode) {
      next.passcode = i18next.t("login:Please input your code!");
    }
    setErrors(next);
    if (Object.keys(next).length > 0) {return;}
    onFinish({passcode, countryCode, dest, enableMfaRemember});
  };

  return (
    <form onSubmit={submit} style={{width: "300px"}}>
      {isShowText() ? (
        <div className="mb-5 text-left">
          {isEmail() ? i18next.t("mfa:Your email is") : i18next.t("mfa:Your phone is")} {dest}
        </div>
      ) : (
        <p>{isEmail()
          ? i18next.t("mfa:Please bind your email first, the system will automatically uses the mail for multi-factor authentication")
          : i18next.t("mfa:Please bind your phone first, the system automatically uses the phone for multi-factor authentication")}
        </p>
      )}
      {!isShowText() && (
        <div className="flex w-[300px] mb-[30px] gap-0">
          {!isEmail() && (
            <CountryCodeSelect
              initValue={countryCode}
              onChange={(v) => setCountryCode(v)}
              style={{width: "30%"}}
              countryCodes={application.organizationObj?.countryCodes ?? ["US"]}
            />
          )}
          <div className="relative" style={{width: isEmail() ? "100%" : "70%"}}>
            <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
            <Input
              className="pl-9 w-full"
              value={dest}
              onChange={(e) => setDest(e.target.value)}
              placeholder={isEmail() ? i18next.t("general:Email") : i18next.t("general:Phone")}
            />
          </div>
        </div>
      )}
      {errors.dest && <p className="text-sm text-red-500 mt-1">{errors.dest}</p>}
      <SendCodeInput
        value={passcode}
        onChange={(v) => setPasscode(v)}
        countryCode={countryCode}
        method={method}
        onButtonClickArgs={[mfaProps.secret || dest, isEmail() ? "email" : "phone", Setting.getApplicationName(application)]}
        application={application}
      />
      {errors.passcode && <p className="text-sm text-red-500 mt-1">{errors.passcode}</p>}
      <div className="flex items-center gap-2 mt-3">
        <Checkbox id="sms-mfa-remember" checked={enableMfaRemember} onCheckedChange={(v) => setEnableMfaRemember(!!v)} />
        <label htmlFor="sms-mfa-remember" className="text-sm">
          {i18next.t("mfa:Remember this account for {hour} hours").replace("{hour}", mfaProps?.mfaRememberInHours)}
        </label>
      </div>
      <Button type="submit" className="mt-6 w-full">
        {i18next.t("forget:Next Step")}
      </Button>
    </form>
  );
};

export default MfaVerifySmsForm;
