// @ts-nocheck
import {Button} from "../../components/ui/button";
import {Checkbox} from "../../components/ui/checkbox";
import {Input} from "../../components/ui/input";
import i18next from "i18next";
import React, {useState} from "react";
import {mfaAuth} from "./MfaVerifyForm";

export const MfaVerifyRadiusForm = ({mfaProps, application, onFinish, method, user}) => {
  const [dest, setDest] = useState("");
  const [passcode, setPasscode] = useState("");
  const [enableMfaRemember, setEnableMfaRemember] = useState(false);
  const [errors, setErrors] = useState({});

  const submit = (e) => {
    e.preventDefault();
    const next = {};
    if (method !== mfaAuth && !dest) {
      next.dest = i18next.t("login:Please input your RADIUS username!");
    }
    if (!passcode) {
      next.passcode = i18next.t("login:Please input your RADIUS password!");
    }
    setErrors(next);
    if (Object.keys(next).length > 0) {return;}
    onFinish({passcode, countryCode: mfaProps.countryCode, dest, enableMfaRemember});
  };

  return (
    <form onSubmit={submit} style={{width: "300px"}}>
      {method === mfaAuth ? null : (
        <div>
          <Input
            value={dest}
            onChange={(e) => setDest(e.target.value)}
            placeholder={i18next.t("signup:Username")}
            className="w-full"
          />
          {errors.dest && <p className="text-sm text-red-500 mt-1">{errors.dest}</p>}
        </div>
      )}
      <Input
        type="password"
        value={passcode}
        onChange={(e) => setPasscode(e.target.value)}
        placeholder={i18next.t("general:Password")}
        className="w-full mt-3"
      />
      {errors.passcode && <p className="text-sm text-red-500 mt-1">{errors.passcode}</p>}
      <div className="flex items-center gap-2 mt-3">
        <Checkbox id="radius-mfa-remember" checked={enableMfaRemember} onCheckedChange={(v) => setEnableMfaRemember(!!v)} />
        <label htmlFor="radius-mfa-remember" className="text-sm">
          {i18next.t("mfa:Remember this account for {hour} hours").replace("{hour}", mfaProps?.mfaRememberInHours)}
        </label>
      </div>
      <Button type="submit" className="mt-6 w-full">
        {i18next.t("forget:Next Step")}
      </Button>
    </form>
  );
};

export default MfaVerifyRadiusForm;
