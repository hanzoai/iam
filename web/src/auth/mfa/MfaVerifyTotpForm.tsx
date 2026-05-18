// @ts-nocheck
import {Copy} from "lucide-react";
import {QRCodeSVG} from "qrcode.react";
import copy from "copy-to-clipboard";
import i18next from "i18next";
import React, {useState} from "react";
import {Button} from "../../components/ui/button";
import {Checkbox} from "../../components/ui/checkbox";
import {Input} from "../../components/ui/input";
import * as Setting from "../../Setting";

export const MfaVerifyTotpForm = ({mfaProps, onFinish}) => {
  const [passcode, setPasscode] = useState("");
  const [enableMfaRemember, setEnableMfaRemember] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = (value) => {
    if (!value || value.length < 6) {
      setError("Please input your passcode");
      return;
    }
    setError("");
    onFinish({passcode: value, enableMfaRemember});
  };

  const renderSecret = () => {
    if (!mfaProps.secret) {
      return null;
    }
    return (
      <React.Fragment>
        <div className="flex justify-center w-full">
          <QRCodeSVG value={mfaProps.url} level="H" />
        </div>
        <p className="text-center">{i18next.t("mfa:Scan the QR code with your Authenticator App")}</p>
        <p className="text-center">{i18next.t("mfa:Or copy the secret to your Authenticator App")}</p>
        <div className="w-full">
          <div className="flex items-center gap-2">
            <Input value={mfaProps.secret} readOnly />
            <Button type="button" size="icon" onClick={() => {
              copy(`${mfaProps.secret}`);
              Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
            }}>
              <Copy className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </React.Fragment>
    );
  };

  return (
    <form onSubmit={(e) => { e.preventDefault(); handleSubmit(passcode); }} style={{width: "300px"}}>
      {renderSecret()}
      <Input
        className="mt-6 tracking-[0.5em] text-center"
        value={passcode}
        maxLength={6}
        onChange={(e) => {
          const v = e.target.value.replace(/[^0-9]/g, "");
          setPasscode(v);
          setError("");
          if (v.length === 6) {
            handleSubmit(v);
          }
        }}
        placeholder="------"
      />
      {error && <p className="text-sm text-red-500 mt-1">{error}</p>}
      <div className="flex items-center gap-2 mt-3">
        <Checkbox id="totp-mfa-remember" checked={enableMfaRemember} onCheckedChange={(v) => setEnableMfaRemember(!!v)} />
        <label htmlFor="totp-mfa-remember" className="text-sm">
          {i18next.t("mfa:Remember this account for {hour} hours").replace("{hour}", mfaProps?.mfaRememberInHours)}
        </label>
      </div>
      <Button type="submit" className="mt-6 w-full">
        {i18next.t("forget:Next Step")}
      </Button>
    </form>
  );
};

export default MfaVerifyTotpForm;
