// @ts-nocheck
import {Loader2} from "lucide-react";
import {Button} from "../../components/ui/button";
import i18next from "i18next";
import React, {useState} from "react";
import * as MfaBackend from "../../backend/MfaBackend";

export function MfaEnableForm({user, mfaType, secret, recoveryCodes, dest, countryCode, onSuccess, onFail}) {
  const [loading, setLoading] = useState(false);
  const requestEnableMfa = () => {
    const data = {
      mfaType,
      secret,
      dest,
      countryCode,
      ...user,
    };
    data["recoveryCodes"] = recoveryCodes[0];
    setLoading(true);
    MfaBackend.MfaSetupEnable(data).then(res => {
      if (res.status === "ok") {
        onSuccess(res);
      } else {
        onFail(res);
      }
    }
    ).finally(() => {
      setLoading(false);
    });
  };

  return (
    <div style={{width: "400px"}}>
      <p>{i18next.t("mfa:Please save this recovery code. Once your device cannot provide an authentication code, you can reset mfa authentication by this recovery code")}</p>
      <br />
      <code className="not-italic">{recoveryCodes[0]}</code>
      <Button className="mt-6 w-full" disabled={loading} onClick={() => {
        requestEnableMfa();
      }}>
        {loading && <Loader2 className="w-4 h-4 animate-spin mr-2" />}
        {i18next.t("general:Enable")}
      </Button>
    </div>
  );
}

export default MfaEnableForm;
