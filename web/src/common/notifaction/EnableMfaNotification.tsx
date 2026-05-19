// @ts-nocheck
import i18next from "i18next";
import {useEffect} from "react";
import {useHistory, useLocation} from "react-router-dom";
import {toast} from "sonner";
import {Button} from "../../components/ui/button";
import {Badge} from "../../components/ui/badge";
import * as Setting from "../../Setting";
import {MfaRulePrompted, MfaRuleRequired} from "../../Setting";

const EnableMfaNotification = ({account}) => {
  const history = useHistory();
  const location = useLocation();

  useEffect(() => {
    if (account === null) {
      return;
    }

    const mfaItems = Setting.getMfaItemsByRules(account, account?.organization, [MfaRuleRequired, MfaRulePrompted]);
    if (location.state?.from === "/login" && mfaItems.length !== 0) {
      if (mfaItems.some((item) => item.rule === MfaRuleRequired)) {
        openRequiredEnableNotification(mfaItems.find((item) => item.rule === MfaRuleRequired).name);
      } else {
        openPromptEnableNotification(mfaItems.filter((item) => item.rule === MfaRulePrompted)?.map((item) => item.name));
      }
    }
  }, [account, location.state?.from]);

  const openPromptEnableNotification = (mfaTypes) => {
    const id = toast(i18next.t("mfa:Enable multi-factor authentication"), {
      duration: Infinity,
      description: (
        <div className="flex flex-col gap-2">
          <span>
            {i18next.t("mfa:To ensure the security of your account, it is recommended that you enable multi-factor authentication")}
          </span>
          <div className="flex flex-wrap gap-1">
            {mfaTypes.map((item) => (
              <Badge
                key={item}
                variant="outline"
                className="border-orange-400 text-orange-600 bg-orange-50 dark:bg-orange-950"
              >
                {item}
              </Badge>
            ))}
          </div>
        </div>
      ),
      action: (
        <div className="flex gap-2 items-center">
          <Button variant="link" size="sm" onClick={() => toast.dismiss(id)}>
            {i18next.t("general:Later")}
          </Button>
          <Button
            size="sm"
            onClick={() => {
              history.push(`/mfa/setup?mfaType=${mfaTypes[0]}`, {from: "/"});
              toast.dismiss(id);
            }}
          >
            {i18next.t("general:Go to enable")}
          </Button>
        </div>
      ),
    });
  };

  const openRequiredEnableNotification = (mfaType) => {
    const id = toast(i18next.t("mfa:Enable multi-factor authentication"), {
      duration: Infinity,
      description: (
        <div className="flex flex-col gap-2">
          <span>
            {i18next.t("mfa:To ensure the security of your account, it is required to enable multi-factor authentication")}
          </span>
          <div className="flex flex-wrap gap-1">
            <Badge
              variant="outline"
              className="border-orange-400 text-orange-600 bg-orange-50 dark:bg-orange-950"
            >
              {mfaType}
            </Badge>
          </div>
        </div>
      ),
      action: (
        <Button size="sm" onClick={() => toast.dismiss(id)}>
          {i18next.t("general:Confirm")}
        </Button>
      ),
    });
  };

  return null;
};

export default EnableMfaNotification;
