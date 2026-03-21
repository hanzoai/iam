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

import {ShieldCheck, Loader2} from "lucide-react";
import React from "react";
import i18next from "i18next";
import * as UserBackend from "../backend/UserBackend";
import * as Setting from "../Setting";
import {CaptchaModal} from "./modal/CaptchaModal";

interface SendCodeInputProps {
  value?: string;
  disabled?: boolean;
  captchaValue?: any;
  useInlineCaptcha?: boolean;
  textBefore?: string;
  onChange: (value: string) => void;
  onButtonClickArgs: any[];
  application: any;
  method: string;
  countryCode?: string;
  refreshCaptcha?: () => void;
}

export const SendCodeInput = ({value, disabled, captchaValue, useInlineCaptcha, textBefore, onChange, onButtonClickArgs, application, method, countryCode, refreshCaptcha}: SendCodeInputProps) => {
  const [visible, setVisible] = React.useState(false);
  const [buttonLeftTime, setButtonLeftTime] = React.useState(0);
  const [buttonLoading, setButtonLoading] = React.useState(false);

  const getCodeResendTimeout = () => {
    return (application && application.codeResendTimeout > 0) ? application.codeResendTimeout : 60;
  };

  const handleCountDown = (leftTime = getCodeResendTimeout()) => {
    let leftTimeSecond = leftTime;
    setButtonLeftTime(leftTimeSecond);
    const countDown = () => {
      leftTimeSecond--;
      setButtonLeftTime(leftTimeSecond);
      if (leftTimeSecond === 0) {
        return;
      }
      setTimeout(countDown, 1000);
    };
    setTimeout(countDown, 1000);
  };

  const handleOk = (captchaType: string, captchaToken: string, clintSecret: string) => {
    setVisible(false);
    setButtonLoading(true);
    UserBackend.sendCode(captchaType, captchaToken, clintSecret, method, countryCode, ...onButtonClickArgs).then((res: any) => {
      setButtonLoading(false);
      if (res) {
        handleCountDown(getCodeResendTimeout());
      } else {
        if (useInlineCaptcha) {
          refreshCaptcha?.();
        }
      }
    }).catch(() => {
      setButtonLoading(false);
      if (useInlineCaptcha) {
        refreshCaptcha?.();
      }
    });
  };

  const handleCancel = () => {
    setVisible(false);
  };

  const handleSearch = () => {
    if (!useInlineCaptcha) {
      setVisible(true);
      return;
    }

    if (!captchaValue?.captchaType || !captchaValue?.captchaToken) {
      Setting.showMessage("error", i18next.t("general:Please complete the captcha correctly"));
      return;
    }
    handleOk(captchaValue.captchaType, captchaValue.captchaToken, captchaValue.clientSecret);
  };

  return (
    <React.Fragment>
      <div className="flex items-stretch">
        {textBefore && (
          <span className="inline-flex items-center px-3 text-sm text-gray-400 bg-white/5 border border-r-0 border-white/20 rounded-l-lg">
            {textBefore}
          </span>
        )}
        <div className={`flex items-center flex-1 border border-white/20 bg-transparent px-3 py-2 ${textBefore ? "" : "rounded-l-lg"}`}>
          <ShieldCheck className="w-4 h-4 text-gray-400 mr-2 shrink-0" />
          <input
            disabled={disabled}
            value={value || ""}
            placeholder={i18next.t("code:Enter your code")}
            className="bg-transparent text-white outline-none flex-1 text-sm min-w-0"
            onChange={e => onChange(e.target.value)}
            autoComplete="one-time-code"
          />
        </div>
        <button
          type="button"
          disabled={disabled || buttonLeftTime > 0 || buttonLoading}
          onClick={handleSearch}
          className="px-4 py-2 text-sm bg-white text-black rounded-r-lg hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap flex items-center gap-1"
        >
          {buttonLoading && <Loader2 className="w-3 h-3 animate-spin" />}
          {buttonLeftTime > 0 ? `${buttonLeftTime} s` : buttonLoading ? i18next.t("code:Sending") : i18next.t("code:Send Code")}
        </button>
      </div>
      {useInlineCaptcha ? null : (
        <CaptchaModal
          owner={application.owner}
          name={application.name}
          visible={visible}
          onOk={handleOk}
          onCancel={handleCancel}
          isCurrentProvider={false}
        />
      )}
    </React.Fragment>
  );
};
