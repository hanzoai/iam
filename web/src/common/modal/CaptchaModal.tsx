// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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

import {ShieldCheck} from "lucide-react";
import i18next from "i18next";
import React, {useEffect} from "react";
import * as UserBackend from "../../backend/UserBackend";
import {CaptchaWidget} from "../CaptchaWidget";

export const CaptchaModal = (props: any) => {
  const {owner, name, visible, onOk, onUpdateToken, onCancel, isCurrentProvider, noModal, innerRef} = props;

  const [captchaType, setCaptchaType] = React.useState("none");
  const [clientId, setClientId] = React.useState("");
  const [clientSecret, setClientSecret] = React.useState("");
  const [subType, setSubType] = React.useState("");
  const [clientId2, setClientId2] = React.useState("");
  const [clientSecret2, setClientSecret2] = React.useState("");

  const [open, setOpen] = React.useState(false);
  const [captchaImg, setCaptchaImg] = React.useState("");
  const [captchaToken, setCaptchaToken] = React.useState("");

  const defaultInputRef = React.useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (visible || noModal) {
      loadCaptcha();
    } else {
      handleCancel();
      setOpen(false);
    }
  }, [visible, noModal]);

  useEffect(() => {
    if (captchaToken !== "" && captchaType !== "Default" && !noModal) {
      handleOk();
    }
  }, [captchaToken]);

  const handleOk = () => {
    onOk?.(captchaType, captchaToken, clientSecret);
  };

  const handleCancel = () => {
    setCaptchaToken("");
    onCancel?.();
  };

  useEffect(() => {
    if (innerRef) {
      innerRef.current = {
        loadCaptcha: loadCaptcha,
      };
    }
  }, [innerRef]);

  const loadCaptcha = () => {
    UserBackend.getCaptcha(owner, name, isCurrentProvider).then((res: any) => {
      if (res.type === "none") {
        handleOk();
      } else if (res.type === "Default") {
        setOpen(true);
        setClientSecret(res.captchaId);
        setCaptchaImg(res.captchaImage);
        setCaptchaType("Default");
      } else {
        setOpen(true);
        setCaptchaType(res.type);
        setClientId(res.clientId);
        setClientSecret(res.clientSecret);
        setSubType(res.subType);
        setClientId2(res.clientId2);
        setClientSecret2(res.clientSecret2);
      }
    });
  };

  const renderDefaultCaptcha = () => {
    if (noModal) {
      return (
        <div className="flex items-center gap-2 text-center">
          <div className="flex-[70%]">
            <div className="flex items-center border border-white/20 rounded-lg bg-transparent px-3 py-2">
              <ShieldCheck className="w-4 h-4 text-gray-400 mr-2" />
              <input
                ref={defaultInputRef}
                value={captchaToken}
                placeholder={i18next.t("general:Captcha")}
                className="bg-transparent text-white outline-none flex-1 text-sm"
                onChange={(e) => onChange(e.target.value)}
              />
            </div>
          </div>
          <div className="flex-[30%]">
            <img
              src={`data:image/png;base64,${captchaImg}`}
              onClick={loadCaptcha}
              className="rounded border border-white/20 mb-5 w-full cursor-pointer"
              alt="captcha"
            />
          </div>
        </div>
      );
    }
    return (
      <div className="text-center">
        <div className="inline-block">
          <div
            className="h-20 w-[200px] rounded border border-white/20 mb-5 bg-no-repeat"
            style={{backgroundImage: `url('data:image/png;base64,${captchaImg}')`}}
          />
          <div>
            <div className="flex items-center border border-white/20 rounded-lg bg-transparent px-3 py-2 w-[200px]">
              <ShieldCheck className="w-4 h-4 text-gray-400 mr-2" />
              <input
                ref={defaultInputRef}
                value={captchaToken}
                placeholder={i18next.t("general:Captcha")}
                className="bg-transparent text-white outline-none flex-1 text-sm"
                onKeyDown={(e) => e.key === "Enter" && handleOk()}
                onChange={(e) => setCaptchaToken(e.target.value)}
              />
            </div>
          </div>
        </div>
      </div>
    );
  };

  const onChange = (token: string) => {
    setCaptchaToken(token);
    if (noModal) {
      onUpdateToken?.(captchaType, token, clientSecret);
    }
  };

  const renderCaptcha = () => {
    if (captchaType === "Default") {
      return renderDefaultCaptcha();
    } else {
      return (
        <div className="flex justify-center">
          <CaptchaWidget
            captchaType={captchaType}
            subType={subType}
            siteKey={clientId}
            clientSecret={clientSecret}
            onChange={onChange}
            clientId2={clientId2}
            clientSecret2={clientSecret2}
          />
        </div>
      );
    }
  };

  if (noModal) {
    return renderCaptcha();
  }

  if (!open) {
    return null;
  }

  const isOkDisabled = captchaType === "Default" && !/^\d{5}$/.test(captchaToken);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
      <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[350px]">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">{i18next.t("general:Captcha")}</h2>
          <button onClick={handleCancel} className="text-gray-400 hover:text-white">
            &times;
          </button>
        </div>
        <div className="mt-5 mb-12">
          {renderCaptcha()}
        </div>
        {captchaType === "Default" && (
          <div className="flex justify-end gap-2 mt-6">
            <button
              onClick={handleOk}
              disabled={isOkDisabled}
              className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {i18next.t("general:OK")}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export const CaptchaRule = {
  Always: "Always",
  Never: "Never",
  Dynamic: "Dynamic",
  InternetOnly: "Internet-Only",
};
