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

import {Mail, Phone} from "lucide-react";
import i18next from "i18next";
import React from "react";
import * as Setting from "../../Setting";
import * as UserBackend from "../../backend/UserBackend";
import {SendCodeInput} from "../SendCodeInput";

export const ResetModal = (props: any) => {
  const [visible, setVisible] = React.useState(false);
  const [confirmLoading, setConfirmLoading] = React.useState(false);
  const [dest, setDest] = React.useState("");
  const [code, setCode] = React.useState("");
  const {buttonText, destType, application, countryCode} = props;

  const showModal = () => {
    setVisible(true);
  };

  const handleCancel = () => {
    setVisible(false);
  };

  const handleOk = () => {
    if (dest === "") {
      if (destType === "phone") {
        Setting.showMessage("error", i18next.t("user:Phone cannot be empty"));
      } else {
        Setting.showMessage("error", i18next.t("user:Email cannot be empty"));
      }
      return;
    }
    if (code === "") {
      Setting.showMessage("error", i18next.t("code:Empty code"));
      return;
    }
    setConfirmLoading(true);
    UserBackend.resetEmailOrPhone(dest, destType, code).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("user:Email/phone reset successfully"));
        window.location.reload();
      } else {
        Setting.showMessage("error", i18next.t("user:" + res.msg));
        setConfirmLoading(false);
      }
    });
  };

  let placeholder = "";
  if (destType === "email") {
    placeholder = i18next.t("user:Input your email");
  } else if (destType === "phone") {
    placeholder = i18next.t("user:Input your phone number");
  }

  return (
    <div>
      <button
        onClick={showModal}
        className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors"
      >
        {buttonText}
      </button>
      {visible && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[600px]">
            <h2 className="text-lg font-semibold text-white mb-4">{buttonText}</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">
                  {destType === "email" ? i18next.t("user:New Email") : i18next.t("user:New phone")}
                </label>
                <div className="flex items-center border border-white/20 rounded-lg bg-transparent px-3 py-2">
                  {destType === "email" ? (
                    <Mail className="w-4 h-4 text-gray-400 mr-2" />
                  ) : (
                    <React.Fragment>
                      <Phone className="w-4 h-4 text-gray-400 mr-2" />
                      {countryCode !== "" && <span className="text-gray-400 mr-1">+{Setting.getCountryCode(countryCode)}</span>}
                    </React.Fragment>
                  )}
                  <input
                    placeholder={placeholder}
                    onChange={e => setDest(e.target.value)}
                    className="bg-transparent text-white outline-none flex-1 text-sm"
                  />
                </div>
              </div>
              <div>
                <SendCodeInput
                  textBefore={i18next.t("code:Code you received")}
                  onChange={setCode}
                  method={"reset"}
                  onButtonClickArgs={[dest, destType, Setting.getApplicationName(application)]}
                  application={application}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={handleCancel} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">
                {i18next.t("general:Cancel")}
              </button>
              <button
                onClick={handleOk}
                disabled={confirmLoading}
                className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
              >
                {confirmLoading ? "..." : buttonText}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ResetModal;
