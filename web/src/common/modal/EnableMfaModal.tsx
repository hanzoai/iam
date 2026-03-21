// Copyright 2023 The Hanzo Authors. All Rights Reserved.
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

import i18next from "i18next";
import React, {useEffect, useState} from "react";
import {EmailMfaType} from "../../auth/MfaSetupPage";
import * as MfaBackend from "../../backend/MfaBackend";
import * as Setting from "../../Setting";

const EnableMfaModal = ({user, mfaType, onSuccess}: any) => {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !user) {
      return;
    }
    MfaBackend.MfaSetupInitiate({
      mfaType,
      ...user,
    }).then((res: any) => {
      if (res.status === "error") {
        Setting.showMessage("error", i18next.t("mfa:Failed to initiate MFA"));
      }
    });
  }, [open]);

  const handleOk = () => {
    setLoading(true);
    MfaBackend.MfaSetupEnable({
      mfaType,
      ...user,
    }).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Enabled successfully"));
        setOpen(false);
        onSuccess();
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to enable")}: ${res.msg}`);
      }
    }).finally(() => {
      setLoading(false);
    });
  };

  const handleCancel = () => {
    setOpen(false);
  };

  const showModal = () => {
    if (!isValid()) {
      if (mfaType === EmailMfaType) {
        Setting.showMessage("error", i18next.t("login:Please input your Email!"));
      } else {
        Setting.showMessage("error", i18next.t("signup:Please input your phone number!"));
      }
      return;
    }
    setOpen(true);
  };

  const renderText = () => {
    return (
      <p className="text-gray-300 text-sm">
        {i18next.t("mfa:Please confirm the information below")}<br />
        <b className="text-white">{i18next.t("general:User")}</b>: {`${user.owner}/${user.name}`}<br />
        {mfaType === EmailMfaType ?
          <><b className="text-white">{i18next.t("general:Email")}</b> : {user.email}</> :
          <><b className="text-white">{i18next.t("general:Phone")}</b> : {user.phone}</>}
      </p>
    );
  };

  const isValid = () => {
    if (mfaType === EmailMfaType) {
      return user.email !== "";
    } else {
      return user.phone !== "";
    }
  };

  return (
    <React.Fragment>
      <button
        onClick={showModal}
        className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors"
      >
        {i18next.t("general:Enable")}
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 max-w-md w-full">
            <h2 className="text-lg font-semibold text-white mb-4">
              {i18next.t("mfa:Enable multi-factor authentication")}
            </h2>
            {renderText()}
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={handleCancel} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">
                {i18next.t("general:Cancel")}
              </button>
              <button
                onClick={handleOk}
                disabled={loading}
                className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
              >
                {loading ? "..." : i18next.t("general:OK")}
              </button>
            </div>
          </div>
        </div>
      )}
    </React.Fragment>
  );
};

export default EnableMfaModal;
