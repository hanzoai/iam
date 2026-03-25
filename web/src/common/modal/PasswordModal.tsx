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

import i18next from "i18next";
import React from "react";
import * as UserBackend from "../../backend/UserBackend";
import * as Setting from "../../Setting";
import * as PasswordChecker from "../PasswordChecker";
import * as Obfuscator from "../../auth/Obfuscator";

export const PasswordModal = (props: any) => {
  const [visible, setVisible] = React.useState(false);
  const [confirmLoading, setConfirmLoading] = React.useState(false);
  const [oldPassword, setOldPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [rePassword, setRePassword] = React.useState("");
  const {user, userName, organization, account} = props;

  const [passwordOptions, setPasswordOptions] = React.useState<string[]>([]);
  const [newPasswordValid, setNewPasswordValid] = React.useState(false);
  const [rePasswordValid, setRePasswordValid] = React.useState(false);
  const [newPasswordErrorMessage, setNewPasswordErrorMessage] = React.useState("");
  const [rePasswordErrorMessage, setRePasswordErrorMessage] = React.useState("");
  const [passwordPopoverOpen, setPasswordPopoverOpen] = React.useState(false);

  React.useEffect(() => {
    if (organization) {
      setPasswordOptions(organization.passwordOptions);
    }
  }, [user.owner]);

  const showModal = () => {
    setVisible(true);
  };

  const handleCancel = () => {
    setVisible(false);
  };

  const handleNewPassword = (value: string) => {
    setNewPassword(value);
    const errorMessage = PasswordChecker.checkPasswordComplexity(value, passwordOptions);
    setNewPasswordValid(errorMessage === "");
    setNewPasswordErrorMessage(errorMessage);
  };

  const handleRePassword = (value: string) => {
    setRePassword(value);
    if (value !== newPassword) {
      setRePasswordErrorMessage(i18next.t("signup:Your confirmed password is inconsistent with the password!"));
      setRePasswordValid(false);
    } else {
      setRePasswordValid(true);
    }
  };

  const handleOk = () => {
    if (newPassword === "" || rePassword === "") {
      Setting.showMessage("error", i18next.t("user:Empty input!"));
      return;
    }
    if (newPassword !== rePassword) {
      Setting.showMessage("error", i18next.t("user:Two passwords you typed do not match."));
      return;
    }
    setConfirmLoading(true);

    if (organization === null) {
      Setting.showMessage("error", i18next.t("general:Organization is null"));
      setConfirmLoading(false);
      return;
    }

    const errorMsg = PasswordChecker.checkPasswordComplexity(newPassword, organization.passwordOptions);
    if (errorMsg !== "") {
      Setting.showMessage("error", errorMsg);
      setConfirmLoading(false);
      return;
    }

    let encryptedOldPassword = oldPassword;
    let encryptedNewPassword = newPassword;

    if (organization.passwordObfuscatorType && organization.passwordObfuscatorType !== "Plain") {
      const [oldPasswordCipher, oldPasswordError] = Obfuscator.encryptByPasswordObfuscator(
        organization.passwordObfuscatorType,
        organization.passwordObfuscatorKey,
        oldPassword
      );
      if (oldPasswordError) {
        Setting.showMessage("error", oldPasswordError);
        setConfirmLoading(false);
        return;
      }
      encryptedOldPassword = oldPasswordCipher;

      const [newPasswordCipher, newPasswordError] = Obfuscator.encryptByPasswordObfuscator(
        organization.passwordObfuscatorType,
        organization.passwordObfuscatorKey,
        newPassword
      );
      if (newPasswordError) {
        Setting.showMessage("error", newPasswordError);
        setConfirmLoading(false);
        return;
      }
      encryptedNewPassword = newPasswordCipher;
    }

    UserBackend.setPassword(user.owner, userName, encryptedOldPassword, encryptedNewPassword)
      .then((res: any) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("user:Password set successfully"));
          setVisible(false);
          if (account.owner === user.owner && account.name === userName) {
            account.needUpdatePassword = false;
          }
        } else {
          Setting.showMessage("error", i18next.t(`user:${res.msg}`));
        }
      })
      .finally(() => {
        setConfirmLoading(false);
      });
  };

  const hasOldPassword = (user.password !== "" || user.ldap !== "");

  return (
    <div>
      <button
        onClick={showModal}
        disabled={props.disabled}
        className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
      >
        {hasOldPassword ? i18next.t("user:Modify password...") : i18next.t("user:Set password...")}
      </button>
      {visible && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[600px]">
            <h2 className="text-lg font-semibold text-white mb-4">{i18next.t("general:Password")}</h2>
            <div className="space-y-4">
              {(hasOldPassword && !Setting.isLocalAdminUser(account)) && (
                <div>
                  <label className="block text-sm text-gray-400 mb-1">{i18next.t("user:Old Password")}</label>
                  <input
                    type="password"
                    placeholder={i18next.t("user:input password")}
                    onChange={(e) => setOldPassword(e.target.value)}
                    className="w-full px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none focus:border-white/40"
                  />
                </div>
              )}
              <div className="relative">
                <label className="block text-sm text-gray-400 mb-1">{i18next.t("user:New Password")}</label>
                <input
                  type="password"
                  placeholder={i18next.t("user:input password")}
                  onChange={(e) => {
                    handleNewPassword(e.target.value);
                    setPasswordPopoverOpen(passwordOptions?.length > 0);
                  }}
                  onFocus={() => {
                    setPasswordPopoverOpen(passwordOptions?.length > 0);
                  }}
                  onBlur={() => {
                    setPasswordPopoverOpen(false);
                  }}
                  className={`w-full px-3 py-2 text-sm bg-transparent border rounded-lg text-white outline-none focus:border-white/40 ${
                    !newPasswordValid && newPasswordErrorMessage ? "border-red-500" : "border-white/20"
                  }`}
                />
                {passwordPopoverOpen && passwordOptions?.length > 0 && (
                  <div className="absolute z-10 top-full mt-1 right-0 bg-[#1a1a1a] border border-white/10 rounded-lg p-3 text-sm shadow-lg">
                    {PasswordChecker.renderPasswordPopover(passwordOptions, newPassword)}
                  </div>
                )}
                {!newPasswordValid && newPasswordErrorMessage && (
                  <div className="text-red-500 text-xs mt-1">{newPasswordErrorMessage}</div>
                )}
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">{i18next.t("user:Re-enter New")}</label>
                <input
                  type="password"
                  placeholder={i18next.t("user:input password")}
                  onChange={(e) => handleRePassword(e.target.value)}
                  className={`w-full px-3 py-2 text-sm bg-transparent border rounded-lg text-white outline-none focus:border-white/40 ${
                    !rePasswordValid && rePasswordErrorMessage ? "border-red-500" : "border-white/20"
                  }`}
                />
                {!rePasswordValid && rePasswordErrorMessage && (
                  <div className="text-red-500 text-xs mt-1">{rePasswordErrorMessage}</div>
                )}
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
                {confirmLoading ? "..." : i18next.t("user:Set Password")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PasswordModal;
