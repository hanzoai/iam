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

import {CheckCircle, XCircle} from "lucide-react";
import i18next from "i18next";
import React from "react";

function isValidOption_AtLeast6(password: string) {
  if (password.length < 6) {
    return i18next.t("user:The password must have at least 6 characters");
  }
  return "";
}

function isValidOption_AtLeast8(password: string) {
  if (password.length < 8) {
    return i18next.t("user:The password must have at least 8 characters");
  }
  return "";
}

function isValidOption_Aa123(password: string) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).+$/;
  if (!regex.test(password)) {
    return i18next.t("user:The password must contain at least one uppercase letter, one lowercase letter and one digit");
  }
  return "";
}

function isValidOption_SpecialChar(password: string) {
  const regex = /^(?=.*[!-/:-@[-`{-~]).+$/;
  if (!regex.test(password)) {
    return i18next.t("user:The password must contain at least one special character");
  }
  return "";
}

function isValidOption_NoRepeat(password: string) {
  const regex = /(.)\1+/;
  if (regex.test(password)) {
    return i18next.t("user:The password must not contain any repeated characters");
  }
  return "";
}

const checkers: Record<string, (password: string) => string> = {
  AtLeast6: isValidOption_AtLeast6,
  AtLeast8: isValidOption_AtLeast8,
  Aa123: isValidOption_Aa123,
  SpecialChar: isValidOption_SpecialChar,
  NoRepeat: isValidOption_NoRepeat,
};

function getOptionDescription(option: string) {
  switch (option) {
  case "AtLeast6": return i18next.t("user:The password must have at least 6 characters");
  case "AtLeast8": return i18next.t("user:The password must have at least 8 characters");
  case "Aa123": return i18next.t("user:The password must contain at least one uppercase letter, one lowercase letter and one digit");
  case "SpecialChar": return i18next.t("user:The password must contain at least one special character");
  case "NoRepeat": return i18next.t("user:The password must not contain any repeated characters");
  }
}

export function renderPasswordPopover(options: string[], password: string) {
  return (
    <div className="w-full">
      {options.map((option, idx) => (
        <div key={idx} className="flex items-center gap-2 text-sm py-0.5">
          {checkers[option](password) === "" ? (
            <CheckCircle className="w-4 h-4 text-green-500 shrink-0" />
          ) : (
            <XCircle className="w-4 h-4 text-red-500 shrink-0" />
          )}
          <span className="text-gray-300">{getOptionDescription(option)}</span>
        </div>
      ))}
    </div>
  );
}

export function checkPasswordComplexity(password: string, options: string[]) {
  if (!password?.length) {
    return i18next.t("login:Please input your password!");
  }

  if (!options || options.length === 0) {
    return "";
  }

  for (const option of options) {
    const checkerFunc = checkers[option];
    if (checkerFunc) {
      const errorMsg = checkerFunc(password);
      if (errorMsg !== "") {
        return errorMsg;
      }
    }
  }
  return "";
}
