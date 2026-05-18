// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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

// @ts-nocheck
import React from "react";
import * as Setting from "../Setting";
import i18next from "i18next";
import {CaptchaPreview} from "../common/CaptchaPreview";

export function renderCaptchaProviderFields(provider, providerName) {
  return (
    <div className="grid grid-cols-12 gap-4 items-start mt-5">
      <div className="col-span-12 md:col-span-2 mt-1">
        {Setting.getLabel(i18next.t("general:Preview"), i18next.t("general:Preview - Tooltip"))} :
      </div>
      <div className="col-span-12 md:col-span-10">
        <CaptchaPreview
          owner={provider.owner}
          name={provider.name}
          provider={provider}
          providerName={providerName}
          captchaType={provider.type}
          subType={provider.subType}
          clientId={provider.clientId}
          clientSecret={provider.clientSecret}
          clientId2={provider.clientId2}
          clientSecret2={provider.clientSecret2}
          providerUrl={provider.providerUrl}
        />
      </div>
    </div>
  );
}
