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

import React, {useEffect, useState} from "react";
import i18next from "i18next";
import * as UserBackend from "../../backend/UserBackend";
import * as Setting from "../../Setting";

interface AffiliationSelectProps {
  application: any;
  user: any;
  labelSpan: number;
  onUpdateUserField: (key: string, value: any) => void;
}

const AffiliationSelect = (props: AffiliationSelectProps) => {
  const {application, user, labelSpan, onUpdateUserField} = props;
  const [addressOptions, setAddressOptions] = useState<any[]>([]);
  const [affiliationOptions, setAffiliationOptions] = useState<any[]>([]);

  useEffect(() => {
    getAddressOptions(application);
    getAffiliationOptions(application, user);
  }, []);

  const getAddressOptions = (app: any) => {
    if (app.affiliationUrl === "") {
      return;
    }
    const addressUrl = app.affiliationUrl.split("|")[0];
    UserBackend.getAddressOptions(addressUrl)
      .then((opts: any) => {
        setAddressOptions(opts);
      });
  };

  const getAffiliationOptions = (app: any, u: any) => {
    if (app.affiliationUrl === "") {
      return;
    }
    if (!u.address || u.address.length === 0) {
      return;
    }
    const affiliationUrl = app.affiliationUrl.split("|")[1];
    const code = u.address[u.address.length - 1];
    UserBackend.getAffiliationOptions(affiliationUrl, code)
      .then((opts: any) => {
        setAffiliationOptions(opts);
      });
  };

  const updateUserField = (key: string, value: any) => {
    onUpdateUserField(key, value);
  };

  // Render cascader options as nested selects for address
  const renderAddressSelects = () => {
    if (application?.affiliationUrl === "" || addressOptions.length === 0) {
      return null;
    }

    return (
      <div className="flex items-start mt-5 gap-4">
        <div className="mt-1 min-w-0" style={{flex: `0 0 ${(labelSpan / 24) * 100}%`}}>
          <span className="text-sm text-gray-400">
            {Setting.getLabel(i18next.t("user:Address"), i18next.t("user:Address - Tooltip"))} :
          </span>
        </div>
        <div className="flex-1">
          <select
            className="w-full max-w-[400px] px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none"
            value={user.address?.[user.address.length - 1] || ""}
            onChange={(e) => {
              updateUserField("address", [e.target.value]);
              updateUserField("affiliation", "");
              updateUserField("score", 0);
              getAffiliationOptions(application, {...user, address: [e.target.value]});
            }}
          >
            <option value="" disabled className="bg-[#0a0a0a]">
              {i18next.t("signup:Please input your address!")}
            </option>
            {addressOptions.map((opt: any, idx: number) => (
              <option key={idx} value={opt.value} className="bg-[#0a0a0a]">
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    );
  };

  return (
    <React.Fragment>
      {renderAddressSelects()}
      <div className="flex items-start mt-5 gap-4">
        <div className="mt-1 min-w-0" style={{flex: `0 0 ${(labelSpan / 24) * 100}%`}}>
          <span className="text-sm text-gray-400">
            {Setting.getLabel(i18next.t("user:Affiliation"), i18next.t("user:Affiliation - Tooltip"))} :
          </span>
        </div>
        <div className="flex-1">
          {application?.affiliationUrl === "" ? (
            <input
              value={user.affiliation || ""}
              onChange={(e) => updateUserField("affiliation", e.target.value)}
              className="w-full px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none focus:border-white/40"
            />
          ) : (
            <select
              className="w-full px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none"
              value={user.affiliation || ""}
              onChange={(e) => {
                const name = e.target.value;
                const affiliationOption = Setting.getArrayItem(affiliationOptions, "name", name);
                const id = affiliationOption?.id;
                updateUserField("affiliation", name);
                updateUserField("score", id);
              }}
            >
              <option value="" className="bg-[#0a0a0a]">({i18next.t("general:empty")})</option>
              {affiliationOptions.map((opt: any) => (
                <option key={opt.name} value={opt.name} className="bg-[#0a0a0a]">
                  {opt.name}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>
    </React.Fragment>
  );
};

export default AffiliationSelect;
