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

import React from "react";
import i18next from "i18next";
import * as Setting from "../../Setting";

export const CountryCodeSelect = (props: any) => {
  const {onChange, style, disabled, initValue, hasDefault} = props;
  const countryCodes = props.countryCodes ?? [];
  const [value, setValue] = React.useState("");

  React.useEffect(() => {
    if (initValue !== undefined) {
      setValue(initValue);
    } else {
      const init = countryCodes.length > 0 ? countryCodes[0] : "";
      handleOnChange(init);
    }
  }, []);

  const handleOnChange = (val: string) => {
    setValue(val);
    onChange?.(val);
  };

  const countryData = Setting.getCountryCodeData(countryCodes);

  return (
    <select
      style={style}
      disabled={disabled}
      value={value}
      onChange={(e) => handleOnChange(e.target.value)}
      className="px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none"
    >
      {hasDefault && (
        <option value="All" className="bg-[#0a0a0a]">
          {i18next.t("general:All")}
        </option>
      )}
      {countryData.map((country: any) => (
        <option key={country.code} value={country.code} className="bg-[#0a0a0a]">
          {country.name} (+{country.phone})
        </option>
      ))}
    </select>
  );
};
