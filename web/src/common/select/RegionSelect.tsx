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

import React from "react";
import * as Setting from "../../Setting";

interface RegionSelectProps {
  value?: string;
  defaultValue?: string;
  size?: string;
  onChange: (value: string) => void;
}

const RegionSelect = (props: RegionSelectProps) => {
  const {onChange} = props;
  const value = props.value !== undefined && props.value !== ""
    ? props.value
    : (props.defaultValue !== undefined && props.defaultValue !== "" ? props.defaultValue : "");

  const countryData = Setting.getCountryCodeData();

  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none"
    >
      <option value="" disabled className="bg-[#0a0a0a]">
        Please select country/region
      </option>
      {countryData
        .sort((a: any, b: any) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
        .map((item: any) => (
          <option key={item.code} value={item.code} className="bg-[#0a0a0a]">
            {`${item.name} (${item.code})`}
          </option>
        ))}
    </select>
  );
};

export default RegionSelect;
