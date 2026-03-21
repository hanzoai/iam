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
import * as OrganizationBackend from "../../backend/OrganizationBackend";
import * as Setting from "../../Setting";

interface OrganizationSelectProps {
  onChange?: (value: string) => void;
  initValue?: string;
  style?: React.CSSProperties;
  onSelect?: (value: string) => void;
  withAll?: boolean;
  className?: string;
  organizations?: any[];
}

const OrganizationSelect = (props: OrganizationSelectProps) => {
  const {onChange, initValue, style, onSelect, withAll, className} = props;
  const [organizations, setOrganizations] = React.useState<any[]>([]);
  const [value, setValue] = React.useState(initValue || "");

  React.useEffect(() => {
    if (props.organizations === undefined) {
      getOrganizations();
    }
    window.addEventListener("storageOrganizationsChanged", getOrganizations);
    return () => {
      window.removeEventListener("storageOrganizationsChanged", getOrganizations);
    };
  }, [value]);

  const getOrganizations = () => {
    OrganizationBackend.getOrganizationNames("admin")
      .then((res: any) => {
        if (res.status === "ok") {
          setOrganizations(res.data);
          const selectedValueExist = res.data.filter((org: any) => org.name === value).length > 0;
          if (initValue === undefined || !selectedValueExist) {
            const items = getOrganizationItems(res.data);
            handleOnChange(items.length > 0 ? items[0].value : "");
          }
        }
      });
  };

  const handleOnChange = (val: string) => {
    setValue(val);
    onChange?.(val);
  };

  const getOrganizationItems = (orgs?: any[]) => {
    const data = orgs || organizations;
    const items: Array<{label: string; value: string}> = [];

    data.forEach((org: any) => items.push(Setting.getOption(org.displayName, org.name)));

    if (withAll) {
      items.unshift({
        label: i18next.t("general:All"),
        value: "All",
      });
    }

    return items;
  };

  const items = getOrganizationItems();

  return (
    <select
      value={value}
      onChange={(e) => {
        handleOnChange(e.target.value);
        onSelect?.(e.target.value);
      }}
      style={style}
      className={`px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none ${className || ""}`}
    >
      {!value && (
        <option value="" disabled className="bg-[#0a0a0a]">
          {i18next.t("login:Please select an organization")}
        </option>
      )}
      {items.map((item) => (
        <option key={item.value} value={item.value} className="bg-[#0a0a0a]">
          {item.label}
        </option>
      ))}
    </select>
  );
};

export default OrganizationSelect;
