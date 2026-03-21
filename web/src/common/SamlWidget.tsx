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

import React from "react";
import * as Setting from "../Setting";

interface SamlWidgetProps {
  user: any;
  application: any;
  providerItem: any;
  labelSpan: number;
}

const SamlWidget = (props: SamlWidgetProps) => {
  const {user, providerItem, labelSpan} = props;
  const provider = providerItem.provider;
  const name = user.name;

  return (
    <div className="flex items-start mt-5 gap-4">
      <div className="mt-1 min-w-0" style={{flex: `0 0 ${(labelSpan / 24) * 100}%`}}>
        <span className="flex items-center gap-1">
          {Setting.getProviderLogo(provider)}
          <span className="text-sm text-gray-400 ml-1">{`${provider.type}:`}</span>
        </span>
      </div>
      <div className="flex-1 mt-1">
        <span
          className="text-sm text-white inline-block"
          style={{
            width: labelSpan === 3 ? "300px" : "130px",
            display: Setting.isMobile() ? "inline" : "inline-block",
          }}
        >
          {name}
        </span>
      </div>
    </div>
  );
};

export default SamlWidget;
