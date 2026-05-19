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
import {Link} from "lucide-react";
import {Input} from "../components/ui/input";
import * as Setting from "../Setting";
import i18next from "i18next";

export function renderMfaProviderFields(provider, updateProviderField) {
  return (
    <React.Fragment>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Host"), i18next.t("provider:Host - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <div className="relative">
            <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
            <Input className="pl-9" value={provider.host} placeholder="10.10.10.10" onChange={e => {
              updateProviderField("host", e.target.value);
            }} />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Port"), i18next.t("provider:Port - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Input
            type="number"
            className="w-40"
            value={provider.port ?? ""}
            onChange={e => {
              const v = e.target.value;
              updateProviderField("port", v === "" ? null : Number(v));
            }}
          />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Client secret"), i18next.t("provider:RADIUS Shared Secret - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Input value={provider.clientSecret} placeholder="Shared secret" onChange={e => {
            updateProviderField("clientSecret", e.target.value);
          }} />
        </div>
      </div>
    </React.Fragment>
  );
}
