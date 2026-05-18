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

export function renderFaceIdProviderFields(provider, updateProviderField) {
  return (
    <>
      {["Alibaba Cloud Facebody"].includes(provider.type) ? null : (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Endpoint (Intranet)"), i18next.t("provider:Region endpoint for Intranet"))} :
          </div>
          <div className="col-span-10">
            <div className="relative">
              <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input className="pl-9" value={provider.intranetEndpoint} onChange={e => {
                updateProviderField("intranetEndpoint", e.target.value);
              }} />
            </div>
          </div>
        </div>
      )}
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Endpoint"), i18next.t("provider:Region endpoint for Internet"))} :
        </div>
        <div className="col-span-10">
          <div className="relative">
            <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
            <Input className="pl-9" value={provider.endpoint} onChange={e => {
              updateProviderField("endpoint", e.target.value);
            }} />
          </div>
        </div>
      </div>
    </>
  );
}
