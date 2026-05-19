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
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "../components/ui/select";
import * as Setting from "../Setting";
import i18next from "i18next";

export function renderPaymentProviderFields(provider, updateProviderField, certs) {
  return (
    <React.Fragment>
      {
        (provider.type === "Alipay" || provider.type === "WeChat Pay" || provider.type === "Hanzo IAM") ? (
          <div className="grid grid-cols-12 gap-4 items-center mt-5">
            <div className="col-span-12 md:col-span-2 mt-1">
              {Setting.getLabel(i18next.t("general:Cert"), i18next.t("general:Cert - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-10">
              <Select value={provider.cert} onValueChange={(value) => {updateProviderField("cert", value);}}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {certs.map((cert, index) => <SelectItem key={index} value={cert.name}>{cert.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
        ) : null
      }
      {
        (provider.type === "Alipay") ? (
          <div className="grid grid-cols-12 gap-4 items-center mt-5">
            <div className="col-span-12 md:col-span-2 mt-1">
              {Setting.getLabel(i18next.t("general:Root cert"), i18next.t("general:Root cert - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-10">
              <Select value={provider.metadata} onValueChange={(value) => {updateProviderField("metadata", value);}}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {certs.map((cert, index) => <SelectItem key={index} value={cert.name}>{cert.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
        ) : null
      }
      {(provider.type === "GC" || provider.type === "FastSpring") ? (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Host"), i18next.t("provider:Host - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <div className="relative">
              <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input className="pl-9" value={provider.host} onChange={e => {
                updateProviderField("host", e.target.value);
              }} />
            </div>
          </div>
        </div>
      ) : null}
    </React.Fragment>
  );
}
