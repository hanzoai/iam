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
import {Button} from "../components/ui/button";
import {Input} from "../components/ui/input";
import {Textarea} from "../components/ui/textarea";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "../components/ui/select";
import * as Setting from "../Setting";
import i18next from "i18next";
import * as ProviderNotification from "../common/TestNotificationWidget";

export function renderNotificationProviderFields(provider, updateProviderField, getReceiverRow) {
  return (
    <React.Fragment>
      {["CUCloud"].includes(provider.type) ? (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-2 mt-1">
            {["Hanzo IAM"].includes(provider.type) ?
              Setting.getLabel(i18next.t("general:Application"), i18next.t("general:Application - Tooltip")) :
              Setting.getLabel(i18next.t("provider:Region ID"), i18next.t("provider:Region ID - Tooltip"))} :
          </div>
          <div className="col-span-10">
            <Input value={provider.regionId} onChange={e => {
              updateProviderField("regionId", e.target.value);
            }} />
          </div>
        </div>
      ) : null}
      {["Custom HTTP"].includes(provider.type) ? (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("general:Method"), i18next.t("provider:Method - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <Select value={provider.method} onValueChange={value => {
              updateProviderField("method", value);
            }}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[
                  {id: "GET", name: "GET"},
                  {id: "POST", name: "POST"},
                ].map((method, index) => <SelectItem key={index} value={method.id}>{method.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>
      ) : null}
      {["Custom HTTP", "CUCloud"].includes(provider.type) ? (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Parameter"), i18next.t("provider:Parameter - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <Input value={provider.title} onChange={e => {
              updateProviderField("title", e.target.value);
            }} />
          </div>
        </div>
      ) : null}
      {["Google Chat", "CUCloud"].includes(provider.type) ? (
        <div className="grid grid-cols-12 gap-4 items-start mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Metadata"), i18next.t("provider:Metadata - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <Textarea rows={4} value={provider.metadata} onChange={e => {
              updateProviderField("metadata", e.target.value);
            }} />
          </div>
        </div>
      ) : null}
      <div className="grid grid-cols-12 gap-4 items-start mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Content"), i18next.t("provider:Content - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Textarea rows={3} value={provider.content} onChange={e => {
            updateProviderField("content", e.target.value);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        {getReceiverRow(provider)}
        <Button
          className="ml-2"
          onClick={() => ProviderNotification.sendTestNotification(provider)}
        >
          {i18next.t("provider:Send Testing Notification")}
        </Button>
      </div>
    </React.Fragment>
  );
}
