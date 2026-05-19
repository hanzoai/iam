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
import {Button} from "../components/ui/button";
import {Input} from "../components/ui/input";
import {Switch} from "../components/ui/switch";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "../components/ui/select";
import * as Setting from "../Setting";
import i18next from "i18next";
import * as ProviderEditTestSms from "../common/TestSmsWidget";
import {CountryCodeSelect} from "../common/select/CountryCodeSelect";
import HttpHeaderTable from "../table/HttpHeaderTable";

const SMS_PROVIDERS_WITHOUT_SIGN_NAME = ["Custom HTTP SMS", "Twilio SMS", "Amazon SNS", "Msg91 SMS", "Infobip SMS"];
const SMS_PROVIDERS_WITHOUT_TEMPLATE_CODE = ["Infobip SMS", "Custom HTTP SMS"];

export function renderSmsProviderFields(provider, updateProviderField, renderSmsMappingInput, account) {
  return (
    <React.Fragment>
      {SMS_PROVIDERS_WITHOUT_SIGN_NAME.includes(provider.type) ?
        null :
        (<div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Sign Name"), i18next.t("provider:Sign Name - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <Input value={provider.signName} onChange={e => {
              updateProviderField("signName", e.target.value);
            }} />
          </div>
        </div>
        )
      }
      {SMS_PROVIDERS_WITHOUT_TEMPLATE_CODE.includes(provider.type) ?
        null :
        (<div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Template code"), i18next.t("provider:Template code - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <Input value={provider.templateCode} onChange={e => {
              updateProviderField("templateCode", e.target.value);
            }} />
          </div>
        </div>
        )
      }
      {
        provider.type === "Custom HTTP SMS" ? (
          <React.Fragment>
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
                      {id: "PUT", name: "PUT"},
                      {id: "DELETE", name: "DELETE"},
                    ].map((method, index) => <SelectItem key={index} value={method.id}>{method.name}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            {
              provider.method !== "GET" ? (
                <div className="grid grid-cols-12 gap-4 items-center mt-5">
                  <div className="col-span-12 md:col-span-2 mt-1">
                    {Setting.getLabel(i18next.t("webhook:Content type"), i18next.t("webhook:Content type - Tooltip"))} :
                  </div>
                  <div className="col-span-12 md:col-span-10">
                    <Select
                      value={provider.issuerUrl === "" ? "application/x-www-form-urlencoded" : provider.issuerUrl}
                      onValueChange={value => {
                        updateProviderField("issuerUrl", value);
                      }}
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {[
                          {id: "application/json", name: "application/json"},
                          {id: "application/x-www-form-urlencoded", name: "application/x-www-form-urlencoded"},
                        ].map((method, index) => <SelectItem key={index} value={method.id}>{method.name}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ) : null
            }
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:HTTP header"), i18next.t("provider:HTTP header - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                <HttpHeaderTable httpHeaders={provider.httpHeaders} onUpdateTable={(value) => {updateProviderField("httpHeaders", value);}} />
              </div>
            </div>
            {provider.method !== "GET" ? (
              <div className="grid grid-cols-12 gap-4 items-start mt-5">
                <div className="col-span-12 md:col-span-2 mt-1">
                  {Setting.getLabel(i18next.t("provider:HTTP body mapping"), i18next.t("provider:HTTP body mapping - Tooltip"))} :
                </div>
                <div className="col-span-12 md:col-span-10">
                  {renderSmsMappingInput()}
                </div>
              </div>
            ) : null}
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
          </React.Fragment>
        ) : null
      }
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Enable proxy"), i18next.t("provider:Enable proxy - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Switch checked={provider.enableProxy} onCheckedChange={checked => {
            updateProviderField("enableProxy", checked);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:SMS Test"), i18next.t("provider:SMS Test - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <div className="flex gap-2 items-center">
            <CountryCodeSelect
              style={{width: "90px"}}
              initValue={provider.content}
              onChange={(value) => {
                updateProviderField("content", value);
              }}
              countryCodes={account.organization.countryCodes}
            />
            <Input
              value={provider.receiver}
              className="w-40"
              placeholder={i18next.t("user:Input your phone number")}
              onChange={e => {
                updateProviderField("receiver", e.target.value);
              }}
            />
            <Button
              className="ml-2"
              disabled={!Setting.isValidPhone(provider.receiver) || (provider.type === "Custom HTTP SMS" && provider.endpoint === "")}
              onClick={() => ProviderEditTestSms.sendTestSms(provider, "+" + Setting.getCountryCode(provider.content) + provider.receiver)}
            >
              {i18next.t("provider:Send Testing SMS")}
            </Button>
          </div>
        </div>
      </div>
    </React.Fragment>
  );
}
