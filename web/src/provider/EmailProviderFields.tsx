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
import * as ProviderEditTestEmail from "../common/TestEmailWidget";
import Editor from "../common/Editor";
import HttpHeaderTable from "../table/HttpHeaderTable";

export function renderEmailProviderFields(provider, updateProviderField, renderEmailMappingInput, account) {
  return (
    <React.Fragment>
      {
        ["Custom HTTP Email", "SendGrid"].includes(provider.type) ? (
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
        ) : null
      }
      {provider.type === "Resend" ? null : (
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
      )}
      {["Azure ACS", "SendGrid", "Resend"].includes(provider.type) ? null : (
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
      )}
      {["Azure ACS", "SendGrid", "Resend"].includes(provider.type) ? null : (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-12 md:col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:SSL mode"), i18next.t("provider:SSL mode - Tooltip"))} :
          </div>
          <div className="col-span-12 md:col-span-10">
            <Select value={provider.sslMode || "Auto"} onValueChange={value => {
              updateProviderField("sslMode", value);
            }}>
              <SelectTrigger className="w-52">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Auto">{i18next.t("general:Auto")}</SelectItem>
                <SelectItem value="Enable">{i18next.t("general:Enable")}</SelectItem>
                <SelectItem value="Disable">{i18next.t("general:Disable")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )}
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
      {
        provider.type === "Custom HTTP Email" ? (
          <React.Fragment>
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
                  {renderEmailMappingInput()}
                </div>
              </div>
            ) : null}
          </React.Fragment>
        ) : null
      }
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Email title"), i18next.t("provider:Email title - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Input value={provider.title} onChange={e => {
            updateProviderField("title", e.target.value);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-start mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Email content"), i18next.t("provider:Email content - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <div className="flex gap-2 mb-2">
            <Button variant="outline" onClick={() => updateProviderField("content", "You have requested a verification code. Here is your code: %s, please enter in 5 minutes. <reset-link>Or click %link to reset</reset-link>")}>
              {i18next.t("general:Reset to Default")} (Text)
            </Button>
            <Button onClick={() => updateProviderField("content", Setting.getDefaultHtmlEmailContent())}>
              {i18next.t("general:Reset to Default")} (HTML)
            </Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div style={{height: "300px"}}>
              <Editor
                value={provider.content}
                fillHeight
                dark
                lang="html"
                onChange={value => {
                  updateProviderField("content", value);
                }}
              />
            </div>
            <div>
              <div dangerouslySetInnerHTML={{__html: provider.content.replace("%s", "123456").replace("%{user.friendlyName}", Setting.getFriendlyUserName(account))}} />
            </div>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-start mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(`${i18next.t("provider:Email content")}-${i18next.t("general:Invitations")}`, i18next.t("provider:Email content - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <div className="flex gap-2 mb-2">
            <Button variant="outline" onClick={() => updateProviderField("metadata", "You have been invited to join. Here is your invitation code: %s, please enter in 5 minutes. Or click %link to sign up")}>
              {i18next.t("general:Reset to Default")} (Text)
            </Button>
            <Button onClick={() => updateProviderField("metadata", Setting.getDefaultInvitationHtmlEmailContent())}>
              {i18next.t("general:Reset to Default")} (HTML)
            </Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div style={{height: "300px"}}>
              <Editor
                value={provider.metadata}
                fillHeight
                dark
                lang="html"
                onChange={value => {
                  updateProviderField("metadata", value);
                }}
              />
            </div>
            <div>
              <div dangerouslySetInnerHTML={{__html: provider.metadata.replace("%code", "123456").replace("%s", "123456")}} />
            </div>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Test Email"), i18next.t("provider:Test Email - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <div className="flex gap-2 items-center flex-wrap">
            <Input
              className="w-64"
              value={provider.receiver}
              placeholder={i18next.t("user:Input your email")}
              onChange={e => {
                updateProviderField("receiver", e.target.value);
              }}
            />
            {["Azure ACS", "SendGrid", "Resend"].includes(provider.type) ? null : (
              <Button variant="outline" onClick={() => ProviderEditTestEmail.connectSmtpServer(provider)}>
                {i18next.t("provider:Test SMTP Connection")}
              </Button>
            )}
            <Button
              disabled={!Setting.isValidEmail(provider.receiver)}
              onClick={() => ProviderEditTestEmail.sendTestEmail(provider, provider.receiver)}
            >
              {i18next.t("provider:Send Testing Email")}
            </Button>
          </div>
        </div>
      </div>
    </React.Fragment>
  );
}
