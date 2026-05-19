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
import {Switch} from "../components/ui/switch";
import {Textarea} from "../components/ui/textarea";
import {Button} from "../components/ui/button";
import {cn} from "../lib/utils";
import * as Setting from "../Setting";
import i18next from "i18next";

export function renderOAuthProviderFields(provider, updateProviderField, renderUserMappingInput) {
  const getDomainLabel = provider => {
    switch (provider.category) {
    case "OAuth":
      if (provider.type === "AzureAD" || provider.type === "AzureADB2C") {
        return Setting.getLabel(i18next.t("provider:Tenant ID"), i18next.t("provider:Tenant ID - Tooltip"));
      } else {
        return Setting.getLabel(i18next.t("provider:Domain"), i18next.t("provider:Domain - Tooltip"));
      }
    default:
      return Setting.getLabel(i18next.t("provider:Domain"), i18next.t("provider:Domain - Tooltip"));
    }
  };

  return (
    <React.Fragment>
      <div className="grid grid-cols-12 gap-4 items-start mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Email regex"), i18next.t("provider:Email regex - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Textarea rows={4} value={provider.emailRegex} onChange={e => {
            updateProviderField("emailRegex", e.target.value);
          }} />
        </div>
      </div>
      {
        provider.type !== "WeChat" ? null : (
          <React.Fragment>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:Use WeChat Media Platform in PC"), i18next.t("provider:Use WeChat Media Platform in PC - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                <Switch
                  disabled={!provider.clientId}
                  checked={provider.disableSsl}
                  onCheckedChange={checked => {
                    updateProviderField("disableSsl", checked);
                  }}
                />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("token:Access token"), i18next.t("token:Access token - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                <Input value={provider.content} disabled={!provider.disableSsl || !provider.clientId2} onChange={e => {
                  updateProviderField("content", e.target.value);
                }} />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:Follow-up action"), i18next.t("provider:Follow-up action - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                <div className="inline-flex rounded-md border border-input bg-background">
                  {[
                    {value: "open", label: i18next.t("provider:Use WeChat Open Platform to login")},
                    {value: "media", label: i18next.t("provider:Use WeChat Media Platform to login")},
                  ].map((opt, i, arr) => {
                    const selected = provider.signName === opt.value;
                    const disabled = !provider.disableSsl || !provider.clientId || !provider.clientId2;
                    return (
                      <Button
                        key={opt.value}
                        type="button"
                        variant={selected ? "default" : "ghost"}
                        disabled={disabled}
                        className={cn(
                          "rounded-none",
                          i === 0 ? "rounded-l-md" : "",
                          i === arr.length - 1 ? "rounded-r-md" : "border-l border-input"
                        )}
                        onClick={() => updateProviderField("signName", opt.value)}
                      >
                        {opt.label}
                      </Button>
                    );
                  })}
                </div>
              </div>
            </div>
          </React.Fragment>
        )
      }
      {
        provider.type !== "ADFS" && provider.type !== "AzureAD"
        && provider.type !== "AzureADB2C" && (provider.type !== "Hanzo IAM" && provider.category !== "Storage")
        && provider.type !== "Okta" && provider.type !== "Nextcloud" ? null : (
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-2 mt-1">
                {getDomainLabel(provider)} :
              </div>
              <div className="col-span-10">
                <div className="relative">
                  <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                  <Input className="pl-9" value={provider.domain} onChange={e => {
                    updateProviderField("domain", e.target.value);
                  }} />
                </div>
              </div>
            </div>
          )
      }
      {
        provider.type !== "Google" && provider.type !== "Lark" ? null : (
          <div className="grid grid-cols-12 gap-4 items-center mt-5">
            <div className="col-span-12 md:col-span-2 mt-1">
              {provider.type === "Google" ?
                Setting.getLabel(i18next.t("provider:Get phone number"), i18next.t("provider:Get phone number - Tooltip"))
                : Setting.getLabel(i18next.t("provider:Use global endpoint"), i18next.t("provider:Use global endpoint - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-10">
              <Switch disabled={!provider.clientId} checked={provider.disableSsl} onCheckedChange={checked => {
                updateProviderField("disableSsl", checked);
              }} />
            </div>
          </div>
        )
      }
      {
        provider.type.startsWith("Custom") ? (
          <React.Fragment>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:Auth URL"), i18next.t("provider:Auth URL - Tooltip"))}
              </div>
              <div className="col-span-12 md:col-span-10">
                <Input value={provider.customAuthUrl} onChange={e => {
                  updateProviderField("customAuthUrl", e.target.value);
                }} />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:Token URL"), i18next.t("provider:Token URL - Tooltip"))}
              </div>
              <div className="col-span-12 md:col-span-10">
                <Input value={provider.customTokenUrl} onChange={e => {
                  updateProviderField("customTokenUrl", e.target.value);
                }} />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:Scope"), i18next.t("provider:Scope - Tooltip"))}
              </div>
              <div className="col-span-12 md:col-span-10">
                <Input value={provider.scopes} onChange={e => {
                  updateProviderField("scopes", e.target.value);
                }} />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:UserInfo URL"), i18next.t("provider:UserInfo URL - Tooltip"))}
              </div>
              <div className="col-span-12 md:col-span-10">
                <Input value={provider.customUserInfoUrl} onChange={e => {
                  updateProviderField("customUserInfoUrl", e.target.value);
                }} />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-center mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:Enable PKCE"), i18next.t("provider:Enable PKCE - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                <Switch checked={provider.enablePkce} onCheckedChange={checked => {
                  updateProviderField("enablePkce", checked);
                }} />
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("provider:User mapping"), i18next.t("provider:User mapping - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                {renderUserMappingInput()}
              </div>
            </div>
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-2 mt-1">
                {Setting.getLabel(i18next.t("general:Favicon"), i18next.t("general:Favicon - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-10">
                <div className="grid grid-cols-12 gap-4 items-center">
                  <div className="col-span-12 md:col-span-1 mt-1">
                    {Setting.getLabel(i18next.t("general:URL"), i18next.t("general:URL - Tooltip"))} :
                  </div>
                  <div className="col-span-12 md:col-span-11">
                    <div className="relative">
                      <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                      <Input className="pl-9" value={provider.customLogo} onChange={e => {
                        updateProviderField("customLogo", e.target.value);
                      }} />
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-12 gap-4 items-center mt-5">
                  <div className="col-span-12 md:col-span-1 mt-1">
                    {i18next.t("general:Preview")}:
                  </div>
                  <div className="col-span-12 md:col-span-11">
                    <a target="_blank" rel="noreferrer" href={provider.customLogo}>
                      <img src={provider.customLogo} alt={provider.customLogo} height={90} style={{marginBottom: "20px"}} />
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </React.Fragment>
        ) : null
      }
    </React.Fragment>
  );
}
