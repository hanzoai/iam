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
import {Loader2} from "lucide-react";
import {Button} from "../components/ui/button";
import {Input} from "../components/ui/input";
import {Switch} from "../components/ui/switch";
import {Textarea} from "../components/ui/textarea";
import * as Setting from "../Setting";
import i18next from "i18next";
import {authConfig} from "../auth/Auth";
import copy from "copy-to-clipboard";

export function renderSamlProviderFields(provider, updateProviderField, metadataConfig) {
  const {requestUrl, setRequestUrl, metadataLoading, fetchSamlMetadata, parseSamlMetadata} = metadataConfig;
  return (
    <React.Fragment>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Sign request"), i18next.t("provider:Sign request - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Switch checked={provider.enableSignAuthnRequest} onCheckedChange={checked => {
            updateProviderField("enableSignAuthnRequest", checked);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Metadata url"), i18next.t("provider:Metadata url - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-6">
          <Input value={requestUrl} onChange={e => {
            setRequestUrl(e.target.value);
          }} />
        </div>
        <div className="col-span-12 md:col-span-4">
          <Button className="ml-2" disabled={metadataLoading} onClick={() => {fetchSamlMetadata();}}>
            {metadataLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {i18next.t("general:Request")}
          </Button>
        </div>
      </div>
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
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-2" />
        <div className="col-span-10">
          <Button onClick={() => {parseSamlMetadata();}}>
            {i18next.t("provider:Parse")}
          </Button>
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Endpoint"), i18next.t("provider:SAML 2.0 Endpoint (HTTP)"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Input value={provider.endpoint} onChange={e => {
            updateProviderField("endpoint", e.target.value);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:IdP"), i18next.t("provider:IdP certificate"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Input value={provider.idP} onChange={e => {
            updateProviderField("idP", e.target.value);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Issuer URL"), i18next.t("provider:Issuer URL - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-10">
          <Input value={provider.issuerUrl} onChange={e => {
            updateProviderField("issuerUrl", e.target.value);
          }} />
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:SP ACS URL"), i18next.t("provider:SP ACS URL - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-9">
          <Input value={`${authConfig.serverUrl}/v1/iam/acs`} readOnly />
        </div>
        <div className="col-span-12 md:col-span-1">
          <Button onClick={() => {
            copy(`${authConfig.serverUrl}/v1/iam/acs`);
            Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
          }}>
            {i18next.t("general:Copy")}
          </Button>
        </div>
      </div>
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-12 md:col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:SP Entity ID"), i18next.t("provider:SP Entity ID - Tooltip"))} :
        </div>
        <div className="col-span-12 md:col-span-9">
          <Input value={`${authConfig.serverUrl}/v1/iam/acs`} readOnly />
        </div>
        <div className="col-span-12 md:col-span-1">
          <Button onClick={() => {
            copy(`${authConfig.serverUrl}/v1/iam/acs`);
            Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
          }}>
            {i18next.t("general:Copy")}
          </Button>
        </div>
      </div>
    </React.Fragment>
  );
}
