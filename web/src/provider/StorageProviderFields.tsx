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

export function renderStorageProviderFields(provider, updateProviderField) {
  return (
    <React.Fragment>
      {["Local File System", "MinIO", "Tencent Cloud COS", "Google Cloud Storage", "Qiniu Cloud Kodo", "Synology", "Hanzo IAM"].includes(provider.type) ? null : (
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
      {["Local File System"].includes(provider.type) ? null : (
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
      )}
      {["Local File System"].includes(provider.type) ? null : (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-2 mt-1">
            {["Hanzo IAM"].includes(provider.type) ?
              Setting.getLabel(i18next.t("general:Provider"), i18next.t("general:Provider - Tooltip"))
              : Setting.getLabel(i18next.t("provider:Bucket"), i18next.t("provider:Bucket - Tooltip"))} :
          </div>
          <div className="col-span-10">
            <Input value={provider.bucket} onChange={e => {
              updateProviderField("bucket", e.target.value);
            }} />
          </div>
        </div>
      )}
      <div className="grid grid-cols-12 gap-4 items-center mt-5">
        <div className="col-span-2 mt-1">
          {Setting.getLabel(i18next.t("provider:Path prefix"), i18next.t("provider:Path prefix - Tooltip"))} :
        </div>
        <div className="col-span-10">
          <Input value={provider.pathPrefix} onChange={e => {
            updateProviderField("pathPrefix", e.target.value);
          }} />
        </div>
      </div>
      {["Synology", "Hanzo IAM"].includes(provider.type) ? null : (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-2 mt-1">
            {Setting.getLabel(i18next.t("provider:Domain"), i18next.t("provider:Domain - Tooltip"))} :
          </div>
          <div className="col-span-10">
            <div className="relative">
              <Link className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                className="pl-9"
                value={provider.domain}
                disabled={provider.type === "Local File System"}
                onChange={e => {
                  updateProviderField("domain", e.target.value);
                }}
              />
            </div>
          </div>
        </div>
      )}
      {["Hanzo IAM"].includes(provider.type) ? (
        <div className="grid grid-cols-12 gap-4 items-center mt-5">
          <div className="col-span-2 mt-1">
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </div>
          <div className="col-span-10">
            <Input value={provider.content} onChange={e => {
              updateProviderField("content", e.target.value);
            }} />
          </div>
        </div>
      ) : null}
      {["AWS S3", "Tencent Cloud COS", "Qiniu Cloud Kodo", "Hanzo IAM", "CUCloud OSS", "MinIO"].includes(provider.type) ? (
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
    </React.Fragment>
  );
}
