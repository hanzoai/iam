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
import {Checkbox} from "../components/ui/checkbox";
import {Label} from "../components/ui/label";
import * as Setting from "../Setting";
import i18next from "i18next";
import * as Web3Auth from "../auth/Web3Auth";

export function renderWeb3ProviderFields(provider, updateProviderField) {
  const getWalletValue = () => {
    try {
      return JSON.parse(provider.metadata);
    } catch {
      return ["injected"];
    }
  };

  if (provider.type !== "Web3Onboard") {
    return null;
  }

  const selected = getWalletValue();
  const toggle = (value, checked) => {
    const next = checked
      ? Array.from(new Set([...selected, value]))
      : selected.filter((v) => v !== value);
    updateProviderField("metadata", JSON.stringify(next));
  };

  return (
    <div className="grid grid-cols-12 gap-4 items-start mt-5">
      <div className="col-span-12 md:col-span-2 mt-1">
        {Setting.getLabel(i18next.t("provider:Wallets"), i18next.t("provider:Wallets - Tooltip"))} :
      </div>
      <div className="col-span-12 md:col-span-10">
        <div className="flex flex-wrap gap-4">
          {Web3Auth.getWeb3OnboardWalletsOptions().map((opt) => {
            const id = `web3-wallet-${opt.value}`;
            return (
              <div key={opt.value} className="flex items-center gap-2">
                <Checkbox
                  id={id}
                  checked={selected.includes(opt.value)}
                  onCheckedChange={(checked) => toggle(opt.value, checked === true)}
                />
                <Label htmlFor={id}>{opt.label}</Label>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
