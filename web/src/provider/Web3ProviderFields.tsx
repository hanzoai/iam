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
import {Label} from "../components/ui/label";
import {RadioGroup, RadioGroupItem} from "../components/ui/radio-group";
import * as Setting from "../Setting";
import i18next from "i18next";
import {CHAINS, providerChain} from "../auth/WalletConnect";

// Native multi-chain wallet config (HIP-0111). A Web3 provider targets exactly
// one chain; the native connector (@luxwallet/connect) auto-discovers wallets on
// that chain (EIP-6963 for EVM, injected for Solana, etc.) -- there is no
// per-wallet allow-list. The chosen chain is stored in `metadata` as
// {"chain":"<chain>"}, which WalletConnect.providerChain() reads at login time.
const CHAIN_LABEL = {
  evm: "Ethereum / EVM",
  solana: "Solana",
  bitcoin: "Bitcoin",
  ton: "TON",
  xrp: "XRP Ledger",
};

export function renderWeb3ProviderFields(provider, updateProviderField) {
  const selected = providerChain(provider);

  const setChain = (chain) => {
    updateProviderField("metadata", JSON.stringify({chain}));
  };

  return (
    <div className="grid grid-cols-12 gap-4 items-start mt-5">
      <div className="col-span-12 md:col-span-2 mt-1">
        {Setting.getLabel(i18next.t("provider:Chain"), i18next.t("provider:Chain - Tooltip"))} :
      </div>
      <div className="col-span-12 md:col-span-10">
        <RadioGroup value={selected} onValueChange={setChain} className="flex flex-wrap gap-4">
          {CHAINS.map((chain) => {
            const id = `web3-chain-${chain}`;
            return (
              <div key={chain} className="flex items-center gap-2">
                <RadioGroupItem id={id} value={chain} />
                <Label htmlFor={id}>{CHAIN_LABEL[chain]}</Label>
              </div>
            );
          })}
        </RadioGroup>
      </div>
    </div>
  );
}
