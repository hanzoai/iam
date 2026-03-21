// @ts-nocheck
// Copyright 2023 The Hanzo Authors. All Rights Reserved.
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

import React, {useEffect, useState} from "react";
import QRCode from "qrcode.react";
import * as Setting from "./Setting";
import * as ProviderBackend from "./backend/ProviderBackend";
import i18next from "i18next";

function QrCodePage(props) {
  const params = new URLSearchParams(window.location.search);
  const owner = props.owner ?? (props.match?.params?.owner ?? null);
  const paymentName = props.paymentName ?? (props.match?.params?.paymentName ?? null);
  const providerName = props.providerName ?? params.get("providerName");
  const payUrl = props.payUrl ?? params.get("payUrl");
  const successUrl = props.successUrl ?? params.get("successUrl");
  const [provider, setProvider] = useState(props.provider ?? null);

  useEffect(() => {
    if (props.onUpdateApplication) props.onUpdateApplication(null);
    if (owner && providerName) {
      ProviderBackend.getProvider(owner, providerName).then((res) => {
        if (res.status === "ok") setProvider(res.data);
        else Setting.showMessage("error", res.msg);
      }).catch(err => Setting.showMessage("error", err.message));
    }
  }, []);

  if (!payUrl || !successUrl || !owner || !paymentName) return null;

  return (
    <div className="login-content">
      <div className="flex flex-col items-center">
        {provider && (
          <div className="flex items-center gap-2 border border-zinc-700 rounded-full px-4 py-2 mb-3">
            <img className="w-9 h-9" src={Setting.getProviderLogoURL(provider)} alt={provider.displayName} />
            <span className="text-white">{i18next.t(`product:${provider.type}`)}</span>
          </div>
        )}
        <div className="mt-3 flex justify-center">
          <QRCode value={payUrl} size={props.size ?? 200} />
        </div>
      </div>
    </div>
  );
}

export default QrCodePage;
