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
import i18next from "i18next";
import * as Setting from "../Setting";

function CartTable({cart: rawCart}) {
  const cart = rawCart || [];

  return (
    <div className="border border-white/10 rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/10 bg-white/[0.02]">
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("general:Name")}</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "80px"}}>{i18next.t("product:Image")}</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("order:Price")}</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("product:Quantity")}</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Detail")}</th>
          </tr>
        </thead>
        <tbody>
          {cart.map((row) => (
            <tr key={`${row.owner}/${row.name}`} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
              <td className="px-4 py-2 text-white">{row.displayName}</td>
              <td className="px-4 py-2">
                {row.image ? (
                  <a target="_blank" rel="noreferrer" href={row.image}>
                    <img src={row.image} alt={row.displayName} width={40} />
                  </a>
                ) : null}
              </td>
              <td className="px-4 py-2 text-white">{Setting.getCurrencySymbol(row.currency)}{row.price}</td>
              <td className="px-4 py-2 text-white">{row.quantity}</td>
              <td className="px-4 py-2 text-white">{row.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default CartTable;
