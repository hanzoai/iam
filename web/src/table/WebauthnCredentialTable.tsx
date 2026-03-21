// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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
import * as UserWebauthnBackend from "../backend/UserWebauthnBackend";
import * as Setting from "../Setting";

class WebAuthnCredentialTable extends React.Component {
  deleteRow(table, i) {
    table = Setting.deleteRow(table, i);
    this.props.updateTable(table);
  }

  registerWebAuthn() {
    UserWebauthnBackend.registerWebauthnCredential().then((res) => {
      if (res.status === "ok") {
        Setting.showMessage("success", "Successfully added webauthn credentials");
      } else {
        Setting.showMessage("error", res.msg);
      }
      this.props.refresh();
    }).catch(error => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  render() {
    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{i18next.t("user:WebAuthn credentials")}</span>
          <button
            disabled={!this.props.isSelf}
            className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
            onClick={() => this.registerWebAuthn()}
          >
            {i18next.t("general:Add")}
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Name")}</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "170px"}}>{i18next.t("general:Action")}</th>
            </tr>
          </thead>
          <tbody>
            {(this.props.table || []).map((row, i) => (
              <tr key={row.id} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                <td className="px-4 py-2 text-white truncate">{row.id}</td>
                <td className="px-4 py-2 text-right">
                  <button
                    className="px-3 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-500 text-white"
                    onClick={() => this.deleteRow(this.props.table, i)}
                  >
                    {i18next.t("general:Delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
}

export default WebAuthnCredentialTable;
