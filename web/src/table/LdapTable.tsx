// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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
import * as Setting from "../Setting";
import i18next from "i18next";
import * as LdapBackend from "../backend/LdapBackend";
import {Link} from "react-router-dom";
import PopconfirmModal from "../common/modal/PopconfirmModal";

class LdapTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
    };
  }

  updateTable(table) {
    this.props.onUpdateTable(table);
  }

  newLdap() {
    return {
      id: "",
      owner: this.props.organizationName,
      createdTime: "",
      serverName: "Example LDAP Server",
      host: "example.com",
      port: 389,
      username: "cn=admin,dc=example,dc=com",
      password: "123",
      baseDn: "ou=People,dc=example,dc=com",
      autosync: 0,
      lastSync: "",
    };
  }

  addRow(table) {
    const newLdap = this.newLdap();
    LdapBackend.addLdap(newLdap)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully added"));
          if (table === undefined) {table = [];}
          table = Setting.addRow(table, res.data2);
          this.updateTable(table);
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${error}`);
      });
  }

  deleteRow(table, i) {
    LdapBackend.deleteLdap(table[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          table = Setting.deleteRow(table, i);
          this.updateTable(table);
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${error}`);
      });
  }

  renderTable(table) {
    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{this.props.title}</span>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => this.addRow(table)}>
            {i18next.t("general:Add")}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "160px"}}>{i18next.t("ldap:Server name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("ldap:Server")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("ldap:Base DN")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("ldap:Auto Sync")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("ldap:Last Sync")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "240px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {(table || []).map((row, i) => (
                <tr key={row.id} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  <td className="px-4 py-2">
                    <Link to={`/ldap/${row.owner}/${row.id}`} className="text-blue-400 hover:text-blue-300">
                      {row.serverName}
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-white truncate">{`${row.host}:${row.port}`}</td>
                  <td className="px-4 py-2 text-white truncate">{row.baseDn}</td>
                  <td className="px-4 py-2">
                    {row.autoSync === 0 ? (
                      <span className="text-yellow-400">Disable</span>
                    ) : (
                      <span className="text-green-400">{row.autoSync + " mins"}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-white truncate">{row.lastSync}</td>
                  <td className="px-4 py-2 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => Setting.goToLink(`/ldap/sync/${row.owner}/${row.id}`)}>
                        {i18next.t("general:Sync")}
                      </button>
                      <button className="px-3 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white" onClick={() => Setting.goToLink(`/ldap/${row.owner}/${row.id}`)}>
                        {i18next.t("general:Edit")}
                      </button>
                      <PopconfirmModal
                        title={i18next.t("general:Sure to delete") + `: ${row.serverName} ?`}
                        onConfirm={() => this.deleteRow(table, i)}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  render() {
    return (
      <div className="mt-5">
        {this.renderTable(this.props.table)}
      </div>
    );
  }
}

export default LdapTable;
