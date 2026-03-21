// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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
import {Trash2} from "lucide-react";
import i18next from "i18next";
import * as Setting from "../Setting";

class AttributesMapperTable extends React.Component {
  constructor(props) {
    super(props);

    const customAttributes = this.props.customAttributes !== null
      ? Object.entries(this.props.customAttributes).map((item, index) => ({
        key: index,
        attributeName: item[0],
        userPropertyName: item[1],
      }))
      : [];
    this.state = {
      customAttributes: customAttributes,
      page: 1,
    };
  }

  pageSize = 10;
  count = this.props.customAttributes !== null ? Object.entries(this.props.customAttributes).length : 0;

  updateTable(table) {
    this.setState({customAttributes: table});
    const customAttributes = {};
    table.forEach((item) => {
      customAttributes[item.attributeName] = item.userPropertyName;
    });
    this.props.onUpdateTable(customAttributes);
  }

  addRow(table) {
    const row = {key: this.count, attributeName: "", userPropertyName: ""};
    if (table === undefined) {table = [];}
    table = Setting.addRow(table, row);
    this.count = this.count + 1;
    this.updateTable(table);
  }

  deleteRow(table, index) {
    table = Setting.deleteRow(table, this.getIndex(index));
    this.updateTable(table);
  }

  getIndex(index) {
    return index + (this.state.page - 1) * this.pageSize;
  }

  updateField(table, index, attributeName, userPropertyName) {
    table[this.getIndex(index)][attributeName] = userPropertyName;
    this.updateTable(table);
  }

  renderTable(table) {
    const totalPages = Math.ceil(table.length / this.pageSize);
    const startIdx = (this.state.page - 1) * this.pageSize;
    const pageData = table.slice(startIdx, startIdx + this.pageSize);

    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02]">
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => this.addRow(table)}>
            {i18next.t("general:Add")}
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("ldap:LDAP attribute name")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("ldap:User property name")}</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "60px"}}>{i18next.t("general:Action")}</th>
            </tr>
          </thead>
          <tbody>
            {pageData.map((row, i) => (
              <tr key={row.key} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                <td className="px-4 py-2">
                  <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.attributeName || ""} onChange={e => this.updateField(table, i, "attributeName", e.target.value)} />
                </td>
                <td className="px-4 py-2">
                  <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.userPropertyName || ""} onChange={e => this.updateField(table, i, "userPropertyName", e.target.value)} />
                </td>
                <td className="px-4 py-2 text-right">
                  <button title={i18next.t("general:Delete")} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300" onClick={() => this.deleteRow(table, i)}>
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-white/10 flex items-center justify-end gap-2">
            {Array.from({length: totalPages}, (_, idx) => (
              <button key={idx} className={`px-2 py-1 text-xs rounded ${this.state.page === idx + 1 ? "bg-blue-600 text-white" : "bg-white/5 text-gray-400 hover:bg-white/10"}`} onClick={() => this.setState({page: idx + 1})}>
                {idx + 1}
              </button>
            ))}
          </div>
        )}
      </div>
    );
  }

  render() {
    return (
      <React.Fragment>
        {this.renderTable(this.state.customAttributes)}
      </React.Fragment>
    );
  }
}

export default AttributesMapperTable;
