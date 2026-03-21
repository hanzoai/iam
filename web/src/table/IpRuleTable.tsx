// Copyright 2023 The casbin Authors. All Rights Reserved.
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
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";

const defaultRules = [
  {name: "loopback", operator: "is in", value: "127.0.0.1"},
  {name: "lan cidr", operator: "is in", value: "10.0.0.0/8,192.168.0.0/16"},
];

class IpRuleTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      options: [],
    };
    if (this.props.table.length === 0) {
      this.restore();
    }
    for (let i = 0; i < this.props.table.length; i++) {
      const values = this.props.table[i].value.split(",");
      const options = values.map(v => ({value: v, label: v}));
      this.state.options.push(options);
    }
  }

  updateTable(table) {
    this.props.onUpdateTable(table);
  }

  updateField(table, index, key, value) {
    if (key === "value") {
      let v = "";
      for (let i = 0; i < value.length; i++) {
        v += value[i].trim() + ",";
      }
      table[index][key] = v.slice(0, -1);
    } else {
      table[index][key] = value;
    }
    this.updateTable(table);
  }

  addRow(table) {
    const row = {name: `New IP Rule - ${table.length}`, operator: "is in", value: "127.0.0.1"};
    if (table === undefined) {table = [];}
    table = Setting.addRow(table, row);
    this.updateTable(table);
  }

  deleteRow(table, i) {
    table = Setting.deleteRow(table, i);
    this.updateTable(table);
  }

  upRow(table, i) {
    table = Setting.swapRow(table, i - 1, i);
    Setting.swapRow(this.state.options, i - 1, i);
    this.updateTable(table);
  }

  downRow(table, i) {
    table = Setting.swapRow(table, i, i + 1);
    Setting.swapRow(this.state.options, i, i + 1);
    this.updateTable(table);
  }

  restore() {
    this.updateTable(defaultRules);
  }

  renderTable(table) {
    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{this.props.title}</span>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => this.addRow(table)}>
            {i18next.t("general:Add")}
          </button>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => this.restore()}>
            {i18next.t("general:Restore")}
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "180px"}}>{i18next.t("general:Name")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "180px"}}>{i18next.t("rule:Operator")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("rule:IP List")}</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
            </tr>
          </thead>
          <tbody>
            {table.map((row, i) => (
              <tr key={i} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                <td className="px-4 py-2">
                  <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => this.updateField(table, i, "name", e.target.value)} />
                </td>
                <td className="px-4 py-2">
                  <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.operator || ""} onChange={e => this.updateField(table, i, "operator", e.target.value)}>
                    <option value="is in">{i18next.t("rule:is in")}</option>
                    <option value="is not in">{i18next.t("rule:is not in")}</option>
                  </select>
                </td>
                <td className="px-4 py-2">
                  <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" placeholder="Comma-separated IP addresses" value={row.value || ""} onChange={e => {
                    table[i].value = e.target.value;
                    this.updateTable([...table]);
                  }} />
                </td>
                <td className="px-4 py-2 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button title="Up" disabled={i === 0} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => this.upRow(table, i)}>
                      <ArrowUp className="w-4 h-4" />
                    </button>
                    <button title="Down" disabled={i === table.length - 1} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => this.downRow(table, i)}>
                      <ArrowDown className="w-4 h-4" />
                    </button>
                    <button title="Delete" className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300" onClick={() => this.deleteRow(table, i)}>
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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

export default IpRuleTable;
