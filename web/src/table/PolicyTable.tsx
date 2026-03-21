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
import {Pencil, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import * as AdapterBackend from "../backend/AdapterBackend";
import i18next from "i18next";

class PolicyTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      policyLists: [],
      loading: false,
      editingIndex: "",
      oldPolicy: "",
      add: false,
      page: 1,
    };
  }

  count = 0;
  pageSize = 100;

  getIndex(index) {
    return index + (this.state.page - 1) * this.pageSize;
  }

  UNSAFE_componentWillMount() {
    if (this.props.mode === "edit" && this.props.enforcer.adapter !== "") {
      this.getPolicies();
    }
  }

  isEditing = (index) => {
    return index === this.state.editingIndex;
  };

  edit = (record, index) => {
    this.setState({editingIndex: index, oldPolicy: Setting.deepCopy(record)});
  };

  cancel = (table, index) => {
    Object.keys(table[this.getIndex(index)]).forEach((key) => {
      table[this.getIndex(index)][key] = this.state.oldPolicy[key];
    });
    this.updateTable(table);
    this.setState({editingIndex: "", oldPolicy: ""});
    if (this.state.add) {
      this.deleteRow(this.state.policyLists, index);
      this.setState({add: false});
    }
  };

  updateTable(table) {
    this.setState({policyLists: table});
  }

  updateField(table, index, key, value) {
    table[this.getIndex(index)][key] = value;
    this.updateTable(table);
  }

  addRow(table) {
    const row = {key: this.count, Ptype: "p"};
    if (table === undefined) {
      table = [];
    }
    table = Setting.addRow(table, row, "top");
    this.count = this.count + 1;
    this.updateTable(table);
    this.edit(row, 0);
    this.setState({page: 1, add: true});
  }

  deleteRow(table, index) {
    table = Setting.deleteRow(table, this.getIndex(index));
    this.updateTable(table);
  }

  save(table, i) {
    this.state.add ? this.addPolicy(table, i) : this.updatePolicy(table, i);
  }

  getPolicies() {
    this.setState({loading: true});
    AdapterBackend.getPolicies(this.props.enforcer.owner, this.props.enforcer.name)
      .then((res) => {
        if (res.status === "ok") {
          const policyList = res.data;
          policyList.map((policy, index) => {
            policy.key = index;
          });
          this.count = policyList.length;
          this.setState({policyLists: policyList});
        } else {
          Setting.showMessage("error", `${i18next.t("adapter:Failed to sync policies")}: ${res.msg}`);
        }
        this.setState({loading: false});
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  updatePolicy(table, i) {
    AdapterBackend.UpdatePolicy(this.props.enforcer.owner, this.props.enforcer.name, [this.state.oldPolicy, table[i]]).then(res => {
      if (res.status === "ok") {
        this.setState({editingIndex: "", oldPolicy: ""});
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
      }
    });
  }

  addPolicy(table, i) {
    AdapterBackend.AddPolicy(this.props.enforcer.owner, this.props.enforcer.name, table[i]).then(res => {
      if (res.status === "ok") {
        this.setState({editingIndex: "", oldPolicy: "", add: false});
        if (res.data !== "Affected") {
          res.msg = i18next.t("adapter:Duplicated policy rules");
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        } else {
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        }
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
      }
    });
  }

  deletePolicy(table, index) {
    AdapterBackend.RemovePolicy(this.props.enforcer.owner, this.props.enforcer.name, table[this.getIndex(index)]).then(res => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully deleted"));
        this.deleteRow(table, index);
      } else {
        Setting.showMessage("error", i18next.t("general:Failed to delete"));
      }
    });
  }

  renderTable(table) {
    if (this.props.modelCfg === undefined) {
      return null;
    }

    const columnKeys = ["V0", "V1", "V2", "V3", "V4", "V5"];
    const columnTitles = this.props.modelCfg ? this.props.modelCfg["p"].split(",") : columnKeys;

    const totalPages = Math.ceil(table.length / this.pageSize);
    const startIdx = (this.state.page - 1) * this.pageSize;
    const pageData = table.slice(startIdx, startIdx + this.pageSize);

    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <button
            className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
            disabled={this.state.editingIndex !== "" || this.props.enforcer.model === "" || this.props.enforcer.adapter === "" || Setting.builtInObject(this.props.enforcer)}
            onClick={() => this.addRow(table)}
          >
            {i18next.t("general:Add")}
          </button>
        </div>
        {this.state.loading ? (
          <div className="px-4 py-8 text-center text-gray-400 text-sm">Loading...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10 bg-white/[0.02]">
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("adapter:Rule type")}</th>
                  {columnTitles.map((title, idx) => (
                    <th key={idx} className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{title}</th>
                  ))}
                  <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "150px"}}>{i18next.t("general:Action")}</th>
                </tr>
              </thead>
              <tbody>
                {pageData.map((row, i) => {
                  const editing = this.isEditing(i);
                  return (
                    <tr key={row.key} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                      <td className="px-4 py-2">
                        {editing && this.props.modelCfg ? (
                          <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.Ptype || ""} onChange={e => this.updateField(table, i, "Ptype", e.target.value)}>
                            {Object.keys(this.props.modelCfg).reverse().map(item => (
                              <option key={item} value={item}>{item}</option>
                            ))}
                          </select>
                        ) : (
                          <span className="text-white">{row.Ptype}</span>
                        )}
                      </td>
                      {columnTitles.map((_, colIdx) => (
                        <td key={colIdx} className="px-4 py-2">
                          {editing ? (
                            <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row[columnKeys[colIdx]] || ""} onChange={e => this.updateField(table, i, columnKeys[colIdx], e.target.value)} />
                          ) : (
                            <span className="text-white">{row[columnKeys[colIdx]]}</span>
                          )}
                        </td>
                      ))}
                      <td className="px-4 py-2 text-right">
                        {editing ? (
                          <div className="flex items-center justify-end gap-2">
                            <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => this.save(table, i)}>
                              {i18next.t("general:Save")}
                            </button>
                            <button className="px-3 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white" onClick={() => this.cancel(table, i)}>
                              {i18next.t("general:Cancel")}
                            </button>
                          </div>
                        ) : (
                          <div className="flex items-center justify-end gap-1">
                            <button title="Edit" disabled={this.state.editingIndex !== "" || Setting.builtInObject(this.props.enforcer)} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => this.edit(row, i)}>
                              <Pencil className="w-4 h-4" />
                            </button>
                            <button title="Delete" disabled={this.state.editingIndex !== "" || Setting.builtInObject(this.props.enforcer)} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300 disabled:opacity-30" onClick={() => this.deletePolicy(table, i)}>
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
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
        <button
          className="mb-3 px-4 py-2 text-sm font-medium rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
          disabled={this.state.editingIndex !== "" || this.props.enforcer.model === "" || this.props.enforcer.adapter === ""}
          onClick={() => this.getPolicies()}
        >
          {i18next.t("general:Sync")}
        </button>
        {this.renderTable(this.state.policyLists)}
      </React.Fragment>
    );
  }
}

export default PolicyTable;
