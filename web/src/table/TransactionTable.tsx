// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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
import {Search} from "lucide-react";
import Highlighter from "react-highlight-words";
import i18next from "i18next";
import {getTransactionTableColumns} from "./TransactionTableColumns";
import * as Setting from "../Setting";
import {Link} from "react-router-dom";

class TransactionTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      searchText: "",
      searchedColumn: "",
      pageSize: 10,
      currentPage: 1,
      filters: {},
    };
  }

  handleSearch = (dataIndex, value) => {
    this.setState({
      searchText: value,
      searchedColumn: dataIndex,
      currentPage: 1,
    });
  };

  handleReset = (dataIndex) => {
    const newFilters = {...this.state.filters};
    delete newFilters[dataIndex];
    this.setState({searchText: "", searchedColumn: "", filters: newFilters});
  };

  getFilteredData() {
    let data = this.props.transactions || [];
    if (this.state.searchText && this.state.searchedColumn) {
      data = data.filter(record =>
        record[this.state.searchedColumn]
          ? record[this.state.searchedColumn].toString().toLowerCase().includes(this.state.searchText.toLowerCase())
          : false
      );
    }
    return data;
  }

  render() {
    const columns = getTransactionTableColumns({
      includeOrganization: false,
      includeUser: this.props.includeUser || false,
      includeTag: !this.props.hideTag,
      includeActions: false,
      getColumnSearchProps: null,
      account: null,
      onEdit: null,
      onDelete: null,
    });

    const data = this.getFilteredData();
    const totalPages = Math.ceil(data.length / this.state.pageSize);
    const startIdx = (this.state.currentPage - 1) * this.state.pageSize;
    const pageData = data.slice(startIdx, startIdx + this.state.pageSize);

    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        {this.props.title && (
          <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02]">
            <span className="text-sm text-gray-300">{this.props.title}</span>
          </div>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                {columns.map((col) => (
                  <th key={col.key || col.dataIndex} className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: col.width}}>
                    {col.title}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageData.map((row) => (
                <tr key={`${row.owner}/${row.name}`} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  {columns.map((col) => {
                    const value = row[col.dataIndex];
                    const rendered = col.render ? col.render(value, row, 0) : value;
                    return (
                      <td key={col.key || col.dataIndex} className="px-4 py-2 text-white">
                        {this.state.searchedColumn === col.dataIndex && this.state.searchText ? (
                          <Highlighter
                            highlightStyle={{backgroundColor: "#ffc069", padding: 0}}
                            searchWords={[this.state.searchText]}
                            autoEscape
                            textToHighlight={value ? value.toString() : ""}
                          />
                        ) : rendered}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <select className="bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white" value={this.state.pageSize} onChange={e => this.setState({pageSize: Number(e.target.value), currentPage: 1})}>
                {[10, 20, 50, 100].map(size => (
                  <option key={size} value={size}>{size} / page</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2">
              {Array.from({length: totalPages}, (_, idx) => (
                <button key={idx} className={`px-2 py-1 text-xs rounded ${this.state.currentPage === idx + 1 ? "bg-blue-600 text-white" : "bg-white/5 text-gray-400 hover:bg-white/10"}`} onClick={() => this.setState({currentPage: idx + 1})}>
                  {idx + 1}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }
}

export default TransactionTable;
