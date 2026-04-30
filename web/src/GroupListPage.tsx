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

// @ts-nocheck
import React from "react";
import {Link} from "react-router-dom";
import {Upload} from "antd";
import {Upload as UploadIcon, Download, Trash2, Pencil, X} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as GroupBackend from "./backend/GroupBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";
import * as XLSX from "xlsx";

class GroupListPage extends BaseListPage {
  constructor(props) {
    super(props);
    this.state = {
      ...this.state,
      owner: Setting.isAdminUser(this.props.account) ? "" : this.props.account.owner,
      groups: [],
    };
  }
  UNSAFE_componentWillMount() {
    super.UNSAFE_componentWillMount();
  }

  newGroup() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `group_${randomName}`,
      createdTime: moment().format(),
      updatedTime: moment().format(),
      displayName: `New Group - ${randomName}`,
      type: "Virtual",
      parentId: this.props.account.owner,
      isTopGroup: true,
      isEnabled: true,
    };
  }

  addGroup() {
    const newGroup = this.newGroup();
    GroupBackend.addGroup(newGroup)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/groups/${newGroup.owner}/${newGroup.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteGroup(i) {
    GroupBackend.deleteGroup(this.state.data[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.fetch({
            pagination: {
              ...this.state.pagination,
              current: this.state.pagination.current > 1 && this.state.data.length === 1 ? this.state.pagination.current - 1 : this.state.pagination.current,
            },
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  uploadFile(info) {
    const {status, msg} = info;
    if (status === "ok") {
      Setting.showMessage("success", i18next.t("general:Successfully saved"));
      const {pagination} = this.state;
      this.fetch({pagination});
    } else if (status === "error") {
      Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${msg}`);
    }
    this.setState({uploadJsonData: [], uploadColumns: [], showUploadModal: false});
  }

  generateDownloadTemplate() {
    const groupObj = {};
    const items = Setting.getGroupColumns();
    items.forEach((item) => {
      groupObj[item] = null;
    });
    const worksheet = XLSX.utils.json_to_sheet([groupObj]);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Sheet1");
    XLSX.writeFile(workbook, "import-group.xlsx", {compression: true});
  }

  renderUpload() {
    const uploadThis = this;
    const uploadProps = {
      name: "file",
      accept: ".xlsx",
      showUploadList: false,
      beforeUpload: (file) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          const binary = e.target.result;
          try {
            const workbook = XLSX.read(binary, {type: "array"});
            if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
              Setting.showMessage("error", i18next.t("general:No sheets found in file"));
              return;
            }
            const worksheet = workbook.Sheets[workbook.SheetNames[0]];
            const jsonData = XLSX.utils.sheet_to_json(worksheet);
            this.setState({uploadJsonData: jsonData, file: file});
            const columns = Setting.getGroupColumns().map(el => {
              return {title: el.split("#")[0], dataIndex: el, key: el};
            });
            this.setState({uploadColumns: columns}, () => {this.setState({showUploadModal: true});});
          } catch (err) {
            Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${err.message}`);
          }
        };
        reader.onerror = (error) => {
          Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${error?.message || error}`);
        };
        reader.readAsArrayBuffer(file);
        return false;
      },
    };

    return (
      <>
        <Upload {...uploadProps}>
          <button className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1.5">
            <UploadIcon size={14} />
            {i18next.t("general:Upload (.xlsx)")}
          </button>
        </Upload>
        {this.state.showUploadModal && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-[#111] border border-white/10 rounded-xl p-6 w-full max-w-4xl max-h-[80vh] overflow-auto">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">{i18next.t("general:Upload (.xlsx)")}</h3>
                <button onClick={() => this.setState({showUploadModal: false, uploadJsonData: [], uploadColumns: []})} className="text-gray-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/10">
                      {this.state.uploadColumns.map(col => (
                        <th key={col.key} className="px-3 py-2 text-left text-gray-400 font-medium">{col.title}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {this.state.uploadJsonData.map((row, idx) => (
                      <tr key={idx} className="border-b border-white/5">
                        {this.state.uploadColumns.map(col => (
                          <td key={col.key} className="px-3 py-2 text-white">{row[col.dataIndex]}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex justify-end gap-3 mt-4">
                <button
                  className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
                  onClick={() => this.setState({showUploadModal: false, uploadJsonData: [], uploadColumns: []})}
                >
                  {i18next.t("general:Cancel")}
                </button>
                <button
                  className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100"
                  onClick={() => {
                    const formData = new FormData();
                    formData.append("file", this.state.file);
                    fetch(`${Setting.ServerUrl}/v1/iam/upload-groups`, {
                      method: "post",
                      body: formData,
                      credentials: "include",
                      headers: {"Accept-Language": Setting.getAcceptLanguage()},
                    })
                      .then((res) => res.json())
                      .then((res) => {uploadThis.uploadFile(res);})
                      .catch((error) => {
                        Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${error.message}`);
                      });
                  }}
                >
                  {i18next.t("general:Click to Upload")}
                </button>
              </div>
            </div>
          </div>
        )}
      </>
    );
  }

  renderTable(data) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">{i18next.t("general:Groups")}</h1>
          <div className="flex gap-2">
            <button
              className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1.5"
              onClick={this.generateDownloadTemplate}
            >
              <Download size={14} />
              {i18next.t("general:Download template")}
            </button>
            {this.renderUpload()}
            <button
              className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100"
              onClick={this.addGroup.bind(this)}
            >
              {i18next.t("general:Add")}
            </button>
          </div>
        </div>

        <div className="overflow-x-auto border border-white/10 rounded-xl">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Organization")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Created time")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Display name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Type")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("group:Parent group")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Users")}</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {data && data.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <Link to={`/groups/${record.owner}/${record.name}`} className="text-white hover:underline">
                      {record.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/organizations/${record.owner}`} className="text-white hover:underline">
                      {record.owner}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-white">{record.displayName}</td>
                  <td className="px-4 py-3 text-white">{i18next.t("group:" + record.type)}</td>
                  <td className="px-4 py-3">
                    {record.isTopGroup ? (
                      <Link to={`/organizations/${record.parentId}`} className="text-white hover:underline">
                        {record.parentId}
                      </Link>
                    ) : (
                      <Link to={`/groups/${record.owner}/${record.parentId}`} className="text-white hover:underline">
                        {record?.parentName}
                      </Link>
                    )}
                  </td>
                  <td className="px-4 py-3">{Setting.getTags(record.users, "users")}</td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                        onClick={() => this.props.history.push(`/groups/${record.owner}/${record.name}`)}
                      >
                        <Pencil size={12} />
                        {i18next.t("general:Edit")}
                      </button>
                      {record.haveChildren ? (
                        <button
                          disabled
                          className="px-3 py-1.5 bg-white/[0.02] border border-white/5 rounded-lg text-xs text-gray-600 cursor-not-allowed inline-flex items-center gap-1"
                          title={i18next.t("group:You need to delete all subgroups first. You can view the subgroups in the left group tree of the [Organizations] -> [Groups] page")}
                        >
                          <Trash2 size={12} />
                          {i18next.t("general:Delete")}
                        </button>
                      ) : (
                        <PopconfirmModal
                          title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                          onConfirm={() => this.deleteGroup(index)}
                        />
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {(!data || data.length === 0) && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                    {this.state.loading ? i18next.t("general:Loading...") : i18next.t("general:No data")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>{i18next.t("general:{total} in total").replace("{total}", this.state.pagination.total)}</span>
          <div className="flex items-center gap-2">
            <button
              disabled={this.state.pagination.current <= 1}
              className="px-3 py-1 border border-white/10 rounded text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/[0.05]"
              onClick={() => this.handleTableChange({...this.state.pagination, current: this.state.pagination.current - 1}, {}, {})}
            >
              Prev
            </button>
            <span className="text-white">{this.state.pagination.current}</span>
            <button
              disabled={this.state.pagination.current * this.state.pagination.pageSize >= this.state.pagination.total}
              className="px-3 py-1 border border-white/10 rounded text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/[0.05]"
              onClick={() => this.handleTableChange({...this.state.pagination, current: this.state.pagination.current + 1}, {}, {})}
            >
              Next
            </button>
          </div>
        </div>
      </div>
    );
  }

  fetch = (params = {}) => {
    let field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (params.category !== undefined && params.category !== null) {
      field = "category";
      value = params.category;
    } else if (params.type !== undefined && params.type !== null) {
      field = "type";
      value = params.type;
    }
    this.setState({loading: true});
    GroupBackend.getGroups(Setting.isDefaultOrganizationSelected(this.props.account) ? "" : Setting.getRequestOrganization(this.props.account), false, params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      .then((res) => {
        this.setState({loading: false});
        if (res.status === "ok") {
          this.setState({
            data: res.data,
            pagination: {
              ...params.pagination,
              total: res.data2,
            },
            searchText: params.searchText,
            searchedColumn: params.searchedColumn,
          });
        } else {
          if (Setting.isResponseDenied(res)) {
            this.setState({isAuthorized: false});
          }
        }
      })
      .catch(error => {
        this.setState({loading: false});
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  };
}

export default GroupListPage;
