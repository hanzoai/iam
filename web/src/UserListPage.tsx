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
import {Link} from "react-router-dom";
import {Upload as UploadIcon, Download, Pencil, UserRoundCheck, X} from "lucide-react";
import moment from "moment";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import * as UserBackend from "./backend/UserBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";
import AccountAvatar from "./account/AccountAvatar";
import * as XLSX from "xlsx";

class UserListPage extends BaseListPage {
  constructor(props) {
    super(props);
    this.state = {
      ...this.state,
      organization: null,
    };
  }

  UNSAFE_componentWillMount() {
    super.UNSAFE_componentWillMount();
    this.getOrganization(this.state.organizationName);
  }

  componentDidUpdate(prevProps, prevState) {
    if (this.props.match.path !== prevProps.match.path || this.props.organizationName !== prevProps.organizationName) {
      this.setState({
        organizationName: this.props.organizationName ?? this.props.match?.params.organizationName,
      });
    }

    if (this.state.organizationName !== prevState.organizationName) {
      this.getOrganization(this.state.organizationName);
    }

    if (prevProps.groupName !== this.props.groupName || this.state.organizationName !== prevState.organizationName) {
      this.fetch({
        pagination: this.state.pagination,
        searchText: this.state.searchText,
        searchedColumn: this.state.searchedColumn,
      });
    }
  }

  newUser() {
    const randomName = Setting.getRandomName();
    const owner = (Setting.isDefaultOrganizationSelected(this.props.account) || this.props.groupName) ? this.state.organizationName : Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `user_${randomName}`,
      createdTime: moment().format(),
      type: "normal-user",
      password: "123",
      passwordSalt: "",
      displayName: `New User - ${randomName}`,
      avatar: this.state.organization.defaultAvatar ?? `${Setting.StaticBaseUrl}/img/hanzo.svg`,
      email: `${randomName}@example.com`,
      phone: Setting.getRandomNumber(),
      countryCode: this.state.organization.countryCodes?.length > 0 ? this.state.organization.countryCodes[0] : "",
      address: [],
      groups: this.props.groupName ? [`${owner}/${this.props.groupName}`] : [],
      affiliation: "Example Inc.",
      tag: "staff",
      region: "",
      realName: "",
      isVerified: false,
      isAdmin: (owner === "built-in"),
      IsForbidden: false,
      score: this.state.organization.initScore,
      isDeleted: false,
      properties: {},
      signupApplication: this.state.organization.defaultApplication,
      registerType: "Add User",
      registerSource: `${this.props.account.owner}/${this.props.account.name}`,
      balanceCurrency: this.state.organization.balanceCurrency || "USD",
    };
  }

  addUser() {
    const newUser = this.newUser();
    UserBackend.addUser(newUser)
      .then((res) => {
        if (res.status === "ok") {
          sessionStorage.setItem("userListUrl", window.location.pathname);
          this.props.history.push({pathname: `/users/${newUser.owner}/${newUser.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteUser(i) {
    UserBackend.deleteUser(this.state.data[i])
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

  removeUserFromGroup(i) {
    const user = this.state.data[i];
    const group = this.props.groupName;
    UserBackend.removeUserFromGroup({groupName: group, owner: user.owner, name: user.name})
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully removed"));
          this.setState({
            data: Setting.deleteRow(this.state.data, i),
            pagination: {total: this.state.pagination.total - 1},
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to remove")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  uploadFile(info) {
    const {status, msg} = info;
    if (status === "ok") {
      Setting.showMessage("success", "Users uploaded successfully, refreshing the page");
      const {pagination} = this.state;
      this.fetch({pagination});
    } else if (status === "error") {
      Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${msg}`);
    }
    this.setState({uploadJsonData: [], uploadColumns: [], showUploadModal: false});
  }

  generateDownloadTemplate() {
    const userObj = {};
    const items = Setting.getUserColumns();
    items.forEach((item) => {
      userObj[item] = null;
    });
    const worksheet = XLSX.utils.json_to_sheet([userObj]);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Sheet1");
    XLSX.writeFile(workbook, "import-user.xlsx", {compression: true});
  }

  getOrganization(organizationName) {
    OrganizationBackend.getOrganization("admin", organizationName)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({organization: res.data});
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${res.msg}`);
        }
      });
  }

  impersonateUser(user) {
    UserBackend.impersonateUser(user).then((res) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully executed"));
        Setting.goToLinkSoft(this, "/");
        window.location.reload();
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  }

  handleUploadFile = (file) => {
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
        const columns = Setting.getUserColumns().map(el => {
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
  };

  renderUpload() {
    const uploadThis = this;

    return (
      <>
        <label className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1.5 cursor-pointer">
          <UploadIcon size={14} />
          {i18next.t("general:Upload (.xlsx)")}
          <input type="file" accept=".xlsx" className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {this.handleUploadFile(file);}
              e.target.value = "";
            }}
          />
        </label>
        {this.state.showUploadModal && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-[#111] border border-white/10 rounded-xl p-6 w-full max-w-5xl max-h-[80vh] overflow-auto">
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
                      {this.state.uploadColumns?.map(col => (
                        <th key={col.key} className="px-3 py-2 text-left text-gray-400 font-medium whitespace-nowrap">{col.title}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {this.state.uploadJsonData?.map((row, idx) => (
                      <tr key={idx} className="border-b border-white/5">
                        {this.state.uploadColumns?.map(col => (
                          <td key={col.key} className="px-3 py-2 text-white whitespace-nowrap">{row[col.dataIndex]}</td>
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
                    fetch(`${Setting.ServerUrl}/v1/iam/upload-users`, {
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

  renderTable(users) {
    const isTreePage = this.props.groupName !== undefined;

    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">{i18next.t("general:Users")}</h1>
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
              onClick={this.addUser.bind(this)}
            >
              {i18next.t("general:Add")}
            </button>
          </div>
        </div>

        <div className="overflow-x-auto border border-white/10 rounded-xl">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Organization")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Display name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Avatar")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Email")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Phone")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Created time")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("user:Is admin")}</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {users && users.map((record, index) => {
                const disabled = (record.owner === this.props.account.owner && record.name === this.props.account.name) || (record.owner === "built-in" && record.name === "admin");
                return (
                  <tr key={`${record.owner}/${record.name}`} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="px-4 py-3">
                      <Link to={`/organizations/${record.owner}`} className="text-white hover:underline">
                        {record.owner}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <Link to={`/users/${record.owner}/${record.name}`} className="text-white hover:underline">
                        {record.name}
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-white">{record.displayName}</td>
                    <td className="px-4 py-3">
                      {record.avatar && (
                        <a target="_blank" rel="noreferrer" href={record.avatar}>
                          <AccountAvatar referrerPolicy="no-referrer" src={record.avatar} alt={record.avatar} size={32} />
                        </a>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <a href={`mailto:${record.email}`} className="text-gray-400 hover:text-white">{record.email}</a>
                    </td>
                    <td className="px-4 py-3 text-gray-400">{record.phone}</td>
                    <td className="px-4 py-3 text-gray-400">{Setting.getFormattedDate(record.createdTime)}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${record.isAdmin ? "bg-white/10 text-white" : "bg-white/5 text-gray-500"}`}>
                        {record.isAdmin ? i18next.t("general:ON") : i18next.t("general:OFF")}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                          onClick={() => this.impersonateUser(`${record.owner}/${record.name}`)}
                        >
                          <UserRoundCheck size={12} />
                          {i18next.t("general:Impersonation")}
                        </button>
                        <button
                          className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                          onClick={() => {
                            sessionStorage.setItem("userListUrl", window.location.pathname);
                            this.props.history.push(`/users/${record.owner}/${record.name}`);
                          }}
                        >
                          <Pencil size={12} />
                          {i18next.t("general:Edit")}
                        </button>
                        {isTreePage && (
                          <PopconfirmModal
                            text={i18next.t("general:remove")}
                            title={i18next.t("general:Sure to remove") + `: ${record.name} ?`}
                            onConfirm={() => this.removeUserFromGroup(index)}
                            disabled={disabled}
                            size="small"
                          />
                        )}
                        <PopconfirmModal
                          title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                          onConfirm={() => this.deleteUser(index)}
                          disabled={disabled}
                          size={isTreePage ? "small" : "default"}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
              {(!users || users.length === 0) && (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
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
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    this.setState({loading: true});
    if (this.props.match?.path === "/users") {
      (Setting.isDefaultOrganizationSelected(this.props.account) ? UserBackend.getGlobalUsers(params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder) : UserBackend.getUsers(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder))
        .then((res) => {
          this.setState({loading: false});
          if (res.status === "ok") {
            this.setState({
              data: res.data,
              pagination: {...params.pagination, total: res.data2},
              searchText: params.searchText,
              searchedColumn: params.searchedColumn,
            });
          } else {
            if (Setting.isResponseDenied(res)) {
              this.setState({isAuthorized: false});
            } else {
              Setting.showMessage("error", res.msg);
            }
          }
        });
    } else {
      (this.props.groupName ?
        UserBackend.getUsers(this.state.organizationName, params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder, this.props.groupName) :
        UserBackend.getUsers(this.state.organizationName, params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder))
        .then((res) => {
          this.setState({loading: false});
          if (res.status === "ok") {
            this.setState({
              data: res.data,
              pagination: {...params.pagination, total: res.data2},
              searchText: params.searchText,
              searchedColumn: params.searchedColumn,
            });
          } else {
            if (Setting.isResponseDenied(res)) {
              this.setState({isAuthorized: false});
            } else {
              Setting.showMessage("error", res.msg);
            }
          }
        });
    }
  };
}

export default UserListPage;
