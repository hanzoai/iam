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
import {Trash2, Pencil, Plus, Users, GripVertical, ChevronRight, ChevronDown} from "lucide-react";
import i18next from "i18next";
import moment from "moment/moment";
import React from "react";
import * as GroupBackend from "./backend/GroupBackend";
import * as Setting from "./Setting";
import OrganizationSelect from "./common/select/OrganizationSelect";
import UserListPage from "./UserListPage";

class GroupTreePage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      owner: Setting.isAdminUser(this.props.account) ? "" : this.props.account.owner,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      groupName: this.props.match?.params.groupName,
      treeData: [],
      selectedKeys: [this.props.match?.params.groupName],
      expandedKeys: [],
    };
  }

  UNSAFE_componentWillMount() {
    this.getTreeData();
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (this.state.organizationName !== prevState.organizationName) {
      this.getTreeData();
    }

    if (prevState.treeData !== this.state.treeData) {
      this.setTreeExpandedKeys();
    }
  }

  getTreeData() {
    GroupBackend.getGroups(this.state.organizationName, true).then((res) => {
      if (res.status === "ok") {
        this.setState({treeData: res.data});
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  }

  setTreeExpandedKeys = () => {
    const expandedKeys = [];
    const setExpandedKeys = (nodes) => {
      for (const node of nodes) {
        expandedKeys.push(node.key);
        if (node.children) {
          setExpandedKeys(node.children);
        }
      }
    };
    setExpandedKeys(this.state.treeData);
    this.setState({expandedKeys});
  };

  newGroup(isRoot) {
    const randomName = Setting.getRandomName();
    return {
      owner: this.state.organizationName,
      name: `group_${randomName}`,
      createdTime: moment().format(),
      updatedTime: moment().format(),
      displayName: `New Group - ${randomName}`,
      type: "Virtual",
      parentId: isRoot ? this.state.organizationName : this.state.groupName,
      isTopGroup: isRoot,
      isEnabled: true,
    };
  }

  addGroup(isRoot = false) {
    const newGroup = this.newGroup(isRoot);
    GroupBackend.addGroup(newGroup)
      .then((res) => {
        if (res.status === "ok") {
          sessionStorage.setItem("groupTreeUrl", window.location.pathname);
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

  deleteTreeNode(node) {
    GroupBackend.deleteGroup({owner: node.owner, name: node.key})
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.getTreeData();
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  toggleExpanded(key) {
    const expanded = [...this.state.expandedKeys];
    const idx = expanded.indexOf(key);
    if (idx >= 0) {
      expanded.splice(idx, 1);
    } else {
      expanded.push(key);
    }
    this.setState({expandedKeys: expanded});
  }

  renderTreeNode(node, depth = 0) {
    const haveChildren = Array.isArray(node.children) && node.children.length > 0;
    const isSelected = this.state.groupName === node.key;
    const isExpanded = this.state.expandedKeys.includes(node.key);

    return (
      <div key={node.key}>
        <div
          className={`flex items-center gap-1 px-2 py-1.5 rounded cursor-pointer group ${isSelected ? "bg-white/[0.08]" : "hover:bg-white/[0.04]"}`}
          style={{paddingLeft: `${depth * 16 + 8}px`}}
          onClick={() => {
            this.setState({selectedKeys: [node.key], groupName: node.key});
            this.props.history.push(`/trees/${this.state.organizationName}/${node.key}`);
          }}
        >
          {haveChildren ? (
            <button
              className="p-0.5 text-gray-400 hover:text-white"
              onClick={(e) => {
                e.stopPropagation();
                this.toggleExpanded(node.key);
              }}
            >
              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          ) : (
            <span className="w-5" />
          )}
          {node.type === "Physical" ? <Users size={14} className="text-gray-400" /> : <GripVertical size={14} className="text-gray-400" />}
          <span className="text-sm text-white flex-1">{node.title}</span>
          {isSelected && (
            <div className="flex items-center gap-1">
              <button
                className="p-1 text-gray-400 hover:text-white"
                onClick={(e) => {
                  e.stopPropagation();
                  sessionStorage.setItem("groupTreeUrl", window.location.pathname);
                  this.addGroup();
                }}
              >
                <Plus size={14} />
              </button>
              <button
                className="p-1 text-gray-400 hover:text-white"
                onClick={(e) => {
                  e.stopPropagation();
                  sessionStorage.setItem("groupTreeUrl", window.location.pathname);
                  this.props.history.push(`/groups/${this.state.organizationName}/${node.key}`);
                }}
              >
                <Pencil size={14} />
              </button>
              {!haveChildren && (
                <button
                  className="p-1 text-gray-400 hover:text-red-400"
                  onClick={(e) => {
                    e.stopPropagation();
                    this.deleteTreeNode(node);
                  }}
                >
                  <Trash2 size={14} />
                </button>
              )}
            </div>
          )}
        </div>
        {haveChildren && isExpanded && node.children.map(child => this.renderTreeNode(child, depth + 1))}
      </div>
    );
  }

  renderOrganizationSelect() {
    if (Setting.isAdminUser(this.props.account)) {
      return (
        <OrganizationSelect
          initValue={this.state.organizationName}
          style={{width: "100%"}}
          onChange={(value) => {
            this.setState({organizationName: value, groupName: ""});
            this.props.history.push(`/trees/${value}`);
          }}
        />
      );
    }
    return null;
  }

  render() {
    return (
      <div className="flex gap-4 min-h-[70vh]">
        <div className="w-64 shrink-0 bg-white/[0.02] border border-white/10 rounded-xl p-3 space-y-3">
          {this.renderOrganizationSelect()}
          <div className="flex gap-2">
            <button
              className="px-3 py-1.5 border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.05]"
              onClick={() => {
                this.setState({selectedKeys: [], groupName: undefined});
                this.props.history.push(`/trees/${this.state.organizationName}`);
              }}
            >
              {i18next.t("group:Show all")}
            </button>
            <button
              className="px-3 py-1.5 bg-white text-black rounded-lg text-xs font-medium hover:bg-gray-100"
              onClick={() => this.addGroup(true)}
            >
              {i18next.t("general:Add")}
            </button>
          </div>
          <div className="space-y-0.5">
            {this.state.treeData.length === 0 ? (
              <div className="text-center text-gray-500 py-8 text-sm">{i18next.t("general:No data")}</div>
            ) : (
              this.state.treeData.map(node => this.renderTreeNode(node))
            )}
          </div>
        </div>
        <div className="flex-1">
          <UserListPage
            organizationName={this.state.organizationName}
            groupName={this.state.groupName}
            {...this.props}
          />
        </div>
      </div>
    );
  }
}

export default GroupTreePage;
