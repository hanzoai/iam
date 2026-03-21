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
import React, {useEffect, useState} from "react";
import * as GroupBackend from "./backend/GroupBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";

function GroupEditPage(props) {
  const {account, history, location, match, organizationName: propsOrgName} = props;

  const initialOrgName = propsOrgName !== undefined ? propsOrgName : match.params.organizationName;
  const initialGroupName = match.params.groupName;

  const [groupName, setGroupName] = useState(initialGroupName);
  const [organizationName] = useState(initialOrgName);
  const [group, setGroup] = useState(null);
  const [groups, setGroups] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [mode] = useState(location.mode !== undefined ? location.mode : "edit");

  useEffect(() => {
    getGroup();
    getGroups(organizationName);
    getOrganizations();
  }, []);

  function getGroup() {
    GroupBackend.getGroup(organizationName, groupName)
      .then((res) => {
        if (res.status === "ok") {
          setGroup(res.data);
        }
      });
  }

  function getGroups(orgName) {
    GroupBackend.getGroups(orgName)
      .then((res) => {
        if (res.status === "ok") {
          setGroups(res.data);
        }
      });
  }

  function getOrganizations() {
    OrganizationBackend.getOrganizationNames("admin")
      .then((res) => {
        if (res.status === "ok") {
          setOrganizations(res.data || []);
        }
      });
  }

  function parseGroupField(key, value) {
    if ([""].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  function updateGroupField(key, value) {
    value = parseGroupField(key, value);
    const newGroup = {...group};
    newGroup[key] = value;
    setGroup(newGroup);
  }

  function getParentIdOptions() {
    const filtered = groups.filter((g) => g.name !== group.name);
    const org = organizations.find((o) => o.name === group.owner);
    const options = [...filtered];
    if (org !== undefined) {
      options.push({name: org.name, displayName: org.displayName});
    }
    return options.map((g) => ({label: g.displayName, value: g.name}));
  }

  function submitGroupEdit(exitAfterSave) {
    const groupCopy = Setting.deepCopy(group);
    groupCopy["isTopGroup"] = organizations.some((o) => o.name === groupCopy.parentId);

    GroupBackend.updateGroup(organizationName, groupName, groupCopy)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          setGroupName(group.name);

          if (exitAfterSave) {
            const groupTreeUrl = sessionStorage.getItem("groupTreeUrl");
            if (groupTreeUrl !== null) {
              sessionStorage.removeItem("groupTreeUrl");
              history.push(groupTreeUrl);
            } else {
              history.push("/groups");
            }
          } else {
            history.push(`/groups/${group.owner}/${group.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          updateGroupField("name", groupName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  function deleteGroup() {
    GroupBackend.deleteGroup(group)
      .then((res) => {
        if (res.status === "ok") {
          const groupTreeUrl = sessionStorage.getItem("groupTreeUrl");
          if (groupTreeUrl !== null) {
            sessionStorage.removeItem("groupTreeUrl");
            history.push(groupTreeUrl);
          } else {
            history.push("/groups");
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  function renderGroup() {
    const parentOptions = getParentIdOptions();

    return (
      <div className="bg-white/[0.02] border border-white/10 rounded-xl p-6 space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            {mode === "add" ? i18next.t("group:New Group") : i18next.t("group:Edit Group")}
          </h2>
          <div className="flex gap-2">
            <button
              className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
              onClick={() => submitGroupEdit(false)}
            >
              {i18next.t("general:Save")}
            </button>
            <button
              className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100"
              onClick={() => submitGroupEdit(true)}
            >
              {i18next.t("general:Save & Exit")}
            </button>
            {mode === "add" && (
              <button
                className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
                onClick={() => deleteGroup()}
              >
                {i18next.t("general:Cancel")}
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5">
          <div>
            <label className="text-sm text-gray-400 mb-1 block">
              {i18next.t("general:Organization")}
            </label>
            <select
              className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white"
              disabled={!Setting.isAdminUser(account)}
              value={group.owner}
              onChange={(e) => {
                updateGroupField("owner", e.target.value);
                getGroups(e.target.value);
              }}
            >
              {organizations.map((org) => (
                <option key={org.name} value={org.name}>{org.displayName}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">
              {i18next.t("general:Name")}
            </label>
            <input
              className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white"
              value={group.name}
              onChange={(e) => updateGroupField("name", e.target.value)}
            />
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">
              {i18next.t("general:Display name")}
            </label>
            <input
              className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white"
              value={group.displayName}
              onChange={(e) => updateGroupField("displayName", e.target.value)}
            />
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">
              {i18next.t("general:Type")}
            </label>
            <select
              className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white"
              value={group.type}
              onChange={(e) => updateGroupField("type", e.target.value)}
            >
              <option value="Virtual">{i18next.t("group:Virtual")}</option>
              <option value="Physical">{i18next.t("group:Physical")}</option>
            </select>
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">
              {i18next.t("group:Parent group")}
            </label>
            <select
              className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white"
              value={group.parentId}
              onChange={(e) => updateGroupField("parentId", e.target.value)}
            >
              {parentOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">
              {i18next.t("general:Users")}
            </label>
            <div className="flex flex-wrap gap-1 mt-1">
              {Setting.getTags(group.users, "users")}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-sm text-gray-400">
              {i18next.t("general:Is enabled")}
            </label>
            <button
              type="button"
              role="switch"
              aria-checked={group.isEnabled}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${group.isEnabled ? "bg-white" : "bg-white/20"}`}
              onClick={() => updateGroupField("isEnabled", !group.isEnabled)}
            >
              <span className={`inline-block h-4 w-4 rounded-full transition-transform ${group.isEnabled ? "translate-x-6 bg-black" : "translate-x-1 bg-gray-400"}`} />
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (group === null) {
    return null;
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {renderGroup()}
      <div className="flex gap-3">
        <button
          className="px-6 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
          onClick={() => submitGroupEdit(false)}
        >
          {i18next.t("general:Save")}
        </button>
        <button
          className="px-6 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100"
          onClick={() => submitGroupEdit(true)}
        >
          {i18next.t("general:Save & Exit")}
        </button>
        {mode === "add" && (
          <button
            className="px-6 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
            onClick={() => deleteGroup()}
          >
            {i18next.t("general:Cancel")}
          </button>
        )}
      </div>
    </div>
  );
}

export default GroupEditPage;
