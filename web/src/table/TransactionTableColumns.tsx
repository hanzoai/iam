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
import {Link} from "react-router-dom";
import * as Setting from "../Setting";
import i18next from "i18next";
import PopconfirmModal from "../common/modal/PopconfirmModal";

export function getTransactionTableColumns(options = {}) {
  const {
    includeOrganization = false,
    includeUser = false,
    includeTag = true,
    includeActions = false,
    getColumnSearchProps = null,
    account = null,
    onEdit = null,
    onDelete = null,
  } = options;

  const columns = [];

  if (includeOrganization) {
    columns.push({
      title: i18next.t("general:Organization"),
      dataIndex: "owner",
      key: "owner",
      width: "120px",
      render: (text) => (<Link to={`/organizations/${text}`}>{text}</Link>),
    });
  }

  columns.push({
    title: i18next.t("general:Name"),
    dataIndex: "name",
    key: "name",
    width: includeOrganization ? "180px" : "280px",
    render: (text, record) => (<Link to={`/transactions/${record.owner}/${record.name}`}>{text}</Link>),
  });

  columns.push({
    title: i18next.t("general:Created time"),
    dataIndex: "createdTime",
    key: "createdTime",
    width: "160px",
    render: (text) => Setting.getFormattedDate(text),
  });

  if (includeTag) {
    columns.push({
      title: i18next.t("user:Tag"),
      dataIndex: "tag",
      key: "tag",
      width: "120px",
    });
  }

  if (includeUser) {
    columns.push({
      title: i18next.t("general:User"),
      dataIndex: "user",
      key: "user",
      width: "120px",
      render: (text, record) => {
        if (!text || Setting.isAnonymousUserName(text)) {return text;}
        return (<Link to={`/users/${record.owner}/${text}`}>{text}</Link>);
      },
    });
  }

  columns.push({
    title: i18next.t("general:Application"),
    dataIndex: "application",
    key: "application",
    width: "150px",
    render: (text, record) => {
      if (!text) {return text;}
      return (<Link to={`/applications/${record.owner}/${record.application}`}>{text}</Link>);
    },
  });

  columns.push({
    title: i18next.t("provider:Domain"),
    dataIndex: "domain",
    key: "domain",
    width: includeOrganization ? "200px" : "270px",
    render: (text) => {
      if (!text) {return null;}
      return (<a href={text} target="_blank" rel="noopener noreferrer">{text}</a>);
    },
  });

  columns.push({
    title: i18next.t("general:Category"),
    dataIndex: "category",
    key: "category",
    width: "120px",
  });

  columns.push({
    title: i18next.t("general:Type"),
    dataIndex: "type",
    key: "type",
    width: "140px",
    render: (text, record) => {
      if (text && record.domain) {
        const chatUrl = `${record.domain}/chats/${text}`;
        return (<a href={chatUrl} target="_blank" rel="noopener noreferrer">{text}</a>);
      }
      return text;
    },
  });

  columns.push({
    title: i18next.t("provider:Subtype"),
    dataIndex: "subtype",
    key: "subtype",
    width: "140px",
    render: (text, record) => {
      if (text && record.domain) {
        const messageUrl = `${record.domain}/messages/${text}`;
        return (<a href={messageUrl} target="_blank" rel="noopener noreferrer">{text}</a>);
      }
      return text;
    },
  });

  columns.push({
    title: i18next.t("general:Provider"),
    dataIndex: "provider",
    key: "provider",
    width: "150px",
    render: (text, record) => {
      if (!text) {return text;}
      if (record.domain) {
        const providerUrl = `${record.domain}/providers/${text}`;
        return (<a href={providerUrl} target="_blank" rel="noopener noreferrer">{text}</a>);
      }
      return (<Link to={`/providers/${record.owner}/${text}`}>{text}</Link>);
    },
  });

  columns.push({
    title: i18next.t("general:Payment"),
    dataIndex: "payment",
    key: "payment",
    width: "120px",
    render: (text, record) => {
      if (!text) {return text;}
      return (<Link to={`/payments/${record.owner}/${text}`}>{text}</Link>);
    },
  });

  columns.push({
    title: i18next.t("general:State"),
    dataIndex: "state",
    key: "state",
    width: "120px",
  });

  columns.push({
    title: i18next.t("product:Amount"),
    dataIndex: "amount",
    key: "amount",
    width: "180px",
    render: (text, record) => Setting.getPriceDisplay(record.amount, record.currency),
  });

  if (includeActions && account && onEdit && onDelete) {
    columns.push({
      title: i18next.t("general:Action"),
      dataIndex: "",
      key: "op",
      width: "200px",
      render: (text, record, index) => {
        const isAdmin = Setting.isLocalAdminUser(account);
        return (
          <div className="flex items-center gap-2">
            <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => onEdit(record, isAdmin)}>
              {isAdmin ? i18next.t("general:Edit") : i18next.t("general:View")}
            </button>
            <PopconfirmModal
              title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
              onConfirm={() => onDelete(index)}
              disabled={!isAdmin}
            />
          </div>
        );
      },
    });
  }

  return columns;
}
