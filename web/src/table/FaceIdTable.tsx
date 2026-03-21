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
import React, {Suspense, lazy} from "react";
import {Upload} from "lucide-react";
import i18next from "i18next";
import * as Setting from "../Setting";
import * as ResourceBackend from "../backend/ResourceBackend";
const FaceRecognitionModal = lazy(() => import("../common/modal/FaceRecognitionModal"));

class FaceIdTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      openFaceRecognitionModal: false,
      uploading: false,
    };
    this.fileInputRef = React.createRef();
  }

  updateTable(table) {
    this.props.onUpdateTable(table);
  }

  updateField(table, index, key, value) {
    table[index][key] = value;
    this.updateTable(table);
  }

  deleteRow(table, i) {
    table = Setting.deleteRow(table, i);
    this.updateTable(table);
  }

  addFaceId(table, faceIdData) {
    const faceId = {name: Setting.getRandomName(), faceIdData: faceIdData};
    if (table === undefined || table === null) {table = [];}
    table = Setting.addRow(table, faceId);
    this.updateTable(table);
  }

  addFaceImage(table, imageUrl) {
    const faceId = {name: Setting.getRandomName(), imageUrl: imageUrl, faceIdData: []};
    if (table === undefined || table === null) {table = [];}
    table = Setting.addRow(table, faceId);
    this.updateTable(table);
  }

  handleUpload(file, table) {
    this.setState({uploading: true});
    const filename = file.name;
    const fullFilePath = `resource/${this.props.account.owner}/${this.props.account.name}/${filename}`;
    ResourceBackend.uploadResource(this.props.account.owner, this.props.account.name, "custom", "ResourceListPage", fullFilePath, file)
      .then(res => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("application:File uploaded successfully"));
          this.addFaceImage(table, res.data);
        } else {
          Setting.showMessage("error", res.msg);
        }
      }).finally(() => {
        this.setState({uploading: false});
      });
  }

  renderTable(table) {
    return (
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4 flex-wrap">
          <span className="text-sm text-gray-300">{i18next.t("user:Face IDs")}</span>
          <button
            disabled={this.props.table?.length >= 5}
            className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
            onClick={() => this.setState({openFaceRecognitionModal: true, withImage: false})}
          >
            {i18next.t("application:Add Face ID")}
          </button>
          <button
            disabled={this.props.table?.length >= 5}
            className="px-3 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white disabled:opacity-50"
            onClick={() => this.setState({openFaceRecognitionModal: true, withImage: true})}
          >
            {i18next.t("application:Add Face ID with Image")}
          </button>
          <label className="px-3 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white cursor-pointer flex items-center gap-1">
            <Upload className="w-3 h-3" />
            {this.state.uploading ? "Uploading..." : i18next.t("resource:Upload a file...")}
            <input
              type="file"
              accept="image/*"
              className="hidden"
              onChange={e => {
                if (e.target.files[0]) {
                  this.handleUpload(e.target.files[0], table);
                }
              }}
            />
          </label>
          <Suspense fallback={null}>
            <FaceRecognitionModal
              visible={this.state.openFaceRecognitionModal}
              withImage={this.state.withImage}
              onOk={(faceIdData) => {
                this.addFaceId(table, faceIdData);
                this.setState({openFaceRecognitionModal: false});
              }}
              onCancel={() => this.setState({openFaceRecognitionModal: false})}
            />
          </Suspense>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Data")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:URL")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {(this.props.table || []).map((row, i) => {
                const dataPreview = row.faceIdData ? (() => {
                  const front = row.faceIdData.slice(0, 3).join(", ");
                  const back = row.faceIdData.slice(-3).join(", ");
                  return "[" + front + " ... " + back + "]";
                })() : "";

                return (
                  <tr key={i} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                    <td className="px-4 py-2">
                      <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" defaultValue={row.name || ""} onChange={e => this.updateField(table, i, "name", e.target.value)} />
                    </td>
                    <td className="px-4 py-2 text-white text-xs truncate">{dataPreview}</td>
                    <td className="px-4 py-2 text-white text-xs truncate">{row.imageUrl}</td>
                    <td className="px-4 py-2 text-right">
                      <button className="px-3 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-500 text-white" onClick={() => this.deleteRow(table, i)}>
                        {i18next.t("general:Delete")}
                      </button>
                    </td>
                  </tr>
                );
              })}
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

export default FaceIdTable;
