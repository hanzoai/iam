// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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
import i18next from "i18next";
import {Switch} from "./components/ui/switch";
import {Table, TableBody, TableCell, TableHead, TableHeader, TableRow} from "./components/ui/table";

class ToolTable extends React.Component {
  updateTable(table) {
    this.props.onUpdateTable(table);
  }

  updateToolEnable(table, index, value) {
    const newTable = [...(table || [])];
    newTable[index] = {
      ...newTable[index],
      isAllowed: value,
    };
    this.updateTable(newTable);
  }

  render() {
    const table = this.props.tools || [];
    return (
      <div className="rounded-md border border-border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[260px]">{i18next.t("general:Name")}</TableHead>
              <TableHead>{i18next.t("general:Description")}</TableHead>
              <TableHead className="w-[120px]">{i18next.t("general:Is allowed")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {table.map((record, index) => (
              <TableRow key={record.name || `tool-${index}`}>
                <TableCell>{record.name}</TableCell>
                <TableCell>{record.description}</TableCell>
                <TableCell>
                  <Switch checked={record.isAllowed} onCheckedChange={(checked) => this.updateToolEnable(table, index, checked)} />
                </TableCell>
              </TableRow>
            ))}
            {table.length === 0 && (
              <TableRow>
                <TableCell colSpan={3} className="h-24 text-center text-muted-foreground">
                  {i18next.t("general:No data")}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    );
  }
}

export default ToolTable;
