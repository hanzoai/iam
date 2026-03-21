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

import React, {useEffect, useState} from "react";
import {Trash2, ChevronUp, ChevronDown} from "lucide-react";
import {getRules} from "../backend/RuleBackend";
import * as Setting from "../Setting";
import i18next from "i18next";

interface CompoundRuleProps {
  owner: string;
  ruleName: string;
  table: any[];
  title: string;
  onUpdateTable: (table: any[]) => void;
}

const defaultRules = [
  {name: "Start", operator: "begin", value: "rule1"},
  {name: "And", operator: "and", value: "rule2"},
];

const CompoundRule = (props: CompoundRuleProps) => {
  const {owner, ruleName, table, title, onUpdateTable} = props;
  const [rules, setRules] = useState<string[]>([]);

  useEffect(() => {
    if (table.length === 0) {
      onUpdateTable(defaultRules);
    }
    fetchRules();
  }, []);

  const fetchRules = () => {
    getRules(owner).then((res: any) => {
      const ruleList: string[] = [];
      for (let i = 0; i < res.data.length; i++) {
        if (Setting.getItemId(res.data[i]) === owner + "/" + ruleName) {
          continue;
        }
        ruleList.push(Setting.getItemId(res.data[i]));
      }
      setRules(ruleList);
    });
  };

  const updateField = (t: any[], index: number, key: string, value: string) => {
    const newTable = [...t];
    newTable[index] = {...newTable[index], [key]: value};
    onUpdateTable(newTable);
  };

  const addRow = () => {
    const row = {name: `New Item - ${table.length}`, operator: "and", value: ""};
    onUpdateTable(Setting.addRow(table || [], row));
  };

  const deleteRow = (i: number) => {
    onUpdateTable(Setting.deleteRow(table, i));
  };

  const upRow = (i: number) => {
    onUpdateTable(Setting.swapRow(table, i - 1, i));
  };

  const downRow = (i: number) => {
    onUpdateTable(Setting.swapRow(table, i, i + 1));
  };

  const restore = () => {
    onUpdateTable(defaultRules);
  };

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-2 px-4 py-3 bg-white/5 border-b border-white/10">
          <span className="text-sm text-white font-medium">{title}</span>
          <button
            onClick={addRow}
            className="px-3 py-1 text-xs bg-white text-black rounded-md hover:bg-gray-200 transition-colors"
          >
            {i18next.t("general:Add")}
          </button>
          <button
            onClick={restore}
            className="px-3 py-1 text-xs bg-white text-black rounded-md hover:bg-gray-200 transition-colors"
          >
            {i18next.t("general:Restore")}
          </button>
        </div>

        {/* Table header */}
        <div className="grid grid-cols-[180px_1fr_100px] border-b border-white/10 bg-white/5">
          <div className="px-4 py-2 text-xs text-gray-400 font-medium">{i18next.t("rule:Logic")}</div>
          <div className="px-4 py-2 text-xs text-gray-400 font-medium">{i18next.t("rule:Rule")}</div>
          <div className="px-4 py-2 text-xs text-gray-400 font-medium">{i18next.t("general:Action")}</div>
        </div>

        {/* Rows */}
        {table.map((row, index) => (
          <div key={index} className="grid grid-cols-[180px_1fr_100px] border-b border-white/10 last:border-b-0">
            <div className="px-4 py-2">
              <select
                value={row.operator}
                onChange={(e) => updateField(table, index, "operator", e.target.value)}
                className="w-full px-2 py-1 text-sm bg-transparent border border-white/20 rounded text-white outline-none"
              >
                {index === 0 ? (
                  <option value="begin" className="bg-[#0a0a0a]">{i18next.t("rule:begin")}</option>
                ) : (
                  <>
                    <option value="and" className="bg-[#0a0a0a]">{i18next.t("rule:and")}</option>
                    <option value="or" className="bg-[#0a0a0a]">{i18next.t("rule:or")}</option>
                  </>
                )}
              </select>
            </div>
            <div className="px-4 py-2">
              <select
                value={row.value}
                onChange={(e) => updateField(table, index, "value", e.target.value)}
                className="w-full px-2 py-1 text-sm bg-transparent border border-white/20 rounded text-white outline-none"
              >
                <option value="" className="bg-[#0a0a0a]">--</option>
                {rules.map((item, idx) => (
                  <option key={idx} value={item} className="bg-[#0a0a0a]">{item}</option>
                ))}
              </select>
            </div>
            <div className="px-4 py-2 flex items-center gap-1">
              <button
                disabled={index === 0}
                onClick={() => upRow(index)}
                className="p-1 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                title="Up"
              >
                <ChevronUp className="w-4 h-4" />
              </button>
              <button
                disabled={index === table.length - 1}
                onClick={() => downRow(index)}
                className="p-1 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                title="Down"
              >
                <ChevronDown className="w-4 h-4" />
              </button>
              <button
                onClick={() => deleteRow(index)}
                className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                title="Delete"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default CompoundRule;
