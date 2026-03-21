// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as Setting from "./Setting";
import * as RuleBackend from "./backend/RuleBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import i18next from "i18next";
import WafRuleTable from "./table/WafRuleTable";
import IpRuleTable from "./table/IpRuleTable";
import UaRuleTable from "./table/UaRuleTable";
import IpRateRuleTable from "./table/IpRateRuleTable";
import CompoundRule from "./common/CompoundRule";
import {Button} from "./components/ui/button";

function RuleEditPage(props) {
  const {account, history, match} = props;
  const owner = match.params.organizationName;
  const ruleNameFromUrl = match.params.ruleName;
  const [ruleName, setRuleName] = useState(ruleNameFromUrl);
  const [rule, setRule] = useState(null);
  const [organizations, setOrganizations] = useState([]);

  useEffect(() => {
    RuleBackend.getRule(owner, ruleNameFromUrl).then((res) => setRule(res.data));
    if (Setting.isAdminUser(account)) OrganizationBackend.getOrganizations("admin").then((res) => setOrganizations(res.data || []));
  }, []);

  function updateField(key, value) {
    const r = Setting.deepCopy(rule);
    r[key] = value;
    if (key === "type") r.expressions = [];
    setRule(r);
  }

  function submitEdit() {
    RuleBackend.updateRule(owner, ruleName, Setting.deepCopy(rule)).then((res) => {
      if (res.status !== "error") { Setting.showMessage("success", "Rule updated successfully"); setRule(rule); }
      else { Setting.showMessage("error", `Rule failed to update: ${res.msg}`); setRuleName(rule.name); history.push(`/rules/${rule.owner}/${rule.name}`); }
    });
  }

  if (!rule) return null;

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{i18next.t("rule:Edit Rule")}</h2>
          <Button onClick={submitEdit}>{i18next.t("general:Save")}</Button>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={rule.owner} onChange={e => updateField("owner", e.target.value)}>
              {organizations.map(org => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={rule.name} onChange={e => updateField("name", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("rule:Type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={rule.type} onChange={e => updateField("type", e.target.value)}>
              {[{value: "WAF", text: "WAF"}, {value: "IP", text: "IP"}, {value: "User-Agent", text: "User-Agent"}, {value: "IP Rate Limiting", text: i18next.t("rule:IP Rate Limiting")}, {value: "Compound", text: i18next.t("rule:Compound")}].map(item => <option key={item.value} value={item.value}>{item.text}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("rule:Expressions")}</label>
            <div>
              {rule.type === "WAF" && <WafRuleTable title="Seclang" table={rule.expressions} ruleName={rule.name} account={account} onUpdateTable={v => updateField("expressions", v)} />}
              {rule.type === "IP" && <IpRuleTable title="IPs" table={rule.expressions} ruleName={rule.name} account={account} onUpdateTable={v => updateField("expressions", v)} />}
              {rule.type === "User-Agent" && <UaRuleTable title="User-Agents" table={rule.expressions} ruleName={rule.name} account={account} onUpdateTable={v => updateField("expressions", v)} />}
              {rule.type === "IP Rate Limiting" && <IpRateRuleTable title={i18next.t("rule:IP Rate Limiting")} table={rule.expressions} ruleName={rule.name} account={account} onUpdateTable={v => updateField("expressions", v)} />}
              {rule.type === "Compound" && <CompoundRule title={i18next.t("rule:Compound")} table={rule.expressions} ruleName={rule.name} owner={owner} onUpdateTable={v => updateField("expressions", v)} />}
            </div>
          </div>
          {rule.type !== "WAF" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("general:Action")}</label>
              <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={rule.action} onChange={e => updateField("action", e.target.value)}>
                <option value="Allow">{i18next.t("rule:Allow")}</option>
                <option value="Block">{i18next.t("rule:Block")}</option>
              </select>
            </div>
          )}
          {rule.type !== "WAF" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("rule:Status code")}</label>
              <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" min={100} max={599} value={rule.statusCode || ""} onChange={e => updateField("statusCode", parseInt(e.target.value) || 0)} />
            </div>
          )}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("rule:Reason")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={rule.reason || ""} onChange={e => updateField("reason", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("rule:Verbose mode")}</label>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" checked={rule.isVerbose} onChange={e => updateField("isVerbose", e.target.checked)} />
              <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
            </label>
          </div>
        </div>
      </div>
      <div className="flex gap-3 px-6">
        <Button size="lg" onClick={submitEdit}>{i18next.t("general:Save")}</Button>
      </div>
    </div>
  );
}

export default RuleEditPage;
