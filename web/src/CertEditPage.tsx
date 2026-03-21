// @ts-nocheck
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

import React, {useEffect, useState} from "react";
import * as CertBackend from "./backend/CertBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import copy from "copy-to-clipboard";
import FileSaver from "file-saver";
import {Button} from "./components/ui/button";
import {Copy, Download, Eye, EyeOff} from "lucide-react";

interface CertEditPageProps {
  account: any;
  history: any;
  match: any;
  location: any;
  organizationName?: string;
}

function CertEditPage(props: CertEditPageProps) {
  const {account, history, match, location} = props;
  const ownerFromProps = props.organizationName ?? match.params.organizationName;
  const certNameFromUrl = match.params.certName;

  const [certName, setCertName] = useState(certNameFromUrl);
  const [cert, setCert] = useState<any>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [mode] = useState(location.mode ?? "edit");
  const [showSecret, setShowSecret] = useState(false);

  useEffect(() => {
    getCert();
    getOrganizations();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getCert() {
    CertBackend.getCert(ownerFromProps, certNameFromUrl).then((res: any) => {
      if (res.data === null) { history.push("/404"); return; }
      if (res.status === "error") { Setting.showMessage("error", res.msg); return; }
      setCert(res.data);
    });
  }

  function getOrganizations() {
    OrganizationBackend.getOrganizations("admin").then((res: any) => {
      setOrganizations(res.data || []);
    });
  }

  function updateField(key: string, value: any) {
    if (["port"].includes(key)) value = Setting.myParseInt(value);
    const updated = {...cert};
    const previousType = updated.type;
    if (key === "type") {
      if (value === "SSL") {
        updated.cryptoAlgorithm = "RSA";
        updated.certificate = "";
        updated.privateKey = "";
      } else if (previousType === "SSL" && value !== "SSL") {
        updated.provider = ""; updated.account = ""; updated.accessKey = "";
        updated.accessSecret = ""; updated.certificate = ""; updated.privateKey = "";
        updated.expireTime = ""; updated.domainExpireTime = "";
      }
    }
    updated[key] = value;
    setCert(updated);
  }

  function submitEdit(exitAfterSave: boolean) {
    const certCopy = Setting.deepCopy(cert);
    CertBackend.updateCert(ownerFromProps, certName, certCopy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setCertName(cert.name);
        if (exitAfterSave) { history.push("/certs"); }
        else { history.push(`/certs/${cert.owner}/${cert.name}`); getCert(); }
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
        updateField("name", certName);
      }
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  function handleDelete() {
    CertBackend.deleteCert(cert).then((res: any) => {
      if (res.status === "ok") { history.push("/certs"); }
      else { Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`); }
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  if (!cert) return null;

  const cryptoOptions = cert.type === "SSL"
    ? [{id: "RSA", name: "RSA"}, {id: "ECC", name: "ECC"}]
    : [
      {id: "RS256", name: "RS256 (RSA + SHA256)"}, {id: "RS384", name: "RS384 (RSA + SHA384)"},
      {id: "RS512", name: "RS512 (RSA + SHA512)"}, {id: "ES256", name: "ES256 (ECDSA using P-256 + SHA256)"},
      {id: "ES384", name: "ES384 (ECDSA using P-384 + SHA384)"}, {id: "ES512", name: "ES512 (ECDSA using P-521 + SHA512)"},
      {id: "PS256", name: "PS256 (RSASSA-PSS using SHA256 and MGF1 with SHA256)"},
      {id: "PS384", name: "PS384 (RSASSA-PSS using SHA384 and MGF1 with SHA384)"},
      {id: "PS512", name: "PS512 (RSASSA-PSS using SHA512 and MGF1 with SHA512)"},
    ];

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">
            {mode === "add" ? i18next.t("cert:New Cert") : i18next.t("cert:Edit Cert")}
          </h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>

        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={cert.owner} onChange={e => updateField("owner", e.target.value)}>
              {Setting.isAdminUser(account) && <option value="admin">{i18next.t("provider:admin (Shared)")}</option>}
              {organizations.map((org: any) => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.name} onChange={e => updateField("name", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Display name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.displayName} onChange={e => updateField("displayName", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("provider:Scope")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.scope} onChange={e => updateField("scope", e.target.value)}>
              <option value="JWT">JWT</option>
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.type} onChange={e => updateField("type", e.target.value)}>
              <option value="SSL">SSL</option>
              <option value="x509">x509</option>
              <option value="Payment">Payment</option>
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("cert:Crypto algorithm")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.cryptoAlgorithm} onChange={e => {
              const val = e.target.value;
              updateField("cryptoAlgorithm", val);
              if (val.startsWith("ES")) { updateField("bitSize", 0); }
              else if (cert.bitSize !== 1024 && cert.bitSize !== 2048 && cert.bitSize !== 4096) { updateField("bitSize", 2048); }
              updateField("certificate", ""); updateField("privateKey", "");
            }}>
              {cryptoOptions.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </div>

          {!cert.cryptoAlgorithm.startsWith("ES") && cert.type !== "SSL" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("cert:Bit size")}</label>
              <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.bitSize} onChange={e => {
                updateField("bitSize", parseInt(e.target.value));
                updateField("certificate", ""); updateField("privateKey", "");
              }}>
                {Setting.getCryptoAlgorithmOptions(cert.cryptoAlgorithm).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </div>
          )}

          {cert.type !== "SSL" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("cert:Expire in years")}</label>
              <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.expireInYears} onChange={e => updateField("expireInYears", parseInt(e.target.value) || 0)} />
            </div>
          )}

          {cert.type === "SSL" && (
            <>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Expire time")}</label>
                <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={Setting.getFormattedDate(cert.expireTime)} readOnly />
              </div>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Domain expire")}</label>
                <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={Setting.getFormattedDate(cert.domainExpireTime)} readOnly />
              </div>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Provider")}</label>
                <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.provider || ""} onChange={e => updateField("provider", e.target.value)}>
                  <option value="GoDaddy">GoDaddy</option>
                  <option value="Aliyun">Aliyun</option>
                </select>
              </div>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Account")}</label>
                <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.account || ""} onChange={e => updateField("account", e.target.value)} />
              </div>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Access key")}</label>
                <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={cert.accessKey || ""} onChange={e => updateField("accessKey", e.target.value)} />
              </div>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Access secret")}</label>
                <div className="relative">
                  <input type={showSecret ? "text" : "password"} className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm pr-10" value={cert.accessSecret || ""} onChange={e => updateField("accessSecret", e.target.value)} />
                  <button className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white" onClick={() => setShowSecret(!showSecret)}>
                    {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Certificate")}</label>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={!cert.certificate} onClick={() => { copy(cert.certificate); Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully")); }}>
                    <Copy className="w-3 h-3 mr-1" />{i18next.t("cert:Copy certificate")}
                  </Button>
                  <Button size="sm" disabled={!cert.certificate} onClick={() => { const blob = new Blob([cert.certificate], {type: "text/plain;charset=utf-8"}); FileSaver.saveAs(blob, "token_jwt_key.pem"); }}>
                    <Download className="w-3 h-3 mr-1" />{i18next.t("cert:Download certificate")}
                  </Button>
                </div>
              </div>
              <textarea className="w-full h-[400px] bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-xs font-mono resize-none" value={cert.certificate} onChange={e => updateField("certificate", e.target.value)} />
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-zinc-400">{i18next.t("cert:Private key")}</label>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={!cert.privateKey} onClick={() => { copy(cert.privateKey); Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully")); }}>
                    <Copy className="w-3 h-3 mr-1" />{i18next.t("cert:Copy private key")}
                  </Button>
                  <Button size="sm" disabled={!cert.privateKey} onClick={() => { const blob = new Blob([cert.privateKey], {type: "text/plain;charset=utf-8"}); FileSaver.saveAs(blob, "token_jwt_key.key"); }}>
                    <Download className="w-3 h-3 mr-1" />{i18next.t("cert:Download private key")}
                  </Button>
                </div>
              </div>
              <textarea className="w-full h-[400px] bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-xs font-mono resize-none" value={cert.privateKey} onChange={e => updateField("privateKey", e.target.value)} />
            </div>
          </div>
        </div>
      </div>

      <div className="flex gap-3 px-6">
        <Button variant="outline" size="lg" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
        <Button size="lg" onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
        {mode === "add" && <Button variant="outline" size="lg" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
      </div>
    </div>
  );
}

export default CertEditPage;
