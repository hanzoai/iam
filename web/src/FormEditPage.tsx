// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as FormBackend from "./backend/FormBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import FormItemTable from "./table/FormItemTable";
import UserListPage from "./UserListPage";
import ApplicationListPage from "./ApplicationListPage";
import ProviderListPage from "./ProviderListPage";
import OrganizationListPage from "./OrganizationListPage";
import {Button} from "./components/ui/button";

function FormEditPage(props) {
  const {account, history, match} = props;
  const formNameFromUrl = match.params.formName;
  const [formName, setFormName] = useState(formNameFromUrl);
  const [form, setForm] = useState(null);

  useEffect(() => {
    FormBackend.getForm(account.owner, formNameFromUrl).then(r => { if (r.status === "ok") setForm(r.data); });
  }, []);

  function updateField(key, value) { setForm({...form, [key]: value}); }

  function submitEdit(exitAfterSave) {
    FormBackend.updateForm(form.owner, formName, Setting.deepCopy(form)).then(r => {
      if (r.status === "ok") {
        if (r.data) { Setting.showMessage("success", i18next.t("general:Successfully saved")); setFormName(form.name); if (exitAfterSave) history.push("/forms"); else history.push(`/forms/${form.name}`); }
        else { Setting.showMessage("error", i18next.t("general:Failed to save")); updateField("name", formName); }
      } else Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${r.msg}`);
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${error}`));
  }

  if (!form) return null;

  const listPageMap = {users: UserListPage, applications: ApplicationListPage, providers: ProviderListPage, organizations: OrganizationListPage};
  const ListPageComponent = listPageMap[form.type];

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{i18next.t("form:Edit Form")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          </div>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={form.name} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Display name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={form.displayName || ""} onChange={e => updateField("displayName", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={form.type || ""} onChange={e => {
              const v = e.target.value; updateField("type", v); updateField("name", v); updateField("displayName", v);
              const defaultItems = new FormItemTable({formType: v}).getItems(); updateField("formItems", defaultItems);
            }}>
              {Setting.getFormTypeOptions().map(opt => <option key={opt.id} value={opt.id}>{i18next.t(opt.name)}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("user:Tag")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={form.tag || ""} onChange={e => { updateField("tag", e.target.value); updateField("name", e.target.value ? `${form.type}-tag-${e.target.value}` : form.type); }} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("form:Form items")}</label>
            <FormItemTable title={i18next.t("form:Form items")} table={form.formItems} onUpdateTable={v => updateField("formItems", v)} formType={form.type} />
          </div>
          {ListPageComponent && (
            <div className="grid grid-cols-[160px_1fr] items-start gap-4">
              <label className="text-sm text-zinc-400 pt-2">{i18next.t("general:Preview")}</label>
              <div className="relative border border-zinc-700 h-[600px] cursor-pointer overflow-hidden" onClick={() => Setting.openLink(`/${form.type}`)}>
                <div className="h-full overflow-auto">
                  <div className="inline-block relative z-[1] pointer-events-none">
                    <ListPageComponent {...props} formItems={form.formItems} />
                  </div>
                </div>
                <div className="absolute inset-0 z-10 bg-black/40 pointer-events-none" />
              </div>
            </div>
          )}
        </div>
      </div>
      <div className="flex gap-3 px-6">
        <Button variant="outline" size="lg" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
        <Button size="lg" onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
      </div>
    </div>
  );
}

export default FormEditPage;
