// @ts-nocheck
import React, {useEffect, useState} from "react";
import {Link} from "react-router-dom";
import * as Setting from "./Setting";
import * as LdapBackend from "./backend/LdapBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";
import {ChevronLeft, ChevronRight} from "lucide-react";

function LdapSyncPage(props) {
  const {history, match} = props;
  const ldapId = match.params.ldapId;
  const organizationName = match.params.organizationName;
  const [ldap, setLdap] = useState(null);
  const [users, setUsers] = useState([]);
  const [existUuids, setExistUuids] = useState([]);
  const [selectedUsers, setSelectedUsers] = useState([]);

  useEffect(() => {
    LdapBackend.getLdap(organizationName, ldapId).then(r => {
      if (r.status === "ok") {
        setLdap(r.data);
        LdapBackend.getLdapUser(organizationName, ldapId).then(r2 => {
          if (r2.status === "ok") { setUsers(r2.data.users || []); setExistUuids(r2.data.existUuids?.filter(u => u !== "") || []); }
          else Setting.showMessage("error", r2.msg);
        });
      } else Setting.showMessage("error", r.msg);
    });
  }, []);

  function syncUsers() {
    if (selectedUsers.length === 0) { Setting.showMessage("error", i18next.t("general:Please select at least 1 user first")); return; }
    LdapBackend.syncUsers(ldap.owner, ldap.id, selectedUsers).then(r => {
      if (r.status === "ok") {
        const exist = r.data.exist || [];
        const failed = r.data.failed || [];
        if (exist.length === 0 && failed.length === 0) { Setting.goToLink(`/organizations/${ldap.owner}/users`); }
        else {
          if (exist.length > 0) Setting.showMessage("error", `${i18next.t("general:User already exists")}: [${exist.map(e => e.cn).join(", ")}]`);
          if (failed.length > 0) Setting.showMessage("error", `${i18next.t("general:Failed to sync")}: [${failed.map(e => e.cn).join(", ")}]`);
        }
      } else Setting.showMessage("error", r.msg);
    });
  }

  function toggleUser(user) {
    if (existUuids.includes(user.uuid)) return;
    setSelectedUsers(prev => prev.find(u => u.uuid === user.uuid) ? prev.filter(u => u.uuid !== user.uuid) : [...prev, user]);
  }

  function toggleAll(checked) {
    if (checked) setSelectedUsers(users.filter(u => !existUuids.includes(u.uuid)));
    else setSelectedUsers([]);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{ldap?.serverName}</h2>
        <div className="flex items-center gap-2">
          <Button size="sm" disabled={selectedUsers.length === 0} onClick={() => { if (window.confirm("Please confirm to sync selected users")) syncUsers(); }}>{i18next.t("general:Sync")}</Button>
          <Button variant="outline" size="sm" onClick={() => Setting.goToLink(`/ldap/${organizationName}/${ldapId}`)}>{i18next.t("general:Edit")} LDAP</Button>
        </div>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="px-4 py-3 w-10"><input type="checkbox" className="accent-blue-600" onChange={e => toggleAll(e.target.checked)} checked={selectedUsers.length === users.filter(u => !existUuids.includes(u.uuid)).length && users.length > 0} /></th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("ldap:CN")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Uid</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">UidNumber</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("ldap:Group ID")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Email")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Phone")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("user:Address")}</th>
            </tr></thead>
            <tbody>
              {users.length === 0 ? (<tr><td colSpan={8} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               users.map((user) => {
                 const isSynced = existUuids.includes(user.uuid);
                 const isSelected = selectedUsers.find(u => u.uuid === user.uuid);
                 return (
                   <tr key={user.uuid} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                     <td className="px-4 py-3"><input type="checkbox" className="accent-blue-600" disabled={isSynced} checked={!!isSelected} onChange={() => toggleUser(user)} /></td>
                     <td className="px-4 py-3">
                       <div className="flex items-center justify-between">
                         <span className="text-zinc-300">{user.cn}</span>
                         <span className={`px-2 py-0.5 rounded text-xs ${isSynced ? "bg-green-900/50 text-green-400" : "bg-red-900/50 text-red-400"}`}>{isSynced ? i18next.t("ldap:synced") : i18next.t("ldap:unsynced")}</span>
                       </div>
                     </td>
                     <td className="px-4 py-3">{isSynced ? <Link to={`/users/${organizationName}/${user.uid}`} className="text-blue-400 hover:text-blue-300">{user.uid}</Link> : <span className="text-zinc-300">{user.uid}</span>}</td>
                     <td className="px-4 py-3 text-zinc-300">{user.uidNumber}</td>
                     <td className="px-4 py-3 text-zinc-300">{user.groupId}</td>
                     <td className="px-4 py-3 text-zinc-300">{user.email}</td>
                     <td className="px-4 py-3 text-zinc-300">{user.mobile}</td>
                     <td className="px-4 py-3 text-zinc-300">{user.address}</td>
                   </tr>
                 );
               })}
            </tbody>
          </table>
        </div>
      </div>
      <div className="flex gap-3 px-6">
        <Button size="lg" onClick={() => history.push(`/organizations/${organizationName}`)}>{i18next.t("general:Save & Exit")}</Button>
      </div>
    </div>
  );
}

export default LdapSyncPage;
