// @ts-nocheck
import React, {useEffect, useState, useCallback} from "react";
import {Link} from "react-router-dom";
import {Plus, Pencil, Trash2, ChevronLeft, ChevronRight} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as TicketBackend from "./backend/TicketBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

function TicketListPage(props) {
  const {account, history} = props;
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});
  const [isAuthorized, setIsAuthorized] = useState(true);

  const fetchData = useCallback((params = {}) => {
    let field = params.searchedColumn || "";
    let value = params.searchText || "";
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;
    setLoading(true);
    TicketBackend.getTickets(Setting.isDefaultOrganizationSelected(account) ? "" : Setting.getRequestOrganization(account), pag.current, pag.pageSize, field, value, sf, so)
      .then((res) => {
        setLoading(false);
        if (res.status === "ok") { setData(res.data || []); setPagination({...pag, total: res.data2}); }
        else { if (Setting.isResponseDenied(res)) setIsAuthorized(false); else Setting.showMessage("error", res.msg); }
      });
  }, [account, pagination]);

  useEffect(() => { fetchData({pagination: {current: 1, pageSize: 10, total: 0}}); }, []);

  function addTicket() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(account);
    const t = {owner, name: `ticket_${randomName}`, createdTime: moment().format(), updatedTime: moment().format(), displayName: `New Ticket - ${randomName}`, user: account.name, title: "", content: "", state: "Open", messages: []};
    TicketBackend.addTicket(t).then((res) => {
      if (res.status === "ok") { history.push({pathname: `/tickets/${t.owner}/${t.name}`, mode: "add"}); Setting.showMessage("success", i18next.t("general:Successfully added")); }
      else Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function deleteTicket(i) {
    TicketBackend.deleteTicket(data[i]).then((res) => {
      if (res.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully deleted")); fetchData({pagination: {...pagination, current: pagination.current > 1 && data.length === 1 ? pagination.current - 1 : pagination.current}}); }
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handlePageChange(page) { const np = {...pagination, current: page}; setPagination(np); fetchData({pagination: np}); }

  if (!isAuthorized) { return (<div className="flex flex-col items-center justify-center py-20"><h1 className="text-2xl font-bold text-white mb-2">403 Unauthorized</h1><a href="/"><Button>{i18next.t("general:Back Home")}</Button></a></div>); }
  const totalPages = Math.ceil(pagination.total / pagination.pageSize);
  const stateColors = {Open: "bg-blue-900/50 text-blue-400", "In Progress": "bg-yellow-900/50 text-yellow-400", Resolved: "bg-green-900/50 text-green-400", Closed: "bg-zinc-800 text-zinc-500"};

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Tickets")}</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
          <Button size="sm" onClick={addTicket}><Plus className="w-4 h-4 mr-1" />{i18next.t("general:Add")}</Button>
        </div>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Created time")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Display name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Title")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:User")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:State")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={7} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               data.length === 0 ? (<tr><td colSpan={7} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>) :
               data.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  <td className="px-4 py-3"><Link to={`/tickets/${record.owner}/${record.name}`} className="text-blue-400 hover:text-blue-300">{record.name}</Link></td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.displayName}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.title}</td>
                  <td className="px-4 py-3"><Link to={`/users/${record.user}`} className="text-blue-400 hover:text-blue-300">{record.user}</Link></td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs ${stateColors[record.state] || "bg-zinc-800 text-zinc-500"}`}>{record.state}</span></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" onClick={() => history.push(`/tickets/${record.owner}/${record.name}`)}><Pencil className="w-3 h-3 mr-1" />{i18next.t("general:Edit")}</Button>
                      {Setting.isAdminUser(account) && <Button variant="destructive" size="sm" onClick={() => { if (window.confirm(`${i18next.t("general:Sure to delete")}: ${record.name} ?`)) deleteTicket(index); }}><Trash2 className="w-3 h-3 mr-1" />{i18next.t("general:Delete")}</Button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={pagination.current <= 1} onClick={() => handlePageChange(pagination.current - 1)}><ChevronLeft className="w-4 h-4" /></Button>
          <span className="text-sm text-zinc-400">{pagination.current} / {totalPages}</span>
          <Button variant="outline" size="sm" disabled={pagination.current >= totalPages} onClick={() => handlePageChange(pagination.current + 1)}><ChevronRight className="w-4 h-4" /></Button>
        </div>
      )}
    </div>
  );
}

export default TicketListPage;
