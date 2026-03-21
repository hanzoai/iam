// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as TicketBackend from "./backend/TicketBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import moment from "moment";
import {Button} from "./components/ui/button";
import {Send, User} from "lucide-react";

function TicketEditPage(props) {
  const {account, history, match, location} = props;
  const orgNameFromUrl = props.organizationName ?? match.params.organizationName;
  const ticketNameFromUrl = match.params.ticketName;
  const [ticketName, setTicketName] = useState(ticketNameFromUrl);
  const [ticket, setTicket] = useState(null);
  const [mode] = useState(location.mode ?? "edit");
  const [messageText, setMessageText] = useState("");
  const [sending, setSending] = useState(false);

  useEffect(() => {
    TicketBackend.getTicket(orgNameFromUrl, ticketNameFromUrl).then(r => {
      if (r.data === null) { history.push("/404"); return; }
      if (r.data.messages === null) r.data.messages = [];
      setTicket(r.data);
    });
  }, []);

  function updateField(key, value) { setTicket({...ticket, [key]: value}); }

  function submitEdit(exitAfterSave) {
    TicketBackend.updateTicket(orgNameFromUrl, ticketName, Setting.deepCopy(ticket)).then(r => {
      if (r.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully saved")); setTicketName(ticket.name); if (exitAfterSave) history.push("/tickets"); else history.push(`/tickets/${ticket.owner}/${ticket.name}`); }
      else { Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${r.msg}`); updateField("name", ticketName); }
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function sendMessage() {
    if (!messageText.trim()) { Setting.showMessage("error", i18next.t("ticket:Please enter a message")); return; }
    setSending(true);
    const message = {author: account.name, text: messageText, timestamp: moment().format(), isAdmin: Setting.isAdminUser(account)};
    TicketBackend.addTicketMessage(orgNameFromUrl, ticketName, message).then(r => {
      if (r.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully sent")); setMessageText(""); setSending(false); TicketBackend.getTicket(orgNameFromUrl, ticketName).then(r2 => { if (r2.data) { if (r2.data.messages === null) r2.data.messages = []; setTicket(r2.data); } }); }
      else { Setting.showMessage("error", `${i18next.t("general:Failed to send")}: ${r.msg}`); setSending(false); }
    }).catch(error => { Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`); setSending(false); });
  }

  if (!ticket) return null;
  const isAdmin = Setting.isAdminUser(account);
  const isOwner = account.name === ticket.user;

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("ticket:New Ticket") : i18next.t("ticket:Edit Ticket")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          </div>
        </div>
        <div className="p-6 space-y-5">
          {[
            {label: i18next.t("general:Organization"), key: "owner", disabled: true},
            {label: i18next.t("general:Name"), key: "name", disabled: !isAdmin},
            {label: i18next.t("general:Display name"), key: "displayName"},
            {label: i18next.t("general:Created time"), key: "createdTime", disabled: true},
            {label: i18next.t("general:Updated time"), key: "updatedTime", disabled: true},
            {label: i18next.t("general:Title"), key: "title", disabled: !isAdmin && !isOwner},
            {label: i18next.t("general:User"), key: "user", disabled: true},
          ].map(({label, key, disabled}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={disabled} value={ticket[key] ?? ""} onChange={e => updateField(key, e.target.value)} />
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("provider:Content")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm min-h-[80px]" disabled={!isAdmin && !isOwner} value={ticket.content || ""} onChange={e => updateField("content", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:State")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!isAdmin && ticket.state === "Closed"} value={ticket.state} onChange={e => updateField("state", e.target.value)}>
              {["Open", "In Progress", "Resolved", "Closed"].map(s => <option key={s} value={s}>{i18next.t(`ticket:${s}`)}</option>)}
            </select>
          </div>
        </div>
      </div>

      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="px-6 py-4 border-b border-zinc-800">
          <h3 className="text-lg font-semibold text-white">{i18next.t("ticket:Messages")}</h3>
        </div>
        <div className="p-6 space-y-4">
          {(ticket.messages || []).map((msg, idx) => (
            <div key={idx} className="flex gap-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${msg.isAdmin ? "bg-blue-600" : "bg-green-600"}`}>
                <User className="w-4 h-4 text-white" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-white text-sm font-medium">{msg.author}</span>
                  {msg.isAdmin && <span className="px-1.5 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400">{i18next.t("general:Admin")}</span>}
                  <span className="text-zinc-500 text-xs">{Setting.getFormattedDate(msg.timestamp)}</span>
                </div>
                <p className="text-zinc-300 text-sm whitespace-pre-wrap break-words">{msg.text}</p>
              </div>
            </div>
          ))}
          <hr className="border-zinc-800" />
          <div className="flex gap-3">
            <textarea className="flex-1 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm min-h-[80px]" value={messageText} onChange={e => setMessageText(e.target.value)} placeholder={i18next.t("ticket:Type your message here...")}
              onKeyDown={e => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") sendMessage(); }} />
            <Button className="self-stretch" disabled={sending} onClick={sendMessage}><Send className="w-4 h-4 mr-1" />{i18next.t("general:Send")}</Button>
          </div>
          <p className="text-zinc-500 text-xs">{i18next.t("ticket:Press Ctrl+Enter to send")}</p>
        </div>
      </div>
    </div>
  );
}

export default TicketEditPage;
