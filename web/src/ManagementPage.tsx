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
import * as Setting from "./Setting";
import EnableMfaNotification from "./common/notifaction/EnableMfaNotification";
import {Link, Redirect, Route, Switch, withRouter} from "react-router-dom";
import React, {useState} from "react";
import i18next from "i18next";
import {
  AppWindow,
  ChevronDown,
  CircleCheck,
  Cpu,
  Home,
  KeyRound,
  LogOut,
  Menu as MenuIcon,
  Settings,
  ShieldCheck,
  Wallet,
} from "lucide-react";
import {Button} from "./components/ui/button";
import {Card} from "./components/ui/card";
import {Avatar, AvatarFallback, AvatarImage} from "./components/ui/avatar";
import {Sheet, SheetContent, SheetHeader, SheetTitle} from "./components/ui/sheet";
import {Spinner} from "./components/ui/spinner";
import {Tooltip, TooltipContent, TooltipProvider, TooltipTrigger} from "./components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./components/ui/dropdown-menu";
import {cn} from "./lib/utils";
import Dashboard from "./basic/Dashboard";
import AppListPage from "./basic/AppListPage";
import ShortcutsPage from "./basic/ShortcutsPage";
import AccountPage from "./account/AccountPage";
import OrganizationListPage from "./OrganizationListPage";
import OrganizationEditPage from "./OrganizationEditPage";
import UserListPage from "./UserListPage";
import GroupTreePage from "./GroupTreePage";
import GroupListPage from "./GroupListPage";
import GroupEditPage from "./GroupEditPage";
import UserEditPage from "./UserEditPage";
import InvitationListPage from "./InvitationListPage";
import InvitationEditPage from "./InvitationEditPage";
import ApplicationListPage from "./ApplicationListPage";
import ApplicationEditPage from "./ApplicationEditPage";
import ProviderListPage from "./ProviderListPage";
import ProviderEditPage from "./ProviderEditPage";
import RecordListPage from "./RecordListPage";
import ResourceListPage from "./ResourceListPage";
import CertListPage from "./CertListPage";
import CertEditPage from "./CertEditPage";
import KeyListPage from "./KeyListPage";
import KeyEditPage from "./KeyEditPage";
import RoleListPage from "./RoleListPage";
import RoleEditPage from "./RoleEditPage";
import PermissionListPage from "./PermissionListPage";
import PermissionEditPage from "./PermissionEditPage";
import ModelListPage from "./ModelListPage";
import ModelEditPage from "./ModelEditPage";
import AdapterListPage from "./AdapterListPage";
import AdapterEditPage from "./AdapterEditPage";
import EnforcerListPage from "./EnforcerListPage";
import EnforcerEditPage from "./EnforcerEditPage";
import SessionListPage from "./SessionListPage";
import TokenListPage from "./TokenListPage";
import TokenEditPage from "./TokenEditPage";
import SystemInfo from "./SystemInfo";
import FormListPage from "./FormListPage";
import FormEditPage from "./FormEditPage";
import SyncerListPage from "./SyncerListPage";
import SyncerEditPage from "./SyncerEditPage";
import WebhookListPage from "./WebhookListPage";
import WebhookEditPage from "./WebhookEditPage";
import LdapEditPage from "./LdapEditPage";
import LdapSyncPage from "./LdapSyncPage";
import MfaSetupPage from "./auth/MfaSetupPage";
import OdicDiscoveryPage from "./auth/OidcDiscoveryPage";
import * as Conf from "./Conf";
import LanguageSelect from "./common/select/LanguageSelect";
import ThemeSelect from "./common/select/ThemeSelect";
import OpenTour from "./common/OpenTour";
import OrganizationSelect from "./common/select/OrganizationSelect";
import AccountAvatar from "./account/AccountAvatar";
import * as AuthBackend from "./auth/AuthBackend";
import {clearWeb3AuthToken} from "./auth/Web3Auth";
import VerificationListPage from "./VerificationListPage";
import TicketListPage from "./TicketListPage";
import TicketEditPage from "./TicketEditPage";
import * as Cookie from "cookie";
import * as UserBackend from "./backend/UserBackend";
import SiteListPage from "./SiteListPage";
import SiteEditPage from "./SiteEditPage";
import ServerListPage from "./ServerListPage";
import ServerEditPage from "./ServerEditPage";
import RuleEditPage from "./RuleEditPage";
import RuleListPage from "./RuleListPage";

function ManagementPage(props) {
  const [menuVisible, setMenuVisible] = useState(false);
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const organization = props.account?.organization;
  const navItems = Setting.isLocalAdminUser(props.account) ? organization?.navItems : (organization?.userNavItems ?? []);
  const widgetItems = organization?.widgetItems;
  const isDark = props.themeAlgorithm?.includes("dark");

  function logout() {
    AuthBackend.logout()
      .then((res) => {
        if (res.status === "ok") {
          const owner = props.account.owner;
          props.setLogoutState();
          clearWeb3AuthToken();
          Setting.showMessage("success", i18next.t("application:Logged out successfully"));
          const redirectUri = res.data2;
          if (redirectUri !== null && redirectUri !== undefined && redirectUri !== "") {
            Setting.goToLink(redirectUri);
          } else if (owner !== "built-in") {
            Setting.goToLink(`${window.location.origin}/login/${owner}`);
          } else {
            Setting.goToLinkSoft({props}, "/");
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to log out")}: ${res.msg}`);
        }
      });
  }

  function renderAvatar() {
    const name = props.account.name;
    const short = Setting.getShortName(name);
    if (props.account.avatar === "") {
      return (
        <Avatar className="h-10 w-10 align-middle" style={{backgroundColor: Setting.getAvatarColor(name)}}>
          <AvatarFallback className="bg-transparent text-white">{short}</AvatarFallback>
        </Avatar>
      );
    }
    return (
      <Avatar className="h-10 w-10 align-middle">
        <AvatarImage src={props.account.avatar} alt={name} />
        <AvatarFallback>
          <AccountAvatar src={props.account.avatar} style={{verticalAlign: "middle"}} size={40} />
        </AvatarFallback>
      </Avatar>
    );
  }

  function renderRightDropdown() {
    const curCookie = Cookie.parse(document.cookie);
    const impersonating = !!curCookie["impersonateUser"];

    const onAccount = () => props.history.push("/account");
    const onLogout = () => logout();
    const onExitImpersonation = () => {
      UserBackend.exitImpersonateUser().then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("account:Exit impersonation"));
          Setting.goToLinkSoft({props}, "/");
          window.location.reload();
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
    };

    return (
      <DropdownMenu key="/rightDropDown">
        <DropdownMenuTrigger asChild>
          <button className="rightDropDown inline-flex items-center gap-2 px-2 py-1 rounded-md hover:bg-accent/50 focus:outline-none">
            {renderAvatar()}
            {Setting.isMobile() ? null : (
              <span className="ml-1">
                {Setting.getShortText(Setting.getNameAtLeast(props.account.displayName), 30)}
              </span>
            )}
            <ChevronDown className="h-3.5 w-3.5 opacity-70" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-[180px]">
          {props.requiredEnableMfa === false && (
            <DropdownMenuItem onSelect={onAccount}>
              <Settings className="mr-2 h-4 w-4" />
              {i18next.t("account:My Account")}
            </DropdownMenuItem>
          )}
          {impersonating ? (
            <DropdownMenuItem onSelect={onExitImpersonation}>
              <LogOut className="mr-2 h-4 w-4" />
              {i18next.t("account:Exit impersonation")}
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem onSelect={onLogout}>
              <LogOut className="mr-2 h-4 w-4" />
              {i18next.t("account:Logout")}
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    );
  }

  function navItemsIsAll() {
    return !Array.isArray(navItems) || !!navItems?.includes("all");
  }

  function widgetItemsIsAll() {
    return !Array.isArray(widgetItems) || !!widgetItems?.includes("all");
  }

  function isSpecialMenuItem(item) {
    return item.key === "#" || item.key === "logo";
  }

  function renderWidgets() {
    const widgets = [
      Setting.getItem(<ThemeSelect themeAlgorithm={props.themeAlgorithm} onChange={props.setLogoAndThemeAlgorithm} />, "theme"),
      Setting.getItem(<LanguageSelect languages={props.account.organization.languages} />, "language"),
      Setting.getItem(Conf.AiAssistantUrl?.trim() && (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="select-box cursor-pointer" onClick={props.openAiAssistant}>
                <Cpu className="h-6 w-6" />
              </div>
            </TooltipTrigger>
            <TooltipContent>Click to open AI assistant</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ), "ai-assistant"),
      Setting.getItem(<OpenTour />, "tour"),
    ];

    if (widgetItemsIsAll()) {
      return widgets.map(item => <React.Fragment key={item.key}>{item.label}</React.Fragment>);
    }

    return widgets
      .filter(item => widgetItems.includes(item.key))
      .map(item => <React.Fragment key={item.key}>{item.label}</React.Fragment>);
  }

  function renderAccountMenu() {
    if (props.account === undefined) {
      return null;
    } else if (props.account === null) {
      return (
        <React.Fragment>
          <LanguageSelect />
        </React.Fragment>
      );
    } else {
      return (
        <React.Fragment>
          {renderRightDropdown()}
          {renderWidgets()}
          {Setting.isAdminUser(props.account) && (props.uri.indexOf("/trees") === -1) &&
            <OrganizationSelect
              initValue={Setting.getOrganization()}
              withAll={true}
              className="org-select"
              style={{display: Setting.isMobile() ? "none" : "flex"}}
              onChange={(value) => {
                Setting.setOrganization(value);
              }}
            />
          }
        </React.Fragment>
      );
    }
  }

  // Build top-level menu groups. Each group is `{label, key, icon, children, href}`
  // where `children` is the list of leaf items `{label, key, href, external?}`.
  // Keeping this shape compatible with the navItems filter (item.key + item.children[].key)
  // means the org-side allow-list logic is preserved unchanged.
  function getMenuItems() {
    if (props.account === null || props.account === undefined) {
      return [];
    }

    const res = [];
    const iconClass = "h-4 w-4";

    let logo = props.account.organization.logo ? props.account.organization.logo : Setting.getLogo(props.themeAlgorithm);
    if (isDark && props.account.organization.logoDark) {
      logo = props.account.organization.logoDark;
    }

    if (!Setting.isMobile()) {
      res.push({
        key: "logo",
        logo: logo ?? props.logo,
        isLogo: true,
      });
    }

    res.push({
      key: "/home",
      label: i18next.t("general:Home"),
      href: "/",
      icon: <Home className={iconClass} />,
      children: [
        {key: "/", label: i18next.t("general:Dashboard"), href: "/"},
        {key: "/shortcuts", label: i18next.t("general:Shortcuts"), href: "/shortcuts"},
        {key: "/apps", label: i18next.t("general:Apps"), href: "/apps"},
      ],
    });

    if (Setting.isLocalAdminUser(props.account) && Conf.ShowGithubCorner) {
      res.push({
        key: "#",
        isPromo: true,
      });
    }

    res.push({
      key: "/orgs",
      label: i18next.t("general:User Management"),
      href: "/organizations",
      icon: <AppWindow className={iconClass} />,
      children: [
        {key: "/organizations", label: i18next.t("general:Organizations"), href: "/organizations"},
        {key: "/groups", label: i18next.t("general:Groups"), href: "/groups"},
        {key: "/users", label: i18next.t("general:Users"), href: "/users"},
        {key: "/invitations", label: i18next.t("general:Invitations"), href: "/invitations"},
      ],
    });

    res.push({
      key: "/identity",
      label: i18next.t("general:Identity"),
      href: "/applications",
      icon: <KeyRound className={iconClass} />,
      children: [
        {key: "/applications", label: i18next.t("general:Applications"), href: "/applications"},
        {key: "/providers", label: i18next.t("application:Providers"), href: "/providers"},
        {key: "/resources", label: i18next.t("general:Resources"), href: "/resources"},
        {key: "/certs", label: i18next.t("general:Certs"), href: "/certs"},
        {key: "/keys", label: i18next.t("general:Keys"), href: "/keys"},
        {key: "/sites", label: i18next.t("general:Sites"), href: "/sites"},
        {key: "/rules", label: i18next.t("general:Rules"), href: "/rules"},
      ],
    });

    const authChildren = [
      {key: "/roles", label: i18next.t("general:Roles"), href: "/roles"},
      {key: "/permissions", label: i18next.t("general:Permissions"), href: "/permissions"},
      {key: "/models", label: i18next.t("general:Models"), href: "/models"},
      {key: "/adapters", label: i18next.t("general:Adapters"), href: "/adapters"},
      {key: "/enforcers", label: i18next.t("general:Enforcers"), href: "/enforcers"},
    ].filter(item => {
      if (!Setting.isLocalAdminUser(props.account) && ["/models", "/adapters", "/enforcers"].includes(item.key)) {
        return false;
      }
      return true;
    });

    res.push({
      key: "/auth",
      label: i18next.t("general:Authorization"),
      href: "/roles",
      icon: <ShieldCheck className={iconClass} />,
      children: authChildren,
    });

    res.push({
      key: "/gateway",
      label: i18next.t("general:Gateway"),
      href: "/sites",
      icon: <CircleCheck className={iconClass} />,
      children: [
        {key: "/servers", label: i18next.t("general:MCP Servers"), href: "/servers"},
        {key: "/sites", label: i18next.t("general:Sites"), href: "/sites"},
        {key: "/certs", label: i18next.t("general:Certs"), href: "/certs"},
        {key: "/rules", label: i18next.t("general:Rules"), href: "/rules"},
      ],
    });

    res.push({
      key: "/logs",
      label: i18next.t("general:Logging & Auditing"),
      href: "/sessions",
      icon: <Wallet className={iconClass} />,
      children: [
        {key: "/sessions", label: i18next.t("general:Sessions"), href: "/sessions"},
        {key: "/records", label: i18next.t("general:Records"), href: "/records"},
        {key: "/tokens", label: i18next.t("general:Tokens"), href: "/tokens"},
        {key: "/verifications", label: i18next.t("general:Verifications"), href: "/verifications"},
      ],
    });

    if (Setting.isAdminUser(props.account)) {
      res.push({
        key: "/admin",
        label: i18next.t("general:Admin"),
        href: "/sysinfo",
        icon: <Settings className={iconClass} />,
        children: [
          {key: "/sysinfo", label: i18next.t("general:System Info"), href: "/sysinfo"},
          {key: "/forms", label: i18next.t("general:Forms"), href: "/forms"},
          {key: "/syncers", label: i18next.t("general:Syncers"), href: "/syncers"},
          {key: "/webhooks", label: i18next.t("general:Webhooks"), href: "/webhooks"},
          {key: "/tickets", label: i18next.t("general:Tickets"), href: "/tickets"},
          {key: "/swagger", label: i18next.t("general:Swagger"), href: Setting.isLocalhost() ? `${Setting.ServerUrl}/swagger` : "/swagger", external: true},
        ],
      });
    } else {
      res.push({
        key: "/admin",
        label: i18next.t("general:Admin"),
        href: "/syncers",
        icon: <Settings className={iconClass} />,
        children: [
          {key: "/forms", label: i18next.t("general:Forms"), href: "/forms"},
          {key: "/syncers", label: i18next.t("general:Syncers"), href: "/syncers"},
          {key: "/webhooks", label: i18next.t("general:Webhooks"), href: "/webhooks"},
          {key: "/tickets", label: i18next.t("general:Tickets"), href: "/tickets"},
        ],
      });
    }

    if (navItemsIsAll()) {
      return res;
    }

    const resFiltered = res.map(item => {
      if (!Array.isArray(item.children)) {
        return item;
      }
      const filteredChildren = item.children.filter(itemChild => navItems.includes(itemChild.key));
      return {...item, children: filteredChildren};
    });

    const filteredResult = resFiltered.filter(item => {
      if (isSpecialMenuItem(item)) {return true;}
      return Array.isArray(item.children) && item.children.length > 0;
    });

    // Count total end items (leaf nodes); flatten when <= MaxItemsForFlatMenu.
    let totalEndItems = 0;
    filteredResult.forEach(item => {
      if (Array.isArray(item.children)) {
        totalEndItems += item.children.length;
      }
    });

    if (totalEndItems <= Conf.MaxItemsForFlatMenu) {
      const flattenedResult = [];
      filteredResult.forEach(item => {
        if (isSpecialMenuItem(item)) {
          flattenedResult.push(item);
        } else if (Array.isArray(item.children)) {
          item.children.forEach(child => flattenedResult.push(child));
        }
      });
      return flattenedResult;
    }

    return filteredResult;
  }

  function isItemSelected(item) {
    const sel = props.selectedMenuKey;
    if (!sel) {return false;}
    if (item.key === sel) {return true;}
    if (Array.isArray(item.children)) {
      return item.children.some(c => c.key === sel);
    }
    return false;
  }

  function renderLeafLink(child, onNavigate?: () => void) {
    const cls = cn(
      "block w-full px-3 py-1.5 text-sm rounded hover:bg-accent",
      props.selectedMenuKey === child.key && "bg-accent font-medium"
    );
    if (child.external) {
      return (
        <a
          key={child.key}
          href={child.href}
          target="_blank"
          rel="noreferrer"
          className={cls}
          onClick={onNavigate}
        >
          {child.label}
        </a>
      );
    }
    return (
      <Link key={child.key} to={child.href} className={cls} onClick={onNavigate}>
        {child.label}
      </Link>
    );
  }

  function renderDesktopMenu() {
    const items = getMenuItems();
    return (
      <nav className="flex flex-1 items-center gap-1 overflow-hidden">
        {items.map(item => {
          if (item.key === "logo") {
            return (
              <Link key="logo" to="/" className="flex items-center pr-2">
                <img className="logo h-8" src={item.logo} alt="logo" />
              </Link>
            );
          }
          if (item.key === "#") {
            return (
              <a key="#" href="https://iam.com" className="ml-1">
                <span
                  className="font-bold rounded px-1.5 flex items-center h-10"
                  style={{backgroundColor: "rgba(87,52,211,0.4)"}}
                >
                  🚀 SaaS Hosting 🔥
                </span>
              </a>
            );
          }
          // Leaf-after-flatten item (no children) — render as direct link.
          if (!Array.isArray(item.children) || item.children.length === 0) {
            return (
              <Link
                key={item.key}
                to={item.href}
                className={cn(
                  "inline-flex items-center gap-2 px-3 h-10 rounded-md text-sm hover:bg-accent",
                  props.selectedMenuKey === item.key && "bg-accent font-medium"
                )}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            );
          }
          return (
            <DropdownMenu key={item.key}>
              <DropdownMenuTrigger asChild>
                <button
                  className={cn(
                    "inline-flex items-center gap-2 px-3 h-10 rounded-md text-sm hover:bg-accent focus:outline-none",
                    isItemSelected(item) && "bg-accent font-medium"
                  )}
                >
                  {item.icon}
                  <span>{item.label}</span>
                  <ChevronDown className="h-3.5 w-3.5 opacity-70" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="min-w-[180px]">
                {item.children.map(child => (
                  <DropdownMenuItem key={child.key} asChild>
                    {child.external ? (
                      <a href={child.href} target="_blank" rel="noreferrer">{child.label}</a>
                    ) : (
                      <Link to={child.href}>{child.label}</Link>
                    )}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          );
        })}
      </nav>
    );
  }

  function renderMobileMenu() {
    const items = getMenuItems();
    const onNavigate = () => setMenuVisible(false);
    return (
      <nav className="flex flex-col gap-1">
        {items.map(item => {
          if (item.key === "logo" || item.key === "#") {
            return null;
          }
          if (!Array.isArray(item.children) || item.children.length === 0) {
            return (
              <Link
                key={item.key}
                to={item.href}
                onClick={onNavigate}
                className={cn(
                  "flex items-center gap-2 px-3 py-2 rounded-md text-sm hover:bg-accent",
                  props.selectedMenuKey === item.key && "bg-accent font-medium"
                )}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            );
          }
          const expanded = openGroup === item.key || isItemSelected(item);
          return (
            <div key={item.key} className="flex flex-col">
              <button
                type="button"
                onClick={() => setOpenGroup(expanded ? null : item.key)}
                className={cn(
                  "flex items-center gap-2 px-3 py-2 rounded-md text-sm hover:bg-accent text-left",
                  isItemSelected(item) && "font-medium"
                )}
              >
                {item.icon}
                <span className="flex-1">{item.label}</span>
                <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-180")} />
              </button>
              {expanded && (
                <ul className="ml-6 mt-1 flex flex-col gap-1 border-l border-border pl-2">
                  {item.children.map(child => (
                    <li key={child.key}>{renderLeafLink(child, onNavigate)}</li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </nav>
    );
  }

  function renderLoginIfNotLoggedIn(component) {
    if (props.account === null) {
      const lastLoginOrg = localStorage.getItem("lastLoginOrg");
      sessionStorage.setItem("from", window.location.pathname);
      if (lastLoginOrg) {
        return <Redirect to={`/login/${lastLoginOrg}`} />;
      } else {
        return <Redirect to="/login" />;
      }
    } else if (props.account === undefined) {
      return (
        <div className="flex items-center justify-center h-screen flex-col gap-2">
          <Spinner size="lg" />
          <div className="text-sm text-muted-foreground">Loading...</div>
        </div>
      );
    } else if (props.account.needUpdatePassword) {
      if (window.location.pathname === "/account") {
        return component;
      } else {
        return <Redirect to="/account" />;
      }
    } else {
      return component;
    }
  }

  function renderRouter() {
    const account = props.account;
    const onChangeTheme = props.onChangeTheme;
    const onfinish = props.onfinish;
    return (
      <Switch>
        <Route exact path="/" render={(props) => renderLoginIfNotLoggedIn(<Dashboard account={account} {...props} />)} />
        <Route exact path="/apps" render={(props) => renderLoginIfNotLoggedIn(<AppListPage account={account} {...props} />)} />
        <Route exact path="/shortcuts" render={(props) => renderLoginIfNotLoggedIn(<ShortcutsPage account={account} {...props} />)} />
        <Route exact path="/account" render={(props) => renderLoginIfNotLoggedIn(<AccountPage account={account} {...props} />)} />
        <Route exact path="/organizations" render={(props) => renderLoginIfNotLoggedIn(<OrganizationListPage account={account} {...props} />)} />
        <Route exact path="/organizations/:organizationName" render={(props) => renderLoginIfNotLoggedIn(<OrganizationEditPage account={account} onChangeTheme={onChangeTheme} {...props} />)} />
        <Route exact path="/organizations/:organizationName/users" render={(props) => renderLoginIfNotLoggedIn(<UserListPage account={account} {...props} />)} />
        <Route exact path="/trees/:organizationName" render={(props) => renderLoginIfNotLoggedIn(<GroupTreePage account={account} {...props} />)} />
        <Route exact path="/trees/:organizationName/:groupName" render={(props) => renderLoginIfNotLoggedIn(<GroupTreePage account={account} {...props} />)} />
        <Route exact path="/groups" render={(props) => renderLoginIfNotLoggedIn(<GroupListPage account={account} {...props} />)} />
        <Route exact path="/groups/:organizationName/:groupName" render={(props) => renderLoginIfNotLoggedIn(<GroupEditPage account={account} {...props} />)} />
        <Route exact path="/users" render={(props) => renderLoginIfNotLoggedIn(<UserListPage account={account} {...props} />)} />
        <Route exact path="/users/:organizationName/:userName" render={(props) => <UserEditPage account={account} {...props} />} />
        <Route exact path="/invitations" render={(props) => renderLoginIfNotLoggedIn(<InvitationListPage account={account} {...props} />)} />
        <Route exact path="/invitations/:organizationName/:invitationName" render={(props) => renderLoginIfNotLoggedIn(<InvitationEditPage account={account} {...props} />)} />
        <Route exact path="/applications" render={(props) => renderLoginIfNotLoggedIn(<ApplicationListPage account={account} {...props} />)} />
        <Route exact path="/applications/:organizationName/:applicationName" render={(props) => renderLoginIfNotLoggedIn(<ApplicationEditPage account={account} {...props} />)} />
        <Route exact path="/providers" render={(props) => renderLoginIfNotLoggedIn(<ProviderListPage account={account} {...props} />)} />
        <Route exact path="/providers/:organizationName/:providerName" render={(props) => renderLoginIfNotLoggedIn(<ProviderEditPage account={account} {...props} />)} />
        <Route exact path="/records" render={(props) => renderLoginIfNotLoggedIn(<RecordListPage account={account} {...props} />)} />
        <Route exact path="/resources" render={(props) => renderLoginIfNotLoggedIn(<ResourceListPage account={account} {...props} />)} />
        <Route exact path="/certs" render={(props) => renderLoginIfNotLoggedIn(<CertListPage account={account} {...props} />)} />
        <Route exact path="/certs/:organizationName/:certName" render={(props) => renderLoginIfNotLoggedIn(<CertEditPage account={account} {...props} />)} />
        <Route exact path="/keys" render={(props) => renderLoginIfNotLoggedIn(<KeyListPage account={account} {...props} />)} />
        <Route exact path="/keys/:organizationName/:keyName" render={(props) => renderLoginIfNotLoggedIn(<KeyEditPage account={account} {...props} />)} />
        <Route exact path="/servers" render={(props) => renderLoginIfNotLoggedIn(<ServerListPage account={account} {...props} />)} />
        <Route exact path="/servers/:organizationName/:serverName" render={(props) => renderLoginIfNotLoggedIn(<ServerEditPage account={account} {...props} />)} />
        <Route exact path="/sites" render={(props) => renderLoginIfNotLoggedIn(<SiteListPage account={account} {...props} />)} />
        <Route exact path="/sites/:organizationName/:siteName" render={(props) => renderLoginIfNotLoggedIn(<SiteEditPage account={account} {...props} />)} />
        <Route exact path="/rules" render={(props) => renderLoginIfNotLoggedIn(<RuleListPage account={account} {...props} />)} />
        <Route exact path="/rules/:organizationName/:ruleName" render={(props) => renderLoginIfNotLoggedIn(<RuleEditPage account={account} {...props} />)} />
        <Route exact path="/verifications" render={(props) => renderLoginIfNotLoggedIn(<VerificationListPage account={account} {...props} />)} />
        <Route exact path="/roles" render={(props) => renderLoginIfNotLoggedIn(<RoleListPage account={account} {...props} />)} />
        <Route exact path="/roles/:organizationName/:roleName" render={(props) => renderLoginIfNotLoggedIn(<RoleEditPage account={account} {...props} />)} />
        <Route exact path="/permissions" render={(props) => renderLoginIfNotLoggedIn(<PermissionListPage account={account} {...props} />)} />
        <Route exact path="/permissions/:organizationName/:permissionName" render={(props) => renderLoginIfNotLoggedIn(<PermissionEditPage account={account} {...props} />)} />
        <Route exact path="/models" render={(props) => renderLoginIfNotLoggedIn(<ModelListPage account={account} {...props} />)} />
        <Route exact path="/models/:organizationName/:modelName" render={(props) => renderLoginIfNotLoggedIn(<ModelEditPage account={account} {...props} />)} />
        <Route exact path="/adapters" render={(props) => renderLoginIfNotLoggedIn(<AdapterListPage account={account} {...props} />)} />
        <Route exact path="/adapters/:organizationName/:adapterName" render={(props) => renderLoginIfNotLoggedIn(<AdapterEditPage account={account} {...props} />)} />
        <Route exact path="/enforcers" render={(props) => renderLoginIfNotLoggedIn(<EnforcerListPage account={account} {...props} />)} />
        <Route exact path="/enforcers/:organizationName/:enforcerName" render={(props) => renderLoginIfNotLoggedIn(<EnforcerEditPage account={account} {...props} />)} />
        <Route exact path="/sessions" render={(props) => renderLoginIfNotLoggedIn(<SessionListPage account={account} {...props} />)} />
        <Route exact path="/tokens" render={(props) => renderLoginIfNotLoggedIn(<TokenListPage account={account} {...props} />)} />
        <Route exact path="/tokens/:tokenName" render={(props) => renderLoginIfNotLoggedIn(<TokenEditPage account={account} {...props} />)} />
        <Route exact path="/sysinfo" render={(props) => renderLoginIfNotLoggedIn(<SystemInfo account={account} {...props} />)} />
        <Route exact path="/forms" render={(props) => renderLoginIfNotLoggedIn(<FormListPage account={account} {...props} />)} />
        <Route exact path="/forms/:formName" render={(props) => renderLoginIfNotLoggedIn(<FormEditPage account={account} {...props} />)} />
        <Route exact path="/syncers" render={(props) => renderLoginIfNotLoggedIn(<SyncerListPage account={account} {...props} />)} />
        <Route exact path="/syncers/:syncerName" render={(props) => renderLoginIfNotLoggedIn(<SyncerEditPage account={account} {...props} />)} />
        <Route exact path="/webhooks" render={(props) => renderLoginIfNotLoggedIn(<WebhookListPage account={account} {...props} />)} />
        <Route exact path="/webhooks/:webhookName" render={(props) => renderLoginIfNotLoggedIn(<WebhookEditPage account={account} {...props} />)} />
        <Route exact path="/tickets" render={(props) => renderLoginIfNotLoggedIn(<TicketListPage account={account} {...props} />)} />
        <Route exact path="/tickets/:organizationName/:ticketName" render={(props) => renderLoginIfNotLoggedIn(<TicketEditPage account={account} {...props} />)} />
        <Route exact path="/ldap/:organizationName/:ldapId" render={(props) => renderLoginIfNotLoggedIn(<LdapEditPage account={account} {...props} />)} />
        <Route exact path="/ldap/sync/:organizationName/:ldapId" render={(props) => renderLoginIfNotLoggedIn(<LdapSyncPage account={account} {...props} />)} />
        <Route exact path="/mfa/setup" render={(props) => renderLoginIfNotLoggedIn(<MfaSetupPage account={account} onfinish={onfinish} {...props} />)} />
        <Route exact path="/.well-known/openid-configuration" render={(props) => <OdicDiscoveryPage />} />
        <Route path="" render={() => (
          <div className="flex flex-col items-center justify-center min-h-[60vh] gap-6">
            <div className="text-[80px] font-extrabold leading-none text-neutral-100 tracking-tight">404</div>
            <div className="text-base text-neutral-500">
              {i18next.t("general:Sorry, the page you visited does not exist.")}
            </div>
            <a href="/"><Button>{i18next.t("general:Back Home")}</Button></a>
          </div>
        )} />
      </Switch>
    );
  }

  function isWithoutCard() {
    return Setting.isMobile() || window.location.pathname.startsWith("/trees");
  }

  return (
    <React.Fragment>
      <EnableMfaNotification account={props.account} />
      <header
        className={cn(
          "flex justify-between items-center px-0 mb-1 h-16",
          isDark ? "bg-black text-white" : "bg-white text-black"
        )}
      >
        {props.requiredEnableMfa ? null : (Setting.isMobile() ? (
          <React.Fragment>
            <Sheet open={menuVisible} onOpenChange={setMenuVisible}>
              <SheetContent side="left" className="w-72 overflow-y-auto">
                <SheetHeader>
                  <SheetTitle>{i18next.t("general:Close")}</SheetTitle>
                </SheetHeader>
                <div className="mt-4">
                  {renderMobileMenu()}
                </div>
              </SheetContent>
            </Sheet>
            <Button variant="ghost" onClick={() => setMenuVisible(true)} className="gap-2">
              <MenuIcon className="h-4 w-4" />
              {i18next.t("general:Menu")}
            </Button>
          </React.Fragment>
        ) : (
          // Padding 1px for menu item highlight border
          <div className="flex-1 overflow-hidden pb-px">
            {renderDesktopMenu()}
          </div>
        ))}
        <div className="shrink-0 flex items-center gap-2 pr-2">
          {renderAccountMenu()}
        </div>
      </header>
      <main className="flex flex-col">
        {isWithoutCard() ?
          renderRouter() :
          <Card className="content-warp-card">
            {renderRouter()}
          </Card>
        }
      </main>
    </React.Fragment>
  );
}

export default withRouter(ManagementPage);
