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

// @ts-nocheck
import React, {Component, Suspense, lazy} from "react";
import "./App.css";
import {Helmet} from "react-helmet";
import * as Setting from "./Setting";
import {setOrgIsTourVisible, setTourLogo} from "./TourConfig";
import {Github, Share2, ArrowUp} from "lucide-react";
import {Sheet, SheetContent, SheetHeader, SheetTitle} from "./components/ui/sheet";
import {Tooltip, TooltipContent, TooltipProvider, TooltipTrigger} from "./components/ui/tooltip";
import {Toaster} from "sonner";
import {Route, Switch, withRouter} from "react-router-dom";
import CustomGithubCorner from "./common/CustomGithubCorner";
import * as Conf from "./Conf";

import * as Auth from "./auth/Auth";
import EntryPage from "./EntryPage";
import * as AuthBackend from "./auth/AuthBackend";
import AuthCallback from "./auth/AuthCallback";
import SamlCallback from "./auth/SamlCallback";
import TelegramLogin from "./auth/TelegramLogin";
import i18next from "i18next";
import {withTranslation} from "react-i18next";
const ManagementPage = lazy(() => import("./ManagementPage"));

import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as Cookie from "cookie";

class App extends Component {
  constructor(props) {
    super(props);
    this.setThemeAlgorithm();
    let storageThemeAlgorithm = [];
    try {
      storageThemeAlgorithm = localStorage.getItem("themeAlgorithm") ? JSON.parse(localStorage.getItem("themeAlgorithm")) : ["dark"];
    } catch {
      storageThemeAlgorithm = ["dark"];
    }
    this.state = {
      classes: props,
      selectedMenuKey: 0,
      account: undefined,
      accessToken: undefined,
      uri: null,
      themeAlgorithm: storageThemeAlgorithm,
      themeData: Conf.ThemeDefault,
      logo: this.getLogo(storageThemeAlgorithm),
      requiredEnableMfa: false,
      isAiAssistantOpen: false,
      application: undefined,
    };
    Setting.initServerUrl();
    Setting.initWebConfig();
    Auth.initAuthWithConfig({
      serverUrl: Setting.ServerUrl,
      appName: Conf.DefaultApplication, // the application used in Hanzo IAM root path: "/"
    });
  }

  UNSAFE_componentWillMount() {
    // Normalize hyphenated URL variants (e.g. /sign-up → /signup)
    const path = window.location.pathname;
    const search = window.location.search;
    const urlNormMap = {"/sign-up": "/signup", "/log-in": "/login", "/register": "/signup"};
    const normMatch = Object.entries(urlNormMap).find(([k]) => path === k || path.startsWith(k + "/"));
    if (normMatch) {
      window.location.replace(normMatch[1] + search);
      return;
    }
    // On dedicated IAM domains, keep signup local (no redirect)
    // Each deployment handles its own signup flow
    this.updateMenuKey();
    this.getAccount();
    this.getApplication();
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
    const uri = location.pathname;
    if (this.state.uri !== uri) {
      this.updateMenuKey();
    }

    if (this.state.account !== prevState.account) {
      const requiredEnableMfa = Setting.isRequiredEnableMfa(this.state.account, this.state.account?.organization);
      this.setState({
        requiredEnableMfa: requiredEnableMfa,
      });

      if (requiredEnableMfa === true) {
        const mfaType = Setting.getMfaItemsByRules(this.state.account, this.state.account?.organization, [Setting.MfaRuleRequired])
          .find((item) => item.rule === Setting.MfaRuleRequired)?.name;
        if (mfaType !== undefined) {
          this.props.history.push(`/mfa/setup?mfaType=${mfaType}`, {from: "/login"});
        }
      }
    }
  }

  shouldFlattenMenu() {
    const organization = this.state.account?.organization;
    const navItems = Setting.isLocalAdminUser(this.state.account) ? organization?.navItems : (organization?.userNavItems ?? []);

    // If navItems is "all" or not configured, don't flatten
    if (!Array.isArray(navItems) || navItems?.includes("all")) {
      return false;
    }

    // Count how many valid menu items would be visible
    // Filter out any invalid or non-existent menu items
    const validMenuItems = [
      "/", "/shortcuts", "/apps", // Home group
      "/organizations", "/groups", "/users", "/invitations", // User Management
      "/applications", "/providers", "/resources", "/certs", "/keys", // Identity
      "/roles", "/permissions", "/models", "/adapters", "/enforcers", // Authorization
      "/sessions", "/records", "/tokens", "/verifications", // Logging & Auditing
      "/sysinfo", "/forms", "/syncers", "/webhooks", "/tickets", "/swagger", // Admin
    ];

    const count = navItems.filter(item => validMenuItems.includes(item)).length;
    return count <= Conf.MaxItemsForFlatMenu;
  }

  getSelectedMenuKeyForFlatMenu(uri) {
    // For flattened menu, return the actual child path instead of parent group
    if (uri === "/" || uri.includes("/shortcuts") || uri.includes("/apps")) {
      if (uri === "/") {
        return "/";
      } else if (uri.includes("/shortcuts")) {
        return "/shortcuts";
      } else if (uri.includes("/apps")) {
        return "/apps";
      }
    } else if (uri.includes("/organizations") || uri.includes("/trees") || uri.includes("/groups") || uri.includes("/users") || uri.includes("/invitations")) {
      if (uri.includes("/organizations")) {
        return "/organizations";
      } else if (uri.includes("/groups")) {
        return "/groups";
      } else if (uri.includes("/users")) {
        return "/users";
      } else if (uri.includes("/invitations")) {
        return "/invitations";
      }
    } else if (uri.includes("/applications") || uri.includes("/providers") || uri.includes("/resources") || uri.includes("/certs")) {
      if (uri.includes("/applications")) {
        return "/applications";
      } else if (uri.includes("/providers")) {
        return "/providers";
      } else if (uri.includes("/resources")) {
        return "/resources";
      } else if (uri.includes("/certs")) {
        return "/certs";
      }
    } else if (uri.includes("/keys")) {
      return "/keys";
    } else if (uri.includes("/roles") || uri.includes("/permissions") || uri.includes("/models") || uri.includes("/adapters") || uri.includes("/enforcers")) {
      if (uri.includes("/roles")) {
        return "/roles";
      } else if (uri.includes("/permissions")) {
        return "/permissions";
      } else if (uri.includes("/models")) {
        return "/models";
      } else if (uri.includes("/adapters")) {
        return "/adapters";
      } else if (uri.includes("/enforcers")) {
        return "/enforcers";
      }
    } else if (uri.includes("/records") || uri.includes("/tokens") || uri.includes("/sessions") || uri.includes("/verifications")) {
      if (uri.includes("/sessions")) {
        return "/sessions";
      } else if (uri.includes("/records")) {
        return "/records";
      } else if (uri.includes("/tokens")) {
        return "/tokens";
      } else if (uri.includes("/verifications")) {
        return "/verifications";
      }
    } else if (uri.includes("/sysinfo") || uri.includes("/forms") || uri.includes("/syncers") || uri.includes("/webhooks") || uri.includes("/tickets")) {
      if (uri.includes("/sysinfo")) {
        return "/sysinfo";
      } else if (uri.includes("/forms")) {
        return "/forms";
      } else if (uri.includes("/syncers")) {
        return "/syncers";
      } else if (uri.includes("/webhooks")) {
        return "/webhooks";
      } else if (uri.includes("/tickets")) {
        return "/tickets";
      }
    } else if (uri.includes("/signup")) {
      return "/signup";
    } else if (uri.includes("/login")) {
      return "/login";
    } else if (uri.includes("/result")) {
      return "/result";
    }
    return -1;
  }

  updateMenuKey() {
    const uri = location.pathname;
    this.setState({
      uri: uri,
    });

    // Check if menu should be flattened and use appropriate key selection
    if (this.shouldFlattenMenu()) {
      const selectedKey = this.getSelectedMenuKeyForFlatMenu(uri);
      this.setState({selectedMenuKey: selectedKey});
      return;
    }

    // Original logic for grouped menu
    if (uri === "/" || uri.includes("/shortcuts") || uri.includes("/apps")) {
      this.setState({selectedMenuKey: "/home"});
    } else if (uri.includes("/organizations") || uri.includes("/trees") || uri.includes("/groups") || uri.includes("/users") || uri.includes("/invitations")) {
      this.setState({selectedMenuKey: "/orgs"});
    } else if (uri.includes("/applications") || uri.includes("/providers") || uri.includes("/resources") || uri.includes("/certs") || uri.includes("/keys")) {
      this.setState({selectedMenuKey: "/identity"});
    } else if (uri.includes("/roles") || uri.includes("/permissions") || uri.includes("/models") || uri.includes("/adapters") || uri.includes("/enforcers")) {
      this.setState({selectedMenuKey: "/auth"});
    } else if (uri.includes("/records") || uri.includes("/tokens") || uri.includes("/sessions") || uri.includes("/verifications")) {
      this.setState({selectedMenuKey: "/logs"});
    } else if (uri.includes("/sysinfo") || uri.includes("/forms") || uri.includes("/syncers") || uri.includes("/webhooks") || uri.includes("/tickets")) {
      this.setState({selectedMenuKey: "/admin"});
    } else if (uri.includes("/signup")) {
      this.setState({selectedMenuKey: "/signup"});
    } else if (uri.includes("/login")) {
      this.setState({selectedMenuKey: "/login"});
    } else if (uri.includes("/result")) {
      this.setState({selectedMenuKey: "/result"});
    } else {
      this.setState({selectedMenuKey: -1});
    }
  }

  getAccessTokenParam(params) {
    // "/page?access_token=123"
    const accessToken = params.get("access_token");
    return accessToken === null ? "" : `?accessToken=${accessToken}`;
  }

  getCredentialParams(params) {
    // "/page?username=abc&password=123"
    if (params.get("username") === null || params.get("password") === null) {
      return "";
    }
    return `?username=${params.get("username")}&password=${params.get("password")}`;
  }

  getUrlWithoutQuery() {
    return window.location.toString().replace(window.location.search, "");
  }

  getLanguageParam(params) {
    // "/page?language=en"
    const language = params.get("language");
    if (language !== null) {
      Setting.setLanguage(language);
      return `language=${language}`;
    }
    return "";
  }

  getLogo(themes) {
    return Setting.getLogo(themes);
  }

  setThemeAlgorithm() {
    const currentUrl = window.location.href;
    const url = new URL(currentUrl);
    const themeType = url.searchParams.get("theme");
    if (themeType === "dark" || themeType === "default") {
      localStorage.setItem("themeAlgorithm", JSON.stringify([themeType]));
    }
  }

  setLanguage(account) {
    const language = account?.language;
    if (language !== null && language !== "" && language !== i18next.language) {
      Setting.setLanguage(language);
    }
  }

  setTheme = (theme, initThemeAlgorithm) => {
    this.setState({
      themeData: theme,
    });

    if (initThemeAlgorithm) {
      if (localStorage.getItem("themeAlgorithm")) {
        let storageThemeAlgorithm = [];
        try {
          storageThemeAlgorithm = JSON.parse(localStorage.getItem("themeAlgorithm"));
        } catch {
          storageThemeAlgorithm = ["default"];
        }
        this.setState({
          logo: this.getLogo(storageThemeAlgorithm),
          themeAlgorithm: storageThemeAlgorithm,
        });
        return;
      }
      this.setState({
        logo: this.getLogo(Setting.getAlgorithmNames(theme)),
        themeAlgorithm: Setting.getAlgorithmNames(theme),
      });
    }
  };

  getApplication() {
    const applicationName = localStorage.getItem("applicationName");
    if (!applicationName) {
      return;
    }
    ApplicationBackend.getApplication("admin", applicationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.setState({
          application: res.data,
        });
      });
  }

  getAccount() {
    const params = new URLSearchParams(this.props.location.search);

    let query = this.getAccessTokenParam(params);
    if (query === "") {
      query = this.getCredentialParams(params);
    }

    const query2 = this.getLanguageParam(params);
    if (query2 !== "") {
      const url = window.location.toString().replace(new RegExp(`[?&]${query2}`), "");
      window.history.replaceState({}, document.title, url);
    }

    if (query !== "") {
      const returnUrl = params.get("returnUrl");

      let newUrl;
      if (returnUrl) {
        const newParams = new URLSearchParams();
        newParams.set("returnUrl", returnUrl);
        newUrl = window.location.pathname + "?" + newParams.toString();
      } else {
        newUrl = this.getUrlWithoutQuery();
      }
      window.history.replaceState({}, document.title, newUrl);
    }

    AuthBackend.getAccount(query)
      .then((res) => {
        let account = null;
        let accessToken = null;
        if (res.status === "ok") {
          account = res.data;
          account.organization = res.data2;
          accessToken = res.data.accessToken;

          if (!localStorage.getItem("language")) {
            this.setLanguage(account);
          }
          this.setTheme(Setting.getThemeData(account.organization), Conf.InitThemeAlgorithm);
          setTourLogo(account.organization.logo);
          setOrgIsTourVisible(account.organization.enableTour);
        } else {
          if (res.data !== "Please login first") {
            Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
          }
        }

        this.setState({
          account: account,
          accessToken: accessToken,
        });
      });
  }

  onUpdateAccount(account) {
    this.setState({
      account: account,
    });
  }

  renderFooter(logo, footerHtml) {
    logo = logo ?? this.state.logo;
    footerHtml = footerHtml ?? this.state.application?.footerHtml;
    return (
      <React.Fragment>
        {!this.state.account ? null : <div style={{display: "none"}} id="IamApplicationName" value={this.state.account.signupApplication} />}
        {!this.state.account ? null : <div style={{display: "none"}} id="IamAccessToken" value={this.state.accessToken} />}
        <footer id="footer" className="text-center">
          {
            footerHtml && footerHtml !== "" ?
              <React.Fragment>
                <div dangerouslySetInnerHTML={{__html: footerHtml}} />
              </React.Fragment>
              : (
                Conf.CustomFooter !== null ? Conf.CustomFooter : (
                  <React.Fragment>
                  &nbsp;
                  </React.Fragment>
                )
              )
          }
        </footer>
      </React.Fragment>
    );
  }

  renderAiAssistant() {
    return (
      <Sheet open={this.state.isAiAssistantOpen} onOpenChange={(open) => this.setState({isAiAssistantOpen: open})}>
        <SheetContent side="right" className="w-[500px] sm:max-w-[500px] p-0 flex flex-col">
          <SheetHeader className="px-4 py-3 border-b border-border">
            <SheetTitle asChild>
              <div className="flex items-center justify-between">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <a target="_blank" rel="noreferrer" href={"https://iam.com"} className="flex items-center">
                      <span className="mr-2.5">🤖</span>
                      AI Assistant
                    </a>
                  </TooltipTrigger>
                  <TooltipContent>Want to deploy your own AI assistant? Click to learn more!</TooltipContent>
                </Tooltip>
                <div className="flex items-center gap-3">
                  <a className="custom-link" target="_blank" rel="noreferrer" href={"#"}>
                    <Github className="w-5 h-5 text-neutral-500" />
                  </a>
                  <a className="custom-link" target="_blank" rel="noreferrer" href={`${Conf.AiAssistantUrl}`}>
                    <Share2 className="w-5 h-5 text-neutral-500" />
                  </a>
                </div>
              </div>
            </SheetTitle>
          </SheetHeader>
          <iframe id="iframeHelper" title={"iframeHelper"} src={`${Conf.AiAssistantUrl}/?isRaw=1`} className="flex-1 w-full" scrolling="no" frameBorder="no" />
        </SheetContent>
      </Sheet>
    );
  }

  isDoorPages() {
    return this.isEntryPages() ||
      window.location.pathname.startsWith("/callback") ||
      window.location.pathname.startsWith("/telegram-login");
  }

  isEntryPages() {
    return window.location.pathname.startsWith("/signup") ||
      window.location.pathname.startsWith("/login") ||
      window.location.pathname.startsWith("/oauth") ||
      window.location.pathname.startsWith("/forget") ||
      window.location.pathname.startsWith("/prompt") ||
      window.location.pathname.startsWith("/result") ||
      window.location.pathname.startsWith("/cas") ||
      window.location.pathname.startsWith("/qrcode") ||
      window.location.pathname.startsWith("/consent") ||
      window.location.pathname.startsWith("/captcha");
  }

  onClick = ({key}) => {
    if (key !== "/swagger" && key !== "/records") {
      if (this.state.requiredEnableMfa) {
        Setting.showMessage("info", "Please enable MFA first!");
      } else {
        this.props.history.push(key);
      }
    }
  };

  onLoginSuccess(redirectUrl) {
    window.google?.accounts?.id?.cancel();
    if (redirectUrl) {
      localStorage.setItem("mfaRedirectUrl", redirectUrl);
    }
    this.getAccount();
  }

  renderBackToTop() {
    return (
      <button
        type="button"
        aria-label="Back to top"
        onClick={() => window.scrollTo({top: 0, behavior: "smooth"})}
        className="fixed bottom-6 right-6 z-40 w-10 h-10 rounded-full bg-neutral-800 text-white shadow-lg hover:bg-neutral-700 flex items-center justify-center transition-colors"
      >
        <ArrowUp className="w-4 h-4" />
      </button>
    );
  }

  renderPage() {
    if (this.isDoorPages()) {
      let themeData = this.state.themeData;
      let logo = this.state.logo;
      let footerHtml = null;
      if (this.state.organization === undefined) {
        const curCookie = Cookie.parse(document.cookie);
        if (curCookie["organizationTheme"] && curCookie["organizationTheme"] !== "null") {
          themeData = JSON.parse(curCookie["organizationTheme"]);
        }
        if (curCookie["organizationLogo"] && curCookie["organizationLogo"] !== "") {
          logo = curCookie["organizationLogo"];
        }
        if (curCookie["organizationFootHtml"] && curCookie["organizationFootHtml"] !== "") {
          footerHtml = curCookie["organizationFootHtml"];
        }
      }

      return (
        <div id="parent-area" className="min-h-screen flex flex-col">
          <main className="flex-1 flex justify-center">
            {
              this.isEntryPages() ?
                <EntryPage
                  account={this.state.account}
                  theme={this.state.themeData}
                  themeAlgorithm={this.state.themeAlgorithm}
                  requiredEnableMfa={this.state.requiredEnableMfa}
                  updateApplication={(application) => {
                    this.setState({
                      application: application,
                    });
                  }}
                  onLoginSuccess={(redirectUrl) => {this.onLoginSuccess(redirectUrl);}}
                  onUpdateAccount={(account) => this.onUpdateAccount(account)}
                  updataThemeData={this.setTheme}
                /> :
                <Switch>
                  <Route exact path="/callback" render={(props) => <AuthCallback {...props} {...this.props} application={this.state.application} onLoginSuccess={(redirectUrl) => {this.onLoginSuccess(redirectUrl);}} />} />
                  <Route exact path="/callback/saml" render={(props) => <SamlCallback {...props} {...this.props} application={this.state.application} onLoginSuccess={(redirectUrl) => {this.onLoginSuccess(redirectUrl);}} />} />
                  <Route exact path="/telegram-login" render={(props) => <TelegramLogin {...props} {...this.props} />} />
                  <Route path="" render={() => (
                    <div className="flex flex-col items-center justify-center min-h-[60vh] gap-6">
                      <div className="text-[80px] font-extrabold leading-none text-neutral-100 tracking-tight">404</div>
                      <div className="text-base text-neutral-500">
                        {i18next.t("general:Sorry, the page you visited does not exist.")}
                      </div>
                      <div className="flex gap-3">
                        <a href="/login" className="px-6 py-2.5 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors no-underline">
                          {i18next.t("login:Sign In")}
                        </a>
                        <a href="/signup" className="px-6 py-2.5 rounded-lg border border-white/10 text-neutral-300 font-medium text-sm hover:border-white/20 hover:text-white transition-colors no-underline">
                          {i18next.t("account:Sign Up")}
                        </a>
                      </div>
                    </div>
                  )} />
                </Switch>
            }
          </main>
          {
            this.renderFooter(logo, footerHtml)
          }
          {
            this.renderAiAssistant()
          }
        </div>
      );
    }
    return (
      <React.Fragment>
        {this.renderBackToTop()}
        <CustomGithubCorner />
        {
          <Suspense fallback={null}>
            <div id="parent-area" className="min-h-screen flex flex-col">
              <ManagementPage
                account={this.state.account}
                application={this.state.application}
                uri={this.state.uri}
                themeData={this.state.themeData}
                themeAlgorithm={this.state.themeAlgorithm}
                selectedMenuKey={this.state.selectedMenuKey}
                requiredEnableMfa={this.state.requiredEnableMfa}
                menuVisible={this.state.menuVisible}
                logo={this.state.logo}
                onChangeTheme={this.setTheme}
                onClick={this.onClick}
                onfinish={() => {
                  this.setState({requiredEnableMfa: false});
                }}
                openAiAssistant={() => {
                  this.setState({
                    isAiAssistantOpen: true,
                  });
                }}
                setLogoAndThemeAlgorithm={(nextThemeAlgorithm) => {
                  this.setState({
                    themeAlgorithm: nextThemeAlgorithm,
                    logo: this.getLogo(nextThemeAlgorithm),
                  });
                  localStorage.setItem("themeAlgorithm", JSON.stringify(nextThemeAlgorithm));
                }}
                setLogoutState={() => {
                  this.setState({
                    account: null,
                  });
                }}
              />
              {
                this.renderFooter()
              }
              {
                this.renderAiAssistant()
              }
            </div>
          </Suspense>
        }
      </React.Fragment>
    );
  }

  renderBanner() {
    // Demo banner ripped 2026-05-12. Hanzo IAM deployments never run
    // as a public demo, so the banner has no reason to be on.
    return null;
  }

  render() {
    return (
      <React.Fragment>
        {(this.state.account === undefined || this.state.account === null) ?
          <Helmet>
            <link rel="icon" href={"/favicon.ico"} />
          </Helmet> :
          <Helmet>
            <title>{this.state.account.organization?.displayName}</title>
            <link rel="icon" href={this.state.account.organization?.favicon} />
          </Helmet>
        }
        <TooltipProvider>
          {
            this.renderPage()
          }
          <Toaster position="top-right" richColors closeButton />
        </TooltipProvider>
      </React.Fragment>
    );
  }
}

export default withRouter(withTranslation()(App));
