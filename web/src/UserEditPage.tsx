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
import React from "react";
import {Button} from "./components/ui/button";
import {Input} from "./components/ui/input";
import {Switch} from "./components/ui/switch";
import {Card, CardContent, CardHeader, CardTitle} from "./components/ui/card";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "./components/ui/select";
import {Tabs, TabsList, TabsTrigger} from "./components/ui/tabs";
import {Tooltip, TooltipContent, TooltipTrigger} from "./components/ui/tooltip";
import {Badge} from "./components/ui/badge";
import {cn} from "./lib/utils";
import {withRouter} from "react-router-dom";
import {TotpMfaType} from "./auth/MfaSetupPage";
import * as GroupBackend from "./backend/GroupBackend";
import * as UserBackend from "./backend/UserBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import EnableMfaModal from "./common/modal/EnableMfaModal";
import * as Setting from "./Setting";
import i18next from "i18next";
import CropperDivModal from "./common/modal/CropperDivModal";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import PasswordModal from "./common/modal/PasswordModal";
import ResetModal from "./common/modal/ResetModal";
import AffiliationSelect from "./common/select/AffiliationSelect";
import moment from "moment";
import OAuthWidget from "./common/OAuthWidget";
import SamlWidget from "./common/SamlWidget";
import RegionSelect from "./common/select/RegionSelect";
import WebAuthnCredentialTable from "./table/WebauthnCredentialTable";
import ManagedAccountTable from "./table/ManagedAccountTable";
import AddressTable from "./table/AddressTable";
import PropertyTable from "./table/propertyTable";
import {CountryCodeSelect} from "./common/select/CountryCodeSelect";
import PopconfirmModal from "./common/modal/PopconfirmModal";
import {DeleteMfa} from "./backend/MfaBackend";
import {CheckCircle, GripVertical, Users} from "lucide-react";
import * as MfaBackend from "./backend/MfaBackend";
import AccountAvatar from "./account/AccountAvatar";
import FaceIdTable from "./table/FaceIdTable";
import MfaAccountTable from "./table/MfaAccountTable";
import MfaTable from "./table/MfaTable";
import ConsentTable from "./table/ConsentTable";

// Reusable label column for the 12-col field grid.
function FieldLabel({children, className = ""}) {
  return (
    <div className={cn("col-span-12 md:col-span-2 pt-2 text-sm text-gray-300", className)}>
      {children} :
    </div>
  );
}

// Reusable input column.
function FieldValue({children, span = 10, className = ""}) {
  const spanCls = span === 22 ? "col-span-12 md:col-span-10"
    : span === 5 ? "col-span-12 md:col-span-5"
      : span === 4 ? "col-span-12 md:col-span-4"
        : span === 2 ? "col-span-12 md:col-span-2"
          : "col-span-12 md:col-span-10";
  return <div className={cn(spanCls, className)}>{children}</div>;
}

// Grid row wrapper to mimic antd Row+Col layout.
function FieldRow({children, className = ""}) {
  return <div className={cn("grid grid-cols-12 gap-3 mt-5", className)}>{children}</div>;
}

class UserEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      userName: props.userName !== undefined ? props.userName : props.match.params.userName,
      user: null,
      application: null,
      groups: null,
      organizations: [],
      applications: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
      loading: true,
      returnUrl: null,
      idCardInfo: ["ID card front", "ID card back", "ID card with person"],
      openFaceRecognitionModal: false,
      consents: [],
      activeMenuKey: window.location.hash?.slice(1) || "",
      menuMode: "Horizontal",
    };
  }

  UNSAFE_componentWillMount() {
    this.getUser();
    if (Setting.isLocalAdminUser(this.props.account)) {
      this.getOrganizations();
    }
    this.getApplicationsByOrganization(this.state.organizationName);
    this.getUserApplication();
    this.setReturnUrl();
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (prevState.application !== this.state.application) {
      this.getGroups(this.state.organizationName);
    }
  }

  getUser() {
    UserBackend.getUser(this.state.organizationName, this.state.userName)
      .then((res) => {
        if (res.data === null) {
          this.props.history.push("/404");
          return;
        }

        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.setState({
          user: res.data,
          multiFactorAuths: res.data?.multiFactorAuths ?? [],
          consents: res.data?.applicationScopes ?? [],
          loading: false,
        });

      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizations("admin")
      .then((res) => {
        this.setState({
          organizations: res.data || [],
        });
      });
  }

  getApplicationsByOrganization(organizationName) {
    ApplicationBackend.getApplicationsByOrganization("admin", organizationName)
      .then((res) => {
        this.setState({
          applications: res.data || [],
        });

        const applications = res.data;
        if (this.state.user) {
          if (this.state.user.signupApplication === "" || applications.filter(application => application.name === this.state.user.signupApplication).length === 0) {
            if (applications.length > 0) {
              this.updateUserField("signupApplication", applications[0].name);
            } else {
              this.updateUserField("signupApplication", "");
            }
          }
        }
      });
  }

  getUserApplication() {
    ApplicationBackend.getUserApplication(this.state.organizationName, this.state.userName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.setState({
          menuMode: res.data?.organizationObj?.accountMenu ?? "Horizontal",
          application: res.data,
        });
      });
  }

  getUserOrganization() {
    return this.state.application?.organizationObj;
  }

  isGroupsVisible() {
    const organization = this.getUserOrganization();
    if (!organization) {
      return false;
    } else {
      return organization.accountItems?.some((item) => item.name === "Groups" && item.visible);
    }
  }

  getGroups(organizationName) {
    if (!Setting.isLocalAdminUser(this.props.account)) {
      return;
    }

    if (this.isGroupsVisible()) {
      GroupBackend.getGroups(organizationName)
        .then((res) => {
          if (res.status === "ok") {
            this.setState({
              groups: res.data,
            });
          }
        });
    }
  }

  setReturnUrl() {
    const searchParams = new URLSearchParams(this.props.location.search);
    const returnUrl = searchParams.get("returnUrl");
    if (returnUrl !== null) {
      this.setState({
        returnUrl: returnUrl,
      });
    }
  }

  parseUserField(key, value) {
    if (["score", "karma", "ranking"].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  updateUserField(key, value, idx) {
    if (this.props.account === null) {
      return;
    }

    value = this.parseUserField(key, value);

    const user = this.state.user;
    if (key === "address") {
      if (!user[key]) {
        user[key] = ["", ""];
      }
      user[key][idx] = value;
    } else {
      user[key] = value;
    }

    this.setState({
      user: user,
    });
  }

  unlinked() {
    this.getUser();
  }

  isSelf() {
    if (!this.state.user || !this.props.account) {
      return false;
    }

    // Compare by id if available
    if (this.state.user.id && this.props.account.id) {
      return this.state.user.id === this.props.account.id;
    }

    // Fallback to comparing by owner and name
    return (this.state.user.owner === this.props.account.owner &&
      this.state.user.name === this.props.account.name);
  }

  isSelfOrAdmin() {
    return this.isSelf() || Setting.isLocalAdminUser(this.props.account);
  }

  getCountryCode() {
    return this.props.account.countryCode;
  }

  deleteMfa = () => {
    this.setState({
      RemoveMfaLoading: true,
    });

    DeleteMfa({
      owner: this.state.user.owner,
      name: this.state.user.name,
    }).then((res) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully deleted"));
        this.setState({
          multiFactorAuths: res.data,
        });
      } else {
        Setting.showMessage("error", i18next.t("general:Failed to delete"));
      }
    }).finally(() => {
      this.setState({
        RemoveMfaLoading: false,
      });
    });
  };

  handleVerifyIdentification = () => {
    if (!this.state.user.idCard || !this.state.user.idCardType) {
      Setting.showMessage("error", i18next.t("user:Please fill in ID card information first"));
      return;
    }

    if (!this.state.user.realName) {
      Setting.showMessage("error", i18next.t("user:Please fill in your real name first"));
      return;
    }

    // For normal user verifying themselves, no need to pass user or provider parameters
    // Backend will use logged-in user and auto-select provider
    UserBackend.verifyIdentification(this.state.user.owner, this.state.user.name, "")
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("user:Identity verification successful"));
          this.getUser();
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  };

  renderAccountItem(accountItem) {
    const isAdmin = Setting.isLocalAdminUser(this.props.account);

    let disabled = false;
    if (accountItem.modifyRule === "Self") {
      if (!this.isSelfOrAdmin()) {
        disabled = true;
      }
    } else if (accountItem.modifyRule === "Admin") {
      if (!isAdmin) {
        disabled = true;
      }
    } else if (accountItem.modifyRule === "Immutable") {
      disabled = true;
    }

    if (accountItem.name === "Organization" || accountItem.name === "Name") {
      if (this.state.user.owner === "built-in" && this.state.user.name === "admin") {
        disabled = true;
      }
    }

    if (accountItem.name === "ID card info" || accountItem.name === "ID card" || accountItem.name === "ID card type" || accountItem.name === "Real name") {
      if (this.state.user.isVerified) {
        disabled = true;
      }
    }

    if (accountItem.name === "Organization") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Select disabled={disabled} value={this.state.user.owner} onValueChange={(value) => {
              this.getApplicationsByOrganization(value);
              this.updateUserField("owner", value);
              this.getGroups(value);
            }}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {this.state.organizations.map((organization, index) => (
                  <SelectItem key={index} value={organization.name}>{organization.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Groups") {
      // Multi-select: render as a list of checkbox-style toggles inside a popover-like inline list.
      // TODO(rip-antd): proper multi-select primitive; for now use native multi-select with cn-styled fallback.
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Groups"), i18next.t("general:Groups - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <select
              multiple
              disabled={disabled}
              className="w-full bg-transparent border border-white/10 rounded-md px-2 py-1 text-sm text-white"
              value={this.state.user.groups ?? []}
              onChange={(e) => {
                const value = Array.from(e.target.selectedOptions, (opt) => opt.value);
                if (this.state.groups?.filter(group => value.includes(`${group.owner}/${group.name}`))
                  .filter(group => group.type === "Physical").length > 1) {
                  Setting.showMessage("error", i18next.t("general:You can only select one physical group"));
                  return;
                }
                this.updateUserField("groups", value);
              }}
            >
              {this.state.groups?.map((group) => (
                <option key={group.name} value={`${group.owner}/${group.name}`}>
                  {group.type === "Physical" ? "[P] " : "[V] "}{group.displayName}
                </option>
              ))}
            </select>
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "ID") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel("ID", i18next.t("general:ID - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.id} disabled={disabled} onChange={e => {
              this.updateUserField("id", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Name") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.name} disabled={disabled} onChange={e => {
              this.updateUserField("name", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Display name") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.displayName} onChange={e => {
              this.updateUserField("displayName", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Avatar") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Avatar"), i18next.t("general:Avatar - Tooltip"))}</FieldLabel>
          {this.renderImage(this.state.user.avatar, i18next.t("user:Upload a photo"), i18next.t("user:Set new profile picture"), "avatar", false)}
        </FieldRow>
      );
    } else if (accountItem.name === "User type") {
      let userTypes = ["normal-user", "paid-user"];
      const organization = this.getUserOrganization();
      if (organization && organization.userTypes && organization.userTypes.length > 0) {
        userTypes = organization.userTypes;
      }

      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:User type"), i18next.t("general:User type - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Select value={this.state.user.type} onValueChange={(value) => {this.updateUserField("type", value);}}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {userTypes.map((item) => (
                  <SelectItem key={item} value={item}>{item}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Password") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Password"), i18next.t("general:Password - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            {
              (this.state.user.name === this.state.userName) ? (
                <PasswordModal user={this.state.user} userName={this.state.userName} organization={this.getUserOrganization()} account={this.props.account} disabled={disabled} />
              ) : (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span>
                      <PasswordModal user={this.state.user} userName={this.state.userName} organization={this.getUserOrganization()} account={this.props.account} disabled={true} />
                    </span>
                  </TooltipTrigger>
                  <TooltipContent side="top" align="start">
                    {i18next.t("user:You have changed the username, please save your change first before modifying the password")}
                  </TooltipContent>
                </Tooltip>
              )
            }
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Email") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Email"), i18next.t("general:Email - Tooltip"))}</FieldLabel>
          <FieldValue span={5} className="pr-5">
            <Input
              value={this.state.user.email}
              style={{width: "280px"}}
              disabled={!Setting.isLocalAdminUser(this.props.account) ? true : disabled}
              onChange={e => {
                this.updateUserField("email", e.target.value);
              }}
            />
          </FieldValue>
          <FieldValue span={5}>
            {/* backend auto get the current user, so admin can not edit. Just self can reset*/}
            {this.isSelf() ? <ResetModal application={this.state.application} disabled={disabled} buttonText={i18next.t("user:Reset Email...")} destType={"email"} /> : null}
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Phone") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Phone"), i18next.t("general:Phone - Tooltip"))}</FieldLabel>
          <FieldValue span={5} className="pr-5">
            <div className="flex" style={{width: "280px"}}>
              <div style={{width: "30%"}}>
                <CountryCodeSelect
                  // disabled={!Setting.isLocalAdminUser(this.props.account) ? true : disabled}
                  initValue={this.state.user.countryCode}
                  onChange={(value) => {
                    this.updateUserField("countryCode", value);
                  }}
                  countryCodes={this.getUserOrganization()?.countryCodes}
                />
              </div>
              <div style={{width: "70%"}}>
                <Input value={this.state.user.phone}
                  disabled={!Setting.isLocalAdminUser(this.props.account) ? true : disabled}
                  onChange={e => {
                    this.updateUserField("phone", e.target.value);
                  }} />
              </div>
            </div>
          </FieldValue>
          <FieldValue span={5}>
            {this.isSelf() ? (<ResetModal application={this.state.application} countryCode={this.getCountryCode()} disabled={disabled} buttonText={i18next.t("user:Reset Phone...")} destType={"phone"} />) : null}
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Country/Region") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Country/Region"), i18next.t("user:Country/Region - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <RegionSelect defaultValue={this.state.user.region} onChange={(value) => {
              this.updateUserField("region", value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Location") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Location"), i18next.t("user:Location - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.location} onChange={e => {
              this.updateUserField("location", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Address") {
      return (
        <React.Fragment>
          <FieldRow>
            <FieldLabel>{Setting.getLabel(i18next.t("user:Address"), i18next.t("user:Address - Tooltip"))}</FieldLabel>
            <FieldLabel>{i18next.t("user:Address line") + " 1"}</FieldLabel>
            <div className="col-span-12 md:col-span-8">
              <Input value={!this.state.user.address ? "" : this.state.user.address[0]} onChange={e => {
                this.updateUserField("address", e.target.value, 0);
              }} />
            </div>
          </FieldRow>
          <FieldRow>
            <FieldLabel>{""}</FieldLabel>
            <FieldLabel>{i18next.t("user:Address line") + " 2"}</FieldLabel>
            <div className="col-span-12 md:col-span-8">
              <Input value={!this.state.user.address ? "" : this.state.user.address[1]} onChange={e => {
                this.updateUserField("address", e.target.value, 1);
              }} />
            </div>
          </FieldRow>
        </React.Fragment>
      );
    } else if (accountItem.name === "Addresses") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Addresses"), i18next.t("user:Addresses"))}</FieldLabel>
          <FieldValue span={22}>
            <AddressTable
              title={i18next.t("user:Addresses")}
              table={this.state.user.addresses}
              onUpdateTable={(value) => {
                this.updateUserField("addresses", value);
              }}
            />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Affiliation") {
      return (
        (this.state.application === null || this.state.user === null) ? null : (
          <AffiliationSelect labelSpan={(Setting.isMobile()) ? 22 : 2} application={this.state.application} user={this.state.user} onUpdateUserField={(key, value) => {return this.updateUserField(key, value);}} />
        )
      );
    } else if (accountItem.name === "Title") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Title"), i18next.t("general:Title - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.title} onChange={e => {
              this.updateUserField("title", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "ID card type") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:ID card type"), i18next.t("user:ID card type - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.idCardType} onChange={e => {
              this.updateUserField("idCardType", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "ID card") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:ID card"), i18next.t("user:ID card - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.idCard} disabled={disabled} onChange={e => {
              this.updateUserField("idCard", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "ID card info") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:ID card info"), i18next.t("user:ID card info - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <div className="grid grid-cols-12 gap-3 mt-5">
              {
                [
                  {name: "ID card front", value: "idCardFront"},
                  {name: "ID card back", value: "idCardBack"},
                  {name: "ID card with person", value: "idCardWithPerson"},
                ].map((entry) => {
                  return this.renderImage(this.state.user.properties === null ? "" : (this.state.user.properties[entry.value] || ""), this.getIdCardType(entry.name), this.getIdCardText(entry.name), entry.value, disabled);
                })
              }
            </div>
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Real name") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("application:Real name"), i18next.t("user:Real name - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.realName} disabled={disabled} onChange={e => {
              this.updateUserField("realName", e.target.value);
            }} placeholder={i18next.t("user:Please enter your real name")} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "ID verification") {
      const isVerified = this.state.user.isVerified;
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:ID verification"), i18next.t("user:ID verification - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Button
              disabled={isVerified || disabled}
              onClick={() => this.handleVerifyIdentification()}
            >
              {isVerified ? i18next.t("user:Verified") : i18next.t("user:Verify Identity")}
            </Button>
            {isVerified && (
              <Badge className="ml-2 bg-green-500/20 text-green-400 border-green-500/30">
                <CheckCircle className="w-3.5 h-3.5 mr-1 inline" /> {i18next.t("user:Identity verified")}
              </Badge>
            )}
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Homepage") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Homepage"), i18next.t("user:Homepage - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.homepage} onChange={e => {
              this.updateUserField("homepage", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Bio") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Bio"), i18next.t("user:Bio - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.bio} onChange={e => {
              this.updateUserField("bio", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Tag") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Tag"), i18next.t("product:Tag - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            {
              this.getUserOrganization()?.tags?.length > 0 ? (
                <Select value={this.state.user.tag}
                  onValueChange={(value) => {this.updateUserField("tag", value);}}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {this.getUserOrganization()?.tags?.map((tag) => {
                      const tokens = tag.split("|");
                      const value = tokens[0];
                      const displayValue = Setting.getLanguage() !== "zh" ? tokens[0] : tokens[1];
                      return <SelectItem key={value} value={value}>{displayValue}</SelectItem>;
                    })}
                  </SelectContent>
                </Select>
              ) : (
                <Input value={this.state.user.tag} onChange={e => {
                  this.updateUserField("tag", e.target.value);
                }} />
              )
            }
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Language") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Language"), i18next.t("user:Language - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.language} onChange={e => {
              this.updateUserField("language", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Gender") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Gender"), i18next.t("user:Gender - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.gender} onChange={e => {
              this.updateUserField("gender", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Birthday") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Birthday"), i18next.t("user:Birthday - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.birthday} onChange={e => {
              this.updateUserField("birthday", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Education") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Education"), i18next.t("user:Education - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.education} onChange={e => {
              this.updateUserField("education", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Balance") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Balance"), i18next.t("user:Balance - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input type="number" value={this.state.user.balance} onChange={e => {
              this.updateUserField("balance", e.target.value === "" ? null : Number(e.target.value));
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Balance credit") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("organization:Balance credit"), i18next.t("organization:Balance credit - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input type="number" value={this.state.user.balanceCredit ?? 0} onChange={e => {
              this.updateUserField("balanceCredit", e.target.value === "" ? null : Number(e.target.value));
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Balance currency") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("organization:Balance currency"), i18next.t("organization:Balance currency - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Select value={this.state.user.balanceCurrency || "USD"} onValueChange={(value) => {
              this.updateUserField("balanceCurrency", value);
            }}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {Setting.CurrencyOptions.map((item, index) => (
                  <SelectItem key={index} value={item.id}>{Setting.getCurrencyWithFlag(item.id)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Score") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Score"), i18next.t("user:Score - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input type="number" value={this.state.user.score} onChange={e => {
              this.updateUserField("score", e.target.value === "" ? null : Number(e.target.value));
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Karma") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Karma"), i18next.t("user:Karma - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input type="number" value={this.state.user.karma} onChange={e => {
              this.updateUserField("karma", e.target.value === "" ? null : Number(e.target.value));
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Ranking") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Ranking"), i18next.t("user:Ranking - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input type="number" value={this.state.user.ranking} onChange={e => {
              this.updateUserField("ranking", e.target.value === "" ? null : Number(e.target.value));
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Signup application") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Signup application"), i18next.t("general:Signup application - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Select disabled={disabled} value={this.state.user.signupApplication}
              onValueChange={(value) => {this.updateUserField("signupApplication", value);}}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {this.state.applications.map((application) => (
                  <SelectItem key={application.name} value={application.name}>{application.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Register type") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Register type"), i18next.t("user:Register type - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.registerType} disabled={!this.props.account.isAdmin}
              onChange={e => {this.updateUserField("registerType", e.target.value);}} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Register source") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Register source"), i18next.t("user:Register source - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.registerSource} disabled={!this.props.account.isAdmin}
              onChange={e => {this.updateUserField("registerSource", e.target.value);}} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Roles") {
      return (
        <FieldRow className="items-center">
          <FieldLabel>{Setting.getLabel(i18next.t("general:Roles"), i18next.t("general:Roles - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            {Setting.getTags(this.state.user.roles.map(role => role.name))}
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Permissions") {
      return (
        <FieldRow className="items-center">
          <FieldLabel>{Setting.getLabel(i18next.t("general:Permissions"), i18next.t("general:Permissions - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            {Setting.getTags(this.state.user.permissions.map(permission => permission.name))}
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "3rd-party logins") {
      return (
        !this.isSelfOrAdmin() ? null : (
          <FieldRow>
            <FieldLabel>{Setting.getLabel(i18next.t("user:3rd-party logins"), i18next.t("user:3rd-party logins - Tooltip"))}</FieldLabel>
            <FieldValue span={22}>
              <div style={{marginBottom: 20}}>
                {
                  (this.state.application === null || this.state.user === null) ? null : (
                    this.state.application?.providers.filter(providerItem => Setting.isProviderVisible(providerItem)).map((providerItem) =>
                      (providerItem.provider.category === "OAuth" || providerItem.provider.category === "Web3") ? (
                        <OAuthWidget
                          key={providerItem.name}
                          labelSpan={(Setting.isMobile()) ? 10 : 3}
                          user={this.state.user}
                          application={this.state.application}
                          providerItem={providerItem}
                          account={this.props.account}
                          onUnlinked={() => {return this.unlinked();}} />
                      ) : (
                        <SamlWidget
                          key={providerItem.name}
                          labelSpan={(Setting.isMobile()) ? 10 : 3}
                          user={this.state.user}
                          application={this.state.application}
                          providerItem={providerItem}
                          onUnlinked={() => {return this.unlinked();}} />
                      )
                    )
                  )
                }
              </div>
            </FieldValue>
          </FieldRow>
        )
      );
    } else if (accountItem.name === "Properties") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Properties"), i18next.t("user:Properties - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <PropertyTable properties={this.state.user.properties} onUpdateTable={(value) => {this.updateUserField("properties", value);}} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Is admin") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Is admin"), i18next.t("user:Is admin - Tooltip"))}</FieldLabel>
          <FieldValue span={2}>
            <Switch disabled={disabled} checked={this.state.user.isAdmin} onCheckedChange={(checked) => {
              this.updateUserField("isAdmin", checked);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Is forbidden") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Is forbidden"), i18next.t("user:Is forbidden - Tooltip"))}</FieldLabel>
          <FieldValue span={2}>
            <Switch checked={this.state.user.isForbidden} onCheckedChange={(checked) => {
              this.updateUserField("isForbidden", checked);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Is deleted") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Is deleted"), i18next.t("user:Is deleted - Tooltip"))}</FieldLabel>
          <FieldValue span={2}>
            <Switch checked={this.state.user.isDeleted} onCheckedChange={(checked) => {
              this.updateUserField("isDeleted", checked);
              this.updateUserField("deletedTime", checked ? moment().format() : "");
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "MFA items") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:MFA items"), i18next.t("general:MFA items - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <MfaTable
              title={i18next.t("general:MFA items")}
              table={this.state.user.mfaItems ?? []}
              onUpdateTable={(value) => {this.updateUserField("mfaItems", value);}}
            />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Consents") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("consent:Consents"), i18next.t("consent:Consents - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <ConsentTable
              title={i18next.t("consent:Consents")}
              table={this.state.consents}
              onUpdateTable={() => this.getUser()}
            />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Multi-factor authentication") {
      return (
        !this.isSelfOrAdmin() ? null : (
          <FieldRow>
            <FieldLabel>{Setting.getLabel(i18next.t("mfa:Multi-factor authentication"), i18next.t("mfa:Multi-factor authentication - Tooltip "))}</FieldLabel>
            <FieldValue span={22}>
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-4">
                    <span>{i18next.t("mfa:Multi-factor methods")}</span>
                    {this.state.multiFactorAuths?.some(mfaProps => mfaProps.enabled) ?
                      <PopconfirmModal
                        text={i18next.t("general:Disable")}
                        title={i18next.t("general:Sure to disable") + "?"}
                        onConfirm={() => this.deleteMfa()}
                        size="small"
                      /> : null
                    }
                  </CardTitle>
                </CardHeader>
                <CardContent className="py-2">
                  <ul className="divide-y divide-white/10">
                    {this.state.multiFactorAuths?.map((item) => (
                      <li key={item.mfaType} className="flex items-center justify-between py-2">
                        <div className="flex gap-2 items-center text-sm">
                          <span>{i18next.t("general:Type")}: {item.mfaType}</span>
                          <span>{item.secret}</span>
                        </div>
                        {item.enabled ? (
                          <div className="flex gap-2 items-center">
                            <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                              <CheckCircle className="w-3.5 h-3.5 mr-1 inline" />
                              {i18next.t("general:Enabled")}
                            </Badge>
                            {item.isPreferred ?
                              <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 mr-5">
                                <CheckCircle className="w-3.5 h-3.5 mr-1 inline" />
                                {i18next.t("mfa:preferred")}
                              </Badge> :
                              <Button className="mr-5" onClick={() => {
                                const values = {
                                  owner: this.state.user.owner,
                                  name: this.state.user.name,
                                  mfaType: item.mfaType,
                                };
                                MfaBackend.SetPreferredMfa(values).then((res) => {
                                  if (res.status === "ok") {
                                    this.setState({
                                      multiFactorAuths: res.data,
                                    });
                                  }
                                });
                              }}>
                                {i18next.t("mfa:Set preferred")}
                              </Button>
                            }
                            {this.isSelf() ? <Button variant="outline" onClick={() => {
                              this.props.history.push(`/mfa/setup?mfaType=${item.mfaType}`);
                            }}>
                              {i18next.t("general:Edit")}
                            </Button> : null}
                          </div>
                        ) :
                          <div className="flex gap-2 items-center">
                            {item.mfaType !== TotpMfaType && Setting.isLocalAdminUser(this.props.account) && !this.isSelf() ?
                              <EnableMfaModal user={this.state.user} mfaType={item.mfaType} onSuccess={() => {
                                this.getUser();
                              }} /> : null}
                            {this.isSelf() ? <Button variant="outline" onClick={() => {
                              this.props.history.push(`/mfa/setup?mfaType=${item.mfaType}`);
                            }}>
                              {i18next.t("mfa:Setup")}
                            </Button> : null}
                          </div>}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </FieldValue>
          </FieldRow>
        )
      );
    } else if (accountItem.name === "WebAuthn credentials") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:WebAuthn credentials"), i18next.t("user:WebAuthn credentials"))}</FieldLabel>
          <FieldValue span={22}>
            <WebAuthnCredentialTable isSelf={this.isSelf()} table={this.state.user.webauthnCredentials} updateTable={(table) => {this.updateUserField("webauthnCredentials", table);}} refresh={this.getUser.bind(this)} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Last change password time") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Last change password time"), i18next.t("user:Last change password time"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.lastChangePasswordTime} onChange={e => {
              this.updateUserField("lastChangePasswordTime", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Managed accounts") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Managed accounts"), i18next.t("user:Managed accounts"))}</FieldLabel>
          <FieldValue span={22}>
            <ManagedAccountTable
              title={i18next.t("user:Managed accounts")}
              table={this.state.user.managedAccounts}
              onUpdateTable={(table) => {this.updateUserField("managedAccounts", table);}}
              applications={this.state.applications}
            />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Face ID") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Face IDs"), i18next.t("user:Face IDs"))}</FieldLabel>
          <FieldValue span={22}>
            <FaceIdTable
              title={i18next.t("user:Face IDs")}
              table={this.state.user.faceIds}
              {...this.props}
              onUpdateTable={(table) => {this.updateUserField("faceIds", table);}}
            />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "MFA accounts") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:MFA accounts"), i18next.t("user:MFA accounts"))}</FieldLabel>
          <FieldValue span={22}>
            <MfaAccountTable
              title={i18next.t("user:MFA accounts")}
              table={this.state.user.mfaAccounts}
              accessToken={this.props.account?.accessToken}
              icon={this.state.user.avatar}
              onUpdateTable={(table) => {this.updateUserField("mfaAccounts", table);}}
            />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Need update password") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("user:Need update password"), i18next.t("user:Need update password - Tooltip"))}</FieldLabel>
          <FieldValue span={2}>
            <Switch disabled={(!this.state.user.phone) && (!this.state.user.email) && (!this.state.user.mfaProps)} checked={this.state.user.needUpdatePassword} onCheckedChange={(checked) => {
              this.updateUserField("needUpdatePassword", checked);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "IP whitelist") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:IP whitelist"), i18next.t("general:IP whitelist - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.ipWhitelist} onChange={e => {
              this.updateUserField("ipWhitelist", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "First name") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:First name"), i18next.t("general:First name - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.firstName} onChange={e => {
              this.updateUserField("firstName", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    } else if (accountItem.name === "Last name") {
      return (
        <FieldRow>
          <FieldLabel>{Setting.getLabel(i18next.t("general:Last name"), i18next.t("general:Last name - Tooltip"))}</FieldLabel>
          <FieldValue span={22}>
            <Input value={this.state.user.lastName} onChange={e => {
              this.updateUserField("lastName", e.target.value);
            }} />
          </FieldValue>
        </FieldRow>
      );
    }
  }

  renderImage(imgUrl, title, set, tag, disabled) {
    return (
      <div className="col-span-12 md:col-span-4 text-center mx-auto" style={{marginLeft: "20px"}} key={tag}>
        {
          imgUrl ?
            <div style={{marginBottom: "10px"}}>
              <a target="_blank" rel="noreferrer" href={imgUrl} style={{marginBottom: "10px"}}>
                <AccountAvatar src={imgUrl} alt={imgUrl} height={150} />
              </a>
            </div>
            :
            <div className="border border-dotted border-gray-500 rounded-sm" style={{height: "78%", marginBottom: "10px"}}>
              <div style={{fontSize: 30, margin: 10}}>+</div>
              <div style={{verticalAlign: "middle", marginBottom: 10}}>{`(${i18next.t("general:empty")})`}</div>
            </div>
        }
        {
          (this.props.account === null) ? null : (
            <CropperDivModal disabled={disabled} tag={tag} setTitle={set} buttonText={`${title}...`} title={title} user={this.state.user} organization={this.getUserOrganization()} />
          )
        }
      </div>
    );
  }

  isAccountItemVisible(item) {
    if (!item.visible) {
      return false;
    }

    const isAdmin = Setting.isLocalAdminUser(this.props.account);
    if (item.viewRule === "Self") {
      if (!this.isSelfOrAdmin()) {
        return false;
      }
    } else if (item.viewRule === "Admin") {
      if (!isAdmin) {
        return false;
      }
    }

    return true;
  }

  getAccountItemsByTab(tab) {
    const accountItems = this.getUserOrganization()?.accountItems || [];
    return accountItems.filter(item => {
      if (!this.isAccountItemVisible(item)) {
        return false;
      }

      const itemTab = item.tab || "";
      return itemTab === tab;
    });
  }

  getUniqueTabs() {
    const accountItems = this.getUserOrganization()?.accountItems || [];
    const tabs = new Set();

    accountItems.forEach(item => {
      if (this.isAccountItemVisible(item)) {
        tabs.add(item.tab || "");
      }
    });

    return Array.from(tabs).sort((a, b) => {
      // Empty string (default tab) comes first
      if (a === "") {
        return -1;
      }
      if (b === "") {
        return 1;
      }
      return a.localeCompare(b);
    });
  }

  renderUserForm() {
    const tabs = this.getUniqueTabs();

    // If there are no tabs or only one tab (default), render without tab navigation
    if (tabs.length === 0 || (tabs.length === 1 && tabs[0] === "")) {
      const accountItems = this.getAccountItemsByTab("");
      return (
        <div>
          {accountItems.map(accountItem => (
            <React.Fragment key={accountItem.name}>
              {this.renderAccountItem(accountItem)}
            </React.Fragment>
          ))}
        </div>
      );
    }

    // Render with tabs
    const activeKey = this.state.activeMenuKey || tabs[0] || "";

    const setActive = (key) => {
      this.setState({activeMenuKey: key});
      window.location.hash = key;
    };

    if (this.state.menuMode === "Vertical") {
      // Vertical nav: aside + content
      return (
        <div className="flex bg-inherit" style={{maxHeight: "70vh", overflow: "auto"}}>
          <aside className="w-60 shrink-0 sticky top-0">
            <nav>
              <ul className="space-y-1">
                {tabs.map((tab) => {
                  const isActive = tab === activeKey;
                  const label = tab === "" ? i18next.t("general:Default") : tab;
                  return (
                    <li key={tab}>
                      <button
                        type="button"
                        onClick={() => setActive(tab)}
                        className={cn(
                          "w-full text-left px-3 py-2 rounded-md text-sm transition-colors",
                          isActive ? "bg-white/10 text-white" : "text-gray-300 hover:bg-white/5"
                        )}
                      >
                        {label}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </nav>
          </aside>
          <main className="flex-1 px-4">
            <div>
              {this.getAccountItemsByTab(activeKey).map(accountItem => (
                <React.Fragment key={accountItem.name}>
                  {this.renderAccountItem(accountItem)}
                </React.Fragment>
              ))}
            </div>
          </main>
        </div>
      );
    }

    // Horizontal Tabs header + content below
    return (
      <div className="bg-inherit">
        <div className="bg-inherit">
          <Tabs value={activeKey} onValueChange={setActive}>
            <TabsList>
              {tabs.map((tab) => (
                <TabsTrigger key={tab} value={tab}>
                  {tab === "" ? i18next.t("general:Default") : tab}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
        <div className="bg-inherit" style={{maxHeight: "70vh", overflow: "auto"}}>
          <main className="px-4">
            <div>
              {this.getAccountItemsByTab(activeKey).map(accountItem => (
                <React.Fragment key={accountItem.name}>
                  {this.renderAccountItem(accountItem)}
                </React.Fragment>
              ))}
            </div>
          </main>
        </div>
      </div>
    );
  }

  renderUser() {
    return (
      <div className="bg-white/[0.02] border border-white/10 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">
            {(this.props.account === null) ? i18next.t("user:User Profile") : (
              this.state.mode === "add" ? i18next.t("user:New User") : (this.isSelf() ? i18next.t("account:My Account") : i18next.t("user:Edit User"))
            )}
          </h2>
          {this.props.account !== null && (
            <div className="flex gap-2">
              <button className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.submitUserEdit(false)}>{i18next.t("general:Save")}</button>
              <button className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100" onClick={() => this.submitUserEdit(true)}>{i18next.t("general:Save & Exit")}</button>
              {this.state.mode === "add" && <button className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.deleteUser()}>{i18next.t("general:Cancel")}</button>}
            </div>
          )}
        </div>
        {this.renderUserForm()}
      </div>
    );
  }

  getIdCardType(key) {
    if (key === "ID card front") {
      return i18next.t("user:ID card front");
    } else if (key === "ID card back") {
      return i18next.t("user:ID card back");
    } else if (key === "ID card with person") {
      return i18next.t("user:ID card with person");
    } else {
      return "Unknown Id card name: " + key;
    }
  }

  getIdCardText(key) {
    if (key === "ID card front") {
      return i18next.t("user:Upload ID card front picture");
    } else if (key === "ID card back") {
      return i18next.t("user:Upload ID card back picture");
    } else if (key === "ID card with person") {
      return i18next.t("user:Upload ID card with person picture");
    } else {
      return "Unknown Id card name: " + key;
    }
  }

  submitUserEdit(exitAfterSave) {
    const user = Setting.deepCopy(this.state.user);
    UserBackend.updateUser(this.state.organizationName, this.state.userName, user)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            organizationName: this.state.user.owner,
            userName: this.state.user.name,
          });
          if (exitAfterSave) {
            if (this.state.returnUrl) {
              window.location.href = this.state.returnUrl;
              return;
            }
            const userListUrl = sessionStorage.getItem("userListUrl");
            if (userListUrl !== null) {
              this.props.history.push(userListUrl);
            } else {
              if (Setting.isLocalAdminUser(this.props.account)) {
                this.props.history.push("/users");
              } else {
                this.props.history.push("/");
              }
            }
          } else {
            if (location.pathname !== "/account") {
              this.props.history.push(`/users/${this.state.user.owner}/${this.state.user.name}`);
            }
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateUserField("owner", this.state.organizationName);
          this.updateUserField("name", this.state.userName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteUser() {
    UserBackend.deleteUser(this.state.user)
      .then((res) => {
        if (res.status === "ok") {
          const userListUrl = sessionStorage.getItem("userListUrl");
          if (userListUrl !== null) {
            this.props.history.push(userListUrl);
          } else {
            this.props.history.push("/users");
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  render() {
    if (this.state.loading) {
      return <div className="flex items-center justify-center py-20"><div className="text-gray-400 text-lg">Loading...</div></div>;
    }

    if (this.state.user === null) {
      return (
        <div className="flex flex-col items-center justify-center py-20 space-y-4">
          <h1 className="text-4xl font-bold text-white">404 NOT FOUND</h1>
          <p className="text-gray-400">{i18next.t("general:Sorry, the user you visited does not exist or you are not authorized to access this user.")}</p>
          <a href="/" className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100">{i18next.t("general:Back Home")}</a>
        </div>
      );
    }

    return (
      <div className="max-w-5xl mx-auto space-y-6">
        {this.renderUser()}
        {this.props.account !== null && (
          <div className="flex gap-3">
            <button className="px-6 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.submitUserEdit(false)}>{i18next.t("general:Save")}</button>
            <button className="px-6 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100" onClick={() => this.submitUserEdit(true)}>{i18next.t("general:Save & Exit")}</button>
            {this.state.mode === "add" && <button className="px-6 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.deleteUser()}>{i18next.t("general:Cancel")}</button>}
          </div>
        )}
      </div>
    );
  }
}

export default withRouter(UserEditPage);
