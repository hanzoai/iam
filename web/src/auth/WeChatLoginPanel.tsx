// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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
import * as AuthBackend from "./AuthBackend";
import i18next from "i18next";
import * as Util from "./Util";
import {QRCodeSVG} from "qrcode.react";
import {Spinner} from "../components/ui/spinner";

class WeChatLoginPanel extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      qrCode: null,
      status: "loading",
      ticket: null,
    };
    this.pollingTimer = null;
  }

  UNSAFE_componentWillMount() {
    this.fetchQrCode();
  }

  componentDidUpdate(prevProps) {
    if (this.props.loginMethod === "wechat" && prevProps.loginMethod !== "wechat") {
      this.fetchQrCode();
    }
    if (prevProps.loginMethod === "wechat" && this.props.loginMethod !== "wechat") {
      this.setState({qrCode: null, loading: false, ticket: null});
      this.clearPolling();
    }
  }

  componentWillUnmount() {
    this.clearPolling();
  }

  clearPolling() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  fetchQrCode() {
    const {application} = this.props;
    const wechatProviderItem = application?.providers?.find(p => p.provider?.type === "WeChat");
    if (wechatProviderItem) {
      this.setState({status: "loading", qrCode: null, ticket: null});
      AuthBackend.getWechatQRCode(`${wechatProviderItem.provider.owner}/${wechatProviderItem.provider.name}`).then(res => {
        if (res.status === "ok" && res.data) {
          this.setState({qrCode: res.data, status: "active", ticket: res.data2});
          this.clearPolling();
          this.pollingTimer = setInterval(() => {
            Util.getEvent(application, wechatProviderItem.provider, res.data2, "signup");
          }, 1000);
        } else {
          this.setState({qrCode: null, status: "expired", ticket: null});
          this.clearPolling();
        }
      }).catch(() => {
        this.setState({qrCode: null, status: "expired", ticket: null});
        this.clearPolling();
      });
    }
  }

  render() {
    const {loginWidth = 320} = this.props;
    const {status, qrCode} = this.state;
    const renderQR = () => {
      if (status === "loading") {
        return (
          <div className="flex justify-center items-center" style={{width: 230, height: 230, margin: "20px auto"}}>
            <Spinner size="lg" />
          </div>
        );
      }
      if (status === "expired" || !qrCode) {
        return (
          <div className="flex justify-center items-center text-muted-foreground" style={{width: 230, height: 230, margin: "20px auto"}}>
            {i18next.t("login:Refresh")}
          </div>
        );
      }
      return (
        <div className="mx-auto my-5 w-fit">
          <QRCodeSVG value={qrCode ?? " "} size={230} />
        </div>
      );
    };
    return (
      <div style={{width: loginWidth}} className="mx-auto text-center mt-4">
        <div className="mt-0.5">
          {renderQR()}
          <div className="mt-2">
            <a onClick={e => {e.preventDefault(); this.fetchQrCode();}}>
              {i18next.t("login:Refresh")}
            </a>
          </div>
        </div>
      </div>
    );
  }
}

export default WeChatLoginPanel;
