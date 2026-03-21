// Copyright 2023 The Hanzo Authors. All Rights Reserved.
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

import i18next from "i18next";
import React, {useEffect, useState} from "react";
import * as Setting from "../../Setting";

export const AgreementModal = (props: any) => {
  const {open, onOk, onCancel, application} = props;
  const [doc, setDoc] = useState("");

  useEffect(() => {
    getTermsOfUseContent(application.termsOfUse).then((data: string) => {
      setDoc(data);
    });
  }, []);

  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
      <div
        className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-full"
        style={{maxWidth: Setting.isMobile() ? "100vw" : "55vw", marginTop: Setting.isMobile() ? "5px" : ""}}
      >
        <h2 className="text-lg font-semibold text-white mb-4">{i18next.t("signup:Terms of Use")}</h2>
        <iframe
          title="terms"
          className="border-0 w-full"
          style={{height: Setting.isMobile() ? "80vh" : "60vh"}}
          srcDoc={doc}
        />
        <div className="flex justify-end gap-2 mt-6">
          <button onClick={onCancel} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">
            {i18next.t("signup:Decline")}
          </button>
          <button onClick={onOk} className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors">
            {i18next.t("signup:Accept")}
          </button>
        </div>
      </div>
    </div>
  );
};

function getTermsOfUseContent(url: string) {
  return fetch(url, {
    method: "GET",
  })
    .then(r => r.text())
    .catch(error => {
      Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${url}, ${error}`);
    });
}

export function isAgreementRequired(application: any) {
  if (application && application.signupItems) {
    const agreementItem = application.signupItems.find((item: any) => item.name === "Agreement");
    if (!agreementItem || agreementItem.rule === "None" || !agreementItem.rule) {
      return false;
    }
    if (agreementItem.required) {
      return true;
    }
  }
  return false;
}

function initDefaultValue(application: any) {
  if (!application || !application.signupItems) {
    return false;
  }

  const agreementItem = application.signupItems.find((item: any) => item.name === "Agreement");

  return isAgreementRequired(application) && agreementItem && agreementItem.rule === "Signin (Default True)";
}

export function renderAgreementFormItem(application: any, required: boolean, layout: any, ths: any) {
  return (
    <React.Fragment>
      <div className="flex items-start gap-2 mb-4">
        <input
          type="checkbox"
          id="agreement-checkbox"
          defaultChecked={!!initDefaultValue(application)}
          className="mt-1 h-4 w-4 rounded border-white/20 bg-transparent text-white accent-white"
          onChange={(e) => {
            ths.form.current.setFieldsValue({agreement: e.target.checked});
          }}
        />
        <label htmlFor="agreement-checkbox" className="text-sm text-gray-300">
          {i18next.t("signup:Accept")}&nbsp;
          <a
            className="text-white underline hover:text-gray-300 cursor-pointer"
            onClick={() => {
              ths.setState({
                isTermsOfUseVisible: true,
              });
            }}
          >
            {i18next.t("signup:Terms of Use")}
          </a>
        </label>
      </div>
      <AgreementModal
        application={application}
        layout={layout}
        open={ths.state.isTermsOfUseVisible}
        onOk={() => {
          ths.form.current.setFieldsValue({agreement: true});
          ths.setState({
            isTermsOfUseVisible: false,
          });
        }}
        onCancel={() => {
          ths.form.current.setFieldsValue({agreement: false});
          ths.setState({
            isTermsOfUseVisible: false,
          });
        }}
      />
    </React.Fragment>
  );
}
