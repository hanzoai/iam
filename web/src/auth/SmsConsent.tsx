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
import i18next from "i18next";
import {Checkbox} from "../components/ui/checkbox";

// Canonical A2P 10DLC consent copy. This EXACT disclosure is reused at every
// point where Hanzo collects a phone number for messaging. It MUST stay
// verbatim-identical to the public opt-in page (hanzo.ai/sms-opt-in,
// `SMS_CONSENT_TEXT`) — Twilio / carrier campaign review compares the wording
// across surfaces. Do not paraphrase; keep one string, reused everywhere.
//
// The string is also the i18n key: this fork ships an empty `en/data.json`
// (English renders the key verbatim via `fallbackLng:"en"` + `keySeparator:false`),
// and the sentence contains no `:` so i18next never splits it on the namespace
// separator. Translators localize the whole sentence through Crowdin.
export const SMS_CONSENT_TEXT =
  "I agree to receive text messages (SMS) from Hanzo AI at the number provided, " +
  "including one-time passcodes and two-factor authentication, account and security " +
  "alerts, and transactional notifications. Message frequency varies. Message and data " +
  "rates may apply. Reply STOP to opt out at any time, or HELP for help. Consent is not " +
  "a condition of any purchase.";

const TERMS_URL = "https://hanzo.ai/terms";
const PRIVACY_URL = "https://hanzo.ai/privacy";

// Small muted Terms/Privacy line shown under every SMS consent surface.
function ConsentLinks() {
  return (
    <p className="text-xs text-neutral-500 mt-1">
      {i18next.t("signup:By continuing, you agree to our")}{" "}
      <a href={TERMS_URL} target="_blank" rel="noreferrer" className="text-neutral-300 hover:text-white underline">
        {i18next.t("signup:Terms of Service")}
      </a>{" "}
      {i18next.t("general:and")}{" "}
      <a href={PRIVACY_URL} target="_blank" rel="noreferrer" className="text-neutral-300 hover:text-white underline">
        {i18next.t("signup:Privacy Policy")}
      </a>.
    </p>
  );
}

// Disclosure-only notice (no checkbox). For phone LOGIN and SMS 2FA, where the
// user either is already authenticated or already opted in at signup.
export function SmsConsentNotice({className = ""}) {
  return (
    <div className={`sms-consent-notice ${className}`}>
      <p className="text-xs text-neutral-500 leading-relaxed">
        {i18next.t(SMS_CONSENT_TEXT)}
      </p>
      <ConsentLinks />
    </div>
  );
}

// Required, unchecked-by-default consent checkbox. For phone SIGNUP — the
// caller MUST gate submit on `checked` (A2P requires affirmative opt-in at the
// point of phone collection). `error` renders the validation message when the
// user tries to submit without checking.
export function SmsConsentCheckbox({checked, onChange, error, className = ""}) {
  return (
    <div className={`sms-consent-checkbox mb-3 ${className}`}>
      <div className="flex items-start gap-2">
        <Checkbox
          id="sms-consent"
          className="mt-0.5 shrink-0"
          checked={!!checked}
          onCheckedChange={(v) => onChange(!!v)}
        />
        <label htmlFor="sms-consent" className="text-xs text-neutral-400 leading-relaxed cursor-pointer">
          {i18next.t(SMS_CONSENT_TEXT)}
        </label>
      </div>
      <ConsentLinks />
      {error && <p className="text-sm text-red-500 mt-1">{error}</p>}
    </div>
  );
}
