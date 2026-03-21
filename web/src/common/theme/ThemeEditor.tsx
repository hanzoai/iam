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

import React, {useEffect, useLayoutEffect, useState} from "react";
import ThemePicker from "./ThemePicker";
import ColorPicker, {GREEN_COLOR, PINK_COLOR} from "./ColorPicker";
import RadiusPicker from "./RadiusPicker";
import i18next from "i18next";
import * as Conf from "../../Conf";

const ThemesInfo: Record<string, any> = {
  default: {},
  dark: {
    borderRadius: 2,
  },
  lark: {
    colorPrimary: GREEN_COLOR,
    borderRadius: 4,
  },
  comic: {
    colorPrimary: PINK_COLOR,
    borderRadius: 16,
  },
};

const noop = () => {};

interface ThemeEditorProps {
  themeData?: any;
  onThemeChange?: (changed: any, allValues: any) => void;
}

export default function ThemeEditor(props: ThemeEditorProps) {
  const themeData = props.themeData ?? Conf.ThemeDefault;
  const onThemeChange = props.onThemeChange ?? noop;

  const [formData, setFormData] = useState(themeData);

  useEffect(() => {
    onThemeChange(null, themeData);
    setFormData(themeData);
  }, []);

  useLayoutEffect(() => {
    const mergedData = {
      ...Conf.ThemeDefault,
      themeType: formData.themeType,
      ...ThemesInfo[formData.themeType],
    };
    onThemeChange(null, mergedData);
    setFormData(mergedData);
  }, [formData.themeType]);

  const updateField = (key: string, value: any) => {
    const newData = {...formData, [key]: value};
    setFormData(newData);
    onThemeChange({[key]: value}, newData);
  };

  return (
    <div className="w-[800px] bg-black">
      <div className="border border-white/10 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-6">{i18next.t("theme:Theme")}</h3>
        <div className="space-y-6">
          <div className="flex items-start">
            <label className="w-1/5 text-sm text-gray-400 pt-2">{i18next.t("theme:Theme")}</label>
            <div className="flex-1">
              <ThemePicker
                value={formData.themeType}
                onChange={(val: string) => updateField("themeType", val)}
              />
            </div>
          </div>
          <div className="flex items-start">
            <label className="w-1/5 text-sm text-gray-400 pt-2">{i18next.t("theme:Primary color")}</label>
            <div className="flex-1">
              <ColorPicker
                value={formData.colorPrimary}
                onChange={(val: string) => updateField("colorPrimary", val)}
              />
            </div>
          </div>
          <div className="flex items-start">
            <label className="w-1/5 text-sm text-gray-400 pt-2">{i18next.t("theme:Border radius")}</label>
            <div className="flex-1">
              <RadiusPicker
                value={formData.borderRadius}
                onChange={(val: number) => updateField("borderRadius", val)}
              />
            </div>
          </div>
          <div className="flex items-center">
            <label className="w-1/5 text-sm text-gray-400">{i18next.t("theme:Is compact")}</label>
            <div className="flex-1">
              <button
                type="button"
                role="switch"
                aria-checked={!!formData.isCompact}
                onClick={() => updateField("isCompact", !formData.isCompact)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  formData.isCompact ? "bg-white" : "bg-white/20"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 rounded-full transition-transform ${
                    formData.isCompact ? "translate-x-6 bg-black" : "translate-x-1 bg-gray-400"
                  }`}
                />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
