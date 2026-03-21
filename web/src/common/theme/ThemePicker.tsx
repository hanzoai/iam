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

import React from "react";
import i18next from "i18next";
import * as Setting from "../../Setting";

export const THEMES: Record<string, string> = {
  default: `${Setting.StaticBaseUrl}/img/theme_default.svg`,
  dark: `${Setting.StaticBaseUrl}/img/theme_dark.svg`,
  lark: `${Setting.StaticBaseUrl}/img/theme_lark.svg`,
  comic: `${Setting.StaticBaseUrl}/img/theme_comic.svg`,
};

const themeTypes: Record<string, string> = {
  default: "Default",
  dark: "Dark",
  lark: "Document",
  comic: "Blossom",
};

interface ThemePickerProps {
  value?: string;
  onChange?: (theme: string) => void;
}

export default function ThemePicker({value, onChange}: ThemePickerProps) {
  return (
    <div className="flex gap-6">
      {Object.keys(THEMES).map((theme) => {
        const url = THEMES[theme];
        return (
          <div key={theme} className="flex flex-col items-center gap-2">
            <button
              type="button"
              className={`rounded-lg overflow-hidden cursor-pointer transition-all hover:scale-[1.04] ${
                value === theme
                  ? "ring-2 ring-offset-2 ring-offset-[#0a0a0a] ring-white"
                  : ""
              }`}
              onClick={() => onChange?.(theme)}
            >
              <img src={url} alt={theme} className="shadow-lg" />
            </button>
            <span className="text-sm text-gray-400">{i18next.t(`theme:${themeTypes[theme]}`)}</span>
          </div>
        );
      })}
    </div>
  );
}
