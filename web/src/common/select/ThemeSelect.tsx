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

import React, {useState} from "react";
import {Sun, Moon, Minimize2, Check} from "lucide-react";
import i18next from "i18next";

export const Themes = [
  {label: "Default", key: "default", icon: <Sun className="w-5 h-5" />},
  {label: "Dark", key: "dark", icon: <Moon className="w-5 h-5" />},
  {label: "Compact", key: "compact", icon: <Minimize2 className="w-5 h-5" />},
];

function getIcon(themeKey: string[]) {
  if (themeKey?.includes("dark")) {
    return <Moon className="w-5 h-5" />;
  }
  return <Sun className="w-5 h-5" />;
}

interface ThemeSelectProps {
  themeAlgorithm: string[];
  onChange: (theme: string[]) => void;
}

const ThemeSelect = (props: ThemeSelectProps) => {
  const {themeAlgorithm, onChange} = props;
  const [open, setOpen] = useState(false);

  const icon = getIcon(themeAlgorithm);

  const handleClick = (key: string) => {
    let nextTheme: string[];
    if (key === "compact") {
      if (themeAlgorithm.includes("compact")) {
        nextTheme = themeAlgorithm.filter((t) => t !== "compact");
      } else {
        nextTheme = [...themeAlgorithm, "compact"];
      }
    } else {
      if (!themeAlgorithm.includes(key)) {
        if (key === "dark") {
          nextTheme = [...themeAlgorithm.filter((t) => t !== "default"), key];
        } else {
          nextTheme = [...themeAlgorithm.filter((t) => t !== "dark"), key];
        }
      } else {
        nextTheme = [...themeAlgorithm];
      }
    }
    onChange(nextTheme);
  };

  return (
    <div className="relative inline-block">
      <button
        className="flex items-center justify-center p-2 text-white hover:text-gray-300 transition-colors"
        onClick={() => setOpen(!open)}
        onBlur={() => setTimeout(() => setOpen(false), 200)}
      >
        {icon}
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 bg-[#1a1a1a] border border-white/10 rounded-lg py-1 shadow-lg min-w-[160px] z-50">
          {Themes.map((theme) => (
            <button
              key={theme.key}
              className="w-full flex items-center justify-between px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors"
              onMouseDown={(e) => {
                e.preventDefault();
                handleClick(theme.key);
              }}
            >
              <span className="flex items-center gap-2">
                {theme.icon}
                {i18next.t(`theme:${theme.label}`)}
              </span>
              {themeAlgorithm.includes(theme.key) && <Check className="w-4 h-4" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default ThemeSelect;
