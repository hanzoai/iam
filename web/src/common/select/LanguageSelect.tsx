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

import React, {useMemo, useRef, useState} from "react";
import {Globe} from "lucide-react";
import * as Setting from "../../Setting";

function flagIcon(country: string, alt: string) {
  return (
    <img width={24} alt={alt} src={`/flag-icons/${country}.svg`} />
  );
}

interface LanguageSelectProps {
  languages?: string[];
  onClick?: (key: string) => void;
  style?: React.CSSProperties;
}

const LanguageSelect = (props: LanguageSelectProps) => {
  const languages = props.languages ?? Setting.Countries.map((item: any) => item.key);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Preload flag icons
  useMemo(() => {
    Setting.Countries.forEach((country: any) => {
      new Image().src = `/flag-icons/${country.country}.svg`;
    });
  }, []);

  const languageItems = useMemo(() => {
    return Setting.Countries.filter((country: any) =>
      languages.includes(country.key)
    );
  }, [languages]);

  const handleClick = (key: string) => {
    if (typeof props.onClick === "function") {
      props.onClick(key);
    }
    Setting.setLanguage(key);
    setOpen(false);
  };

  if (languageItems.length === 0) {
    return null;
  }

  return (
    <div className="relative inline-block" ref={ref}>
      <button
        className="flex items-center justify-center p-2 text-white hover:text-gray-300 transition-colors"
        style={props.style}
        onClick={() => setOpen(!open)}
        onBlur={() => setTimeout(() => setOpen(false), 200)}
      >
        <Globe className="w-6 h-6" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 bg-[#1a1a1a] border border-white/10 rounded-lg py-1 shadow-lg min-w-[160px] z-50">
          {languageItems.map((country: any) => (
            <button
              key={country.key}
              className="w-full flex items-center gap-3 px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors"
              onMouseDown={(e) => {
                e.preventDefault();
                handleClick(country.key);
              }}
            >
              {flagIcon(country.country, country.alt)}
              <span>{country.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default LanguageSelect;
