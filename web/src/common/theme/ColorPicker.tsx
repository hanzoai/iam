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

import React, {useMemo, useState} from "react";
import {TinyColor} from "@ctrl/tinycolor";

export const BLUE_COLOR = "#1677FF";
export const PINK_COLOR = "#ED4192";
export const GREEN_COLOR = "#00B96B";

export const COLORS = [
  {color: BLUE_COLOR},
  {color: "#5734d3"},
  {color: "#9E339F"},
  {color: PINK_COLOR},
  {color: "#E0282E"},
  {color: "#F4801A"},
  {color: "#F2BD27"},
  {color: GREEN_COLOR},
];

export const PRESET_COLORS = COLORS.map(({color}) => color);

interface ColorPickerProps {
  value?: string;
  onChange?: (color: string) => void;
}

export default function ColorPicker({value, onChange}: ColorPickerProps) {
  const [pickerOpen, setPickerOpen] = useState(false);

  const matchColors = useMemo(() => {
    const valueStr = new TinyColor(value).toRgbString();
    let existActive = false;

    const colors = PRESET_COLORS.map((color) => {
      const colorStr = new TinyColor(color).toRgbString();
      const active = colorStr === valueStr;
      existActive = existActive || active;
      return {color, active, picker: false};
    });

    return [
      ...colors,
      {
        color: "conic-gradient(red, yellow, lime, aqua, blue, magenta, red)",
        picker: true,
        active: !existActive,
      },
    ];
  }, [value]);

  return (
    <div className="flex items-center gap-6">
      <input
        value={value || ""}
        onChange={(event) => {
          onChange?.(event.target.value);
        }}
        className="w-[120px] px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none focus:border-white/40"
      />
      <div className="flex items-center gap-3">
        {matchColors.map(({color, active, picker}) => {
          const swatch = (
            <button
              key={color}
              type="button"
              className={`w-5 h-5 rounded-full cursor-pointer transition-all inline-block ${
                active ? "ring-2 ring-offset-2 ring-offset-[#0a0a0a] ring-white" : ""
              }`}
              style={{background: color}}
              onClick={() => {
                if (picker) {
                  setPickerOpen(!pickerOpen);
                } else {
                  onChange?.(color);
                }
              }}
            />
          );

          if (picker) {
            return (
              <div key={color} className="relative">
                {swatch}
                {pickerOpen && (
                  <div className="absolute z-50 top-full mt-2 left-0">
                    <div className="bg-[#1a1a1a] border border-white/10 rounded-lg p-3 shadow-lg">
                      <input
                        type="color"
                        value={value || "#ffffff"}
                        onChange={(e) => onChange?.(e.target.value)}
                        className="w-32 h-32 cursor-pointer bg-transparent border-0"
                      />
                    </div>
                  </div>
                )}
              </div>
            );
          }

          return swatch;
        })}
      </div>
    </div>
  );
}
