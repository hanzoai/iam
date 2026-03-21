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

interface RadiusPickerProps {
  value?: number;
  onChange?: (value: number) => void;
}

export default function RadiusPicker({value, onChange}: RadiusPickerProps) {
  return (
    <div className="flex items-center gap-6">
      <div className="relative">
        <input
          type="number"
          value={value ?? 0}
          onChange={(e) => onChange?.(parseFloat(e.target.value) || 0)}
          min={0}
          max={20}
          className="w-[120px] px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none focus:border-white/40 pr-8"
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-gray-500">px</span>
      </div>
      <input
        type="range"
        min={0}
        max={20}
        value={value ?? 0}
        onChange={(e) => onChange?.(parseFloat(e.target.value))}
        className="w-32 accent-white"
      />
    </div>
  );
}
