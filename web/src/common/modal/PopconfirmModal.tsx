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

import i18next from "i18next";
import React, {useState} from "react";

export const PopconfirmModal = (props: any) => {
  const [open, setOpen] = useState(false);
  const text = props.text ? props.text : i18next.t("general:Delete");

  return (
    <div className="relative inline-block">
      <button
        style={{...props.style}}
        disabled={props.disabled}
        className="px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        onClick={() => !props.disabled && setOpen(true)}
      >
        {text}
      </button>
      {open && (
        <div className="absolute z-50 bottom-full mb-2 left-1/2 -translate-x-1/2 bg-[#1a1a1a] border border-white/10 rounded-lg p-4 shadow-lg min-w-[200px]">
          <p className="text-sm text-gray-300 mb-3">{props.title}</p>
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setOpen(false)}
              className="px-3 py-1 text-xs text-gray-400 hover:text-white transition-colors"
            >
              {i18next.t("general:Cancel")}
            </button>
            <button
              onClick={() => {
                setOpen(false);
                props.onConfirm?.();
              }}
              className="px-3 py-1 text-xs bg-white text-black rounded-md hover:bg-gray-200 transition-colors"
            >
              {i18next.t("general:OK")}
            </button>
          </div>
          {/* Arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 w-0 h-0 border-l-[6px] border-r-[6px] border-t-[6px] border-l-transparent border-r-transparent border-t-white/10" />
        </div>
      )}
    </div>
  );
};

export default PopconfirmModal;
