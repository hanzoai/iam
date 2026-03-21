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

import React from "react";
import CodeMirror from "@uiw/react-codemirror";
import {materialDark} from "@uiw/codemirror-theme-material";
import {langs} from "@uiw/codemirror-extensions-langs";

export const Editor = (props: any) => {
  let style: React.CSSProperties = {};
  let height = props.height;
  let width = props.width;
  const copy2StyleProps = [
    "width", "maxWidth", "minWidth",
    "height", "maxHeight", "minHeight",
  ];
  if (props.fillHeight) {
    height = "100%";
    style = {...style, height: "100%"};
  }
  if (props.fillWidth) {
    width = "100%";
    style = {...style, width: "100%"};
  }
  copy2StyleProps.forEach(el => {
    if (["number", "string"].includes(typeof props[el])) {
      style = {...style, [el]: props[el]};
    }
  });
  if (props.style) {
    style = {...style, ...props.style};
  }
  let extensions: any[] = [];
  const langMap: Record<string, string> = {
    javascript: "js",
    js: "js",
    html: "html",
    css: "css",
    xml: "xml",
    json: "json",
  };
  const langKey = langMap[props.lang];
  if (langKey && (langs as any)[langKey]) {
    extensions = [(langs as any)[langKey]()];
  }

  return (
    <CodeMirror
      value={props.value}
      {...props}
      width={width}
      height={height}
      style={style}
      readOnly={props.readOnly}
      theme={props.dark ? materialDark : "light"}
      extensions={extensions}
      onChange={props.onChange}
    />
  );
};

export default Editor;
