// @ts-nocheck
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
import {MetaMaskAvatar} from "react-metamask-avatar";

function AccountAvatar({src, size, width, height}) {
  const matchMetaMask = src.match(/^metamask:(\w+)$/);
  if (matchMetaMask) {
    return <MetaMaskAvatar address={matchMetaMask[1]} size={size} />;
  }
  if (size !== undefined) {
    return <img width={size} height={size} src={src} alt="" />;
  } else if (width === undefined) {
    return <img height={height} src={src} alt="" />;
  } else if (height === undefined) {
    return <img width={width} src={src} alt="" />;
  }
  return null;
}

export default AccountAvatar;
