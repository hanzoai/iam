// @ts-nocheck
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

import React from "react";
import * as Setting from "../Setting";
import {useHistory} from "react-router-dom";

function SingleCard({logo, link, title, desc, time, tags, isSingle}) {
  const history = useHistory();

  function wrappedAsSilentSigninLink(url) {
    if (url && url.startsWith("http")) {
      url += url.includes("?") ? "&silentSignin=1" : "?silentSignin=1";
    }
    return url;
  }

  function renderTags(tags) {
    if (!tags || !Array.isArray(tags) || tags.length === 0) return null;
    return (
      <div className="mt-2 flex flex-wrap gap-1">
        {tags.map(tag => (
          <span key={tag.name} className="px-2 py-0.5 rounded text-xs text-white" style={{backgroundColor: tag.color}}>
            {tag.name}
          </span>
        ))}
      </div>
    );
  }

  const silentSigninLink = wrappedAsSilentSigninLink(link);

  const handleClick = () => {
    if (silentSigninLink && silentSigninLink.startsWith("http")) {
      Setting.goToLink(silentSigninLink);
    } else if (silentSigninLink) {
      history.push(silentSigninLink);
    }
  };

  if (Setting.isMobile()) {
    return (
      <div className="w-full text-center cursor-pointer border-b border-zinc-800 p-4" onClick={handleClick}>
        <img src={logo} alt="logo" className="w-full mb-5" />
        <h3 className="text-white font-medium">{title}</h3>
        <p className="text-zinc-400 text-sm">{desc}</p>
        {renderTags(tags)}
      </div>
    );
  }

  return (
    <div className="px-5 pb-5 mb-5" style={{width: isSingle ? "320px" : "25%"}}>
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30 hover:bg-zinc-900/60 cursor-pointer transition-colors h-full" onClick={handleClick}>
        <img alt="logo" src={logo} className="w-full h-[200px] p-5 object-scale-down" />
        <div className="px-4 pb-4">
          <h3 className="text-white font-medium">{title}</h3>
          <p className="text-zinc-400 text-sm mt-1">{desc}</p>
          {renderTags(tags)}
          {time && <p className="text-zinc-500 text-xs mt-2">{Setting.getFormattedDateShort(time)}</p>}
        </div>
      </div>
    </div>
  );
}

export default SingleCard;
