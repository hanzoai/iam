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

import i18next from "i18next";
import React from "react";
import * as Setting from "../Setting";
import SingleCard from "./SingleCard";

const GridCards = (props) => {
  const items = props.items;

  if (items === null || items === undefined) {
    return (
      <div className="flex justify-center items-center mt-[10%]">
        <span className="text-zinc-400 pt-[10%]">{i18next.t("login:Loading")}</span>
      </div>
    );
  }

  return (
    Setting.isMobile() ? (
      <div className="border border-zinc-800 rounded-lg">
        {items.map(item => <SingleCard key={item.link} logo={item.logo} link={item.link} title={item.name} desc={item.description} tags={item.tags} isSingle={items.length === 1} />)}
      </div>
    ) : (
      <div className="w-full px-[100px]">
        <div className="flex flex-wrap justify-center">
          {items.map(item => <SingleCard logo={item.logo} link={item.link} title={item.name} desc={item.description} tags={item.tags} time={item.createdTime} isSingle={items.length === 1} key={item.name} />)}
        </div>
      </div>
    )
  );
};

export default GridCards;
