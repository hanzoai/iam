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
import * as ApplicationBackend from "../backend/ApplicationBackend";
import GridCards from "./GridCards";
import i18next from "i18next";

const AppListPage = (props) => {
  const [applications, setApplications] = React.useState(null);
  const [selectedTags, setSelectedTags] = React.useState([]);
  const [allTags, setAllTags] = React.useState([]);

  const sort = (applications) => {
    return [...applications].sort((a, b) => a.order - b.order);
  };

  const extractTags = (applications) => {
    const tagsSet = new Set();
    applications.forEach(application => {
      if (application.tags && Array.isArray(application.tags)) {
        application.tags.forEach(tag => tagsSet.add(tag));
      }
    });
    return Array.from(tagsSet);
  };

  React.useEffect(() => {
    if (props.account === null) return;
    ApplicationBackend.getApplicationsByOrganization("admin", props.account.owner)
      .then((res) => {
        const applications = res.data || [];
        const sortedApps = sort(applications);
        setApplications(sortedApps);
        setAllTags(extractTags(sortedApps));
      });
  }, [props.account]);

  const handleTagChange = (tag, checked) => {
    setSelectedTags(prev => checked ? [...prev, tag] : prev.filter(t => t !== tag));
  };

  const filterByTags = (applications) => {
    if (selectedTags.length === 0) return applications;
    return applications.filter(application => {
      if (!application.tags || !Array.isArray(application.tags)) return false;
      return selectedTags.every(tag => application.tags.includes(tag));
    });
  };

  const generateTagColor = (tag) => {
    const colors = [
      "#ff4d4f", "#f5222d", "#ff7a45", "#fa541c",
      "#ffa940", "#fa8c16", "#ffc53d", "#faad14",
      "#ffec3d", "#fadb14", "#bae637", "#a0d911",
      "#73d13d", "#52c41a", "#36cfc9", "#13c2c2",
      "#40a9ff", "#1890ff", "#f759ab", "#eb2f96",
    ];
    let hash = 5381;
    for (let i = 0; i < tag.length; i++) {
      hash = (hash * 33) ^ tag.charCodeAt(i);
    }
    return colors[Math.abs(hash) % colors.length];
  };

  const getItems = () => {
    if (applications === null) return null;
    const filteredApps = filterByTags(applications);
    return filteredApps.map(application => {
      let homepageUrl = application.homepageUrl;
      if (homepageUrl === "<custom-url>") {
        homepageUrl = props.account.homepage;
      }
      const tagObjects = application.tags ? application.tags.map(tag => ({name: tag, color: generateTagColor(tag)})) : [];
      return {link: homepageUrl, name: application.displayName, description: application.description, logo: application.logo, createdTime: "", tags: tagObjects};
    });
  };

  return (
    <div className="p-5">
      {allTags.length > 0 && (
        <div className="mb-5 flex flex-wrap gap-2 items-center">
          <span className="mr-2 font-bold text-white">{i18next.t("organization:Tags")}</span>
          {allTags.map(tag => (
            <button key={tag} className="px-3 py-1 rounded text-sm border transition-colors"
              style={{backgroundColor: selectedTags.includes(tag) ? generateTagColor(tag) : "transparent", borderColor: generateTagColor(tag), color: selectedTags.includes(tag) ? "#fff" : generateTagColor(tag)}}
              onClick={() => handleTagChange(tag, !selectedTags.includes(tag))}>
              {tag}
            </button>
          ))}
          {selectedTags.length > 0 && (
            <button onClick={() => setSelectedTags([])} className="ml-2 px-2 py-1 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-400 hover:text-white cursor-pointer">
              {i18next.t("forget:Reset")}
            </button>
          )}
        </div>
      )}
      <div className="flex justify-center flex-col items-center">
        <GridCards items={getItems()} />
      </div>
    </div>
  );
};

export default AppListPage;
