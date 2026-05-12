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

// @ts-nocheck
// Demo-mode hijack ripped 2026-05-12. The upstream Casdoor behavior
// intercepted every "Unauthorized operation" response and prompted the
// operator to redirect to the public demo at https://iam.hanzo.ai —
// which is wrong for every Hanzo deployment (local docker-compose,
// liquidity universe, etc). A real 403 should surface as a real 403;
// the UI no longer offers to bounce the operator off-cluster.
const {fetch: originalFetch} = window;
const requestFilters = [];
const responseFilters = [];

window.fetch = async(url, option = {}) => {
  requestFilters.forEach(filter => filter(url, option));

  return new Promise((resolve, reject) => {
    originalFetch(url, option)
      .then(res => {
        if (!url.startsWith("/v1/iam/get-organizations")) {
          responseFilters.forEach(filter => filter(res.clone()));
        }
        resolve(res);
      })
      .catch(error => {
        reject(error);
      });
  });
};
