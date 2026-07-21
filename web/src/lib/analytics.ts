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

import {createAnalytics} from "@hanzo/event";

// Live bearer ref. IAM's session token is set once getAccount() resolves, so the
// ONE stable client survives token changes without re-initializing.
let token: string | null = null;
export function setAnalyticsToken(t: string | null | undefined) {
  token = t ?? null;
}

/** The ONE shared telemetry client. IAM (hanzo.id / identity.hanzo.ai) is the
 *  shared auth funnel every product redirects through — pageviews here
 *  (login / signup / consent) light up the whole cross-product funnel. */
export const analytics = createAnalytics({
  product: "iam",
  host: "https://api.hanzo.ai",
  getToken: () => token,
});
