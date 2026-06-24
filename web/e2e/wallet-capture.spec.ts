// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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

// Screenshot capture for the multi-chain wallet-login UI, branded for BOTH
// lux.id and iam.hanzo.ai. This drives the SAME REAL production flow as
// wallet-login.spec.ts (real getWalletChains() picker with real ChainIcon SVGs,
// real authViaWallet() -> /v1/iam/web3/{nonce,verify} against the REAL IAM
// server, mock signer only) and saves a PNG of every wallet-connect screen per
// brand. No assertions of business logic beyond "the login succeeded" — its job
// is faithful visual capture. Screenshots land in e2e/screenshots/ (gitignored).

import {test, type Page} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, "screenshots");
mkdirSync(SHOTS, {recursive: true});

const ALL_CHAINS = ["evm", "solana", "bitcoin", "ton", "xrp", "polkadot", "cardano"];

interface BrandSpec {
  key: "lux" | "hanzo";
  prefix: string; // file prefix, e.g. "luxid"
  name: string;
}

const BRANDS: BrandSpec[] = [
  {key: "lux", prefix: "luxid", name: "Lux (lux.id)"},
  {key: "hanzo", prefix: "hanzoid", name: "Hanzo (iam.hanzo.ai)"},
];

async function gotoBrand(page: Page, brand: BrandSpec): Promise<void> {
  await page.goto(`/harness.html?brand=${brand.key}`);
  await page.waitForFunction(() => (window as unknown as {__harnessReady?: boolean}).__harnessReady === true);
  // All 7 chain buttons present before we shoot.
  for (const c of ALL_CHAINS) {
    await page.getByTestId(`wallet-chain-${c}`).waitFor({state: "visible"});
  }
}

// Drive one chain through the REAL production flow and wait for the verified,
// logged-in state (the harness restores it from sessionStorage across the
// production reload). Returns once data-state="logged-in".
async function driveChain(page: Page, chain: string): Promise<void> {
  const verifyResponsePromise = page.waitForResponse(
    (r) => r.url().includes("/v1/iam/web3/verify") && r.request().method() === "POST",
    {timeout: 20000},
  );
  await page.getByTestId(`wallet-chain-${chain}`).click();
  await verifyResponsePromise;
  await page.getByTestId("status").waitFor({state: "attached"});
  await page.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.getAttribute("data-state") === "logged-in",
    {timeout: 15000},
  );
}

for (const brand of BRANDS) {
  test.describe(`wallet-connect capture — ${brand.name}`, () => {
    // (1) The full login page with the wallet-connect option in context —
    // social (Google/GitHub) + email/password + the 7-chain wallet picker.
    test(`${brand.prefix}: login page in context`, async ({page}) => {
      await gotoBrand(page, brand);
      await page.screenshot({path: resolve(SHOTS, `${brand.prefix}-01-login.png`), fullPage: true});
    });

    // (2) The 7-chain picker with logos — a tight shot of just the picker card.
    test(`${brand.prefix}: 7-chain picker with logos`, async ({page}) => {
      await gotoBrand(page, brand);
      await page.getByTestId("login-card").screenshot({path: resolve(SHOTS, `${brand.prefix}-02-picker.png`)});
    });

    // (3a) EVM connect/sign state, then the logged-in success state (4).
    test(`${brand.prefix}: EVM sign -> success`, async ({page}) => {
      await gotoBrand(page, brand);
      // Kick off EVM and grab the "signing" state before it resolves.
      const verifyResponsePromise = page.waitForResponse(
        (r) => r.url().includes("/v1/iam/web3/verify") && r.request().method() === "POST",
        {timeout: 20000},
      );
      await page.getByTestId("wallet-chain-evm").click();
      // Brief moment to show the connecting/active chain highlight + status.
      await page.waitForFunction(
        () => {
          const s = document.querySelector('[data-testid="status"]')?.getAttribute("data-state");
          return s === "idle" || s === "logged-in";
        },
        {timeout: 10000},
      ).catch(() => undefined);
      await page.screenshot({path: resolve(SHOTS, `${brand.prefix}-03-evm-connecting.png`), fullPage: true});
      await verifyResponsePromise;
      await page.waitForFunction(
        () => document.querySelector('[data-testid="status"]')?.getAttribute("data-state") === "logged-in",
        {timeout: 15000},
      );
      await page.getByTestId("success-panel").waitFor({state: "visible"});
      await page.screenshot({path: resolve(SHOTS, `${brand.prefix}-04-success.png`), fullPage: true});
    });

    // (3b) A non-EVM chain connect -> verified -> success (Solana).
    test(`${brand.prefix}: Solana -> success`, async ({page}) => {
      await gotoBrand(page, brand);
      await driveChain(page, "solana");
      await page.getByTestId("success-panel").waitFor({state: "visible"});
      await page.screenshot({path: resolve(SHOTS, `${brand.prefix}-05-solana-success.png`), fullPage: true});
    });
  });
}

// A brand-neutral, zoomed close-up proving all 7 chains render WITH their logos
// in the picker grid (the headline "7 chains, 7 logos" shot).
test("picker — all 7 chains with logos (close-up)", async ({page}) => {
  await page.goto(`/harness.html?brand=hanzo`);
  await page.waitForFunction(() => (window as unknown as {__harnessReady?: boolean}).__harnessReady === true);
  for (const c of ALL_CHAINS) {
    await page.getByTestId(`wallet-chain-${c}`).waitFor({state: "visible"});
  }
  await page.getByTestId("chain-picker").screenshot({path: resolve(SHOTS, "picker-7chains-logos.png")});
});
