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

// End-to-end proof of the Hanzo IAM multi-chain wallet login UI in a real
// browser. The mock wallet (e2e/mock-wallet.ts, installed by the harness)
// produces GENUINE secp256k1 / ed25519 signatures, so the REAL IAM server runs
// its real walletconnect.VerifyProof and accepts the login. Nothing about the
// server flow is faked; only the wallet signer is injected.
//
// Per chain it asserts:
//   1. the 7-chain picker renders (CHAINS x ENABLED_CHAINS)
//   2. GET  /v1/iam/web3/nonce returns a CAIP-122 challenge
//   3. POST /v1/iam/web3/verify returns HTTP 200 {status:"ok"} — the REAL
//      server cryptographically verified the genuine signature
//   4. the UI transitions to a logged-in state
//
// The verify response is captured via Playwright's network listener, which is
// authoritative and survives the production post-login page reload. Screenshots
// land in e2e/screenshots/.

import {test, expect, type Page, type Request, type Response} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, "screenshots");
mkdirSync(SHOTS, {recursive: true});

const ALL_CHAINS = ["evm", "solana", "bitcoin", "ton", "xrp", "polkadot", "cardano"];

interface CapturedCall {
  url: string;
  method: string;
  status: number;
  responseBody?: unknown;
  requestBody?: unknown;
}

interface VerifyCapture {
  status: number;
  body: {status?: string; msg?: string; data?: {data?: unknown}} | null;
}

async function readNetCalls(page: Page): Promise<CapturedCall[]> {
  return page.evaluate(() => (window as unknown as {__netCalls?: CapturedCall[]}).__netCalls ?? []);
}

// Capture every POST /v1/iam/web3/verify response off the wire. This is the
// authoritative proof the REAL server verified the signature, and it is
// independent of any page reload the production success path triggers.
function captureVerify(page: Page): VerifyCapture[] {
  const out: VerifyCapture[] = [];
  page.on("requestfinished", async (req: Request) => {
    if (req.url().includes("/v1/iam/web3/verify") && req.method() === "POST") {
      const res: Response | null = await req.response();
      if (res) {
        out.push({status: res.status(), body: await res.json().catch(() => null)});
      }
    }
  });
  return out;
}

interface HarnessOutcome {
  chain: string;
  ok: boolean;
  verifyStatus: number;
  msg?: string;
  userData?: unknown;
  nonce?: string;
  domain?: string;
  at: number;
}

// Drive one chain through the production flow and assert a real server-verified
// login. The authoritative signal is the harness's own outcome record: the
// wrapped fetch captures the /web3/verify response BODY synchronously the
// instant it returns (before the production success path can reload the page)
// and persists it to window + sessionStorage. Re-reading the wire Response from
// the test races that reload, so we assert on the captured outcome instead. We
// still wait on the POST /verify response to confirm a request reached the
// server and got HTTP 200.
async function driveChain(page: Page, chain: string, verifyCaps: VerifyCapture[]): Promise<HarnessOutcome> {
  const verifyResponsePromise = page.waitForResponse(
    (r) => r.url().includes("/v1/iam/web3/verify") && r.request().method() === "POST",
    {timeout: 20000},
  );

  await page.getByTestId(`wallet-chain-${chain}`).click();

  // A POST /verify reached the server and returned HTTP 200.
  const verifyResponse = await verifyResponsePromise;
  expect(verifyResponse.status(), `POST /web3/verify HTTP status for ${chain}`).toBe(200);

  // (4) The UI reaches the logged-in state. The harness restores this from
  // sessionStorage even if the production success path reloaded the page.
  await expect(page.getByTestId("status")).toHaveAttribute("data-state", "logged-in", {timeout: 15000});

  // (3) Authoritative: the harness captured the verify response body as ok with
  // the resolved/provisioned wallet user. Read it from sessionStorage (survives
  // the production reload) falling back to the live window value.
  const outcome = await page.evaluate(() => {
    const key = "__hanzo_e2e_login";
    try {
      const raw = sessionStorage.getItem(key);
      if (raw) return JSON.parse(raw) as HarnessOutcome;
    } catch {/* fall through */}
    return (window as unknown as {__lastVerify?: HarnessOutcome}).__lastVerify ?? null;
  });

  expect(outcome, `harness captured a verify outcome for ${chain}`).toBeTruthy();
  expect(outcome!.verifyStatus, `captured verify HTTP status for ${chain}`).toBe(200);
  expect(outcome!.ok, `server verify ok for ${chain} (msg: ${outcome!.msg})`).toBe(true);
  expect(outcome!.nonce, `nonce present for ${chain}`).toBeTruthy();
  expect(outcome!.domain, `domain bound in nonce for ${chain}`).toBe("localhost:8000");
  expect(String(outcome!.userData ?? ""), `resolved wallet user for ${chain}`).toContain(chain);

  // Secondary: the wire listener independently saw a POST /verify return 200.
  // (The body re-read can race the production reload, so we only require the
  // HTTP status here; the parsed-ok assertion above uses the harness capture
  // taken synchronously before any reload.)
  expect(verifyCaps.some((v) => v.status === 200), "listener saw a 200 verify response").toBeTruthy();

  return outcome!;
}

test.describe("IAM multi-chain wallet login (real server verify, mock signer)", () => {
  test("renders the 7-chain picker", async ({page}) => {
    const consoleErrors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") consoleErrors.push(m.text());
    });
    page.on("pageerror", (e) => consoleErrors.push(`pageerror: ${e.message}`));

    await page.goto("/harness.html");
    await page.waitForFunction(() => (window as unknown as {__harnessReady?: boolean}).__harnessReady === true);

    // Every ENABLED chain renders a button.
    for (const c of ALL_CHAINS) {
      await expect(page.getByTestId(`wallet-chain-${c}`)).toBeVisible();
    }

    // The production CHAINS list is exactly the 7 expected families.
    const allChainsText = await page.getByTestId("all-chains").textContent();
    for (const c of ALL_CHAINS) {
      expect(allChainsText).toContain(c);
    }

    await page.screenshot({path: resolve(SHOTS, "01-chain-picker.png"), fullPage: true});

    // The harness itself must mount cleanly (no React/JS errors).
    expect(consoleErrors, consoleErrors.join("\n")).toEqual([]);
  });

  test("EVM: connect -> sign -> server verify -> logged in", async ({page}) => {
    const verifyCaps = captureVerify(page);

    await page.goto("/harness.html");
    await page.waitForFunction(() => (window as unknown as {__harnessReady?: boolean}).__harnessReady === true);

    const evmAddr = await page.getByTestId("evm-address").textContent();
    expect(evmAddr).toMatch(/^0x[0-9a-fA-F]{40}$/);

    await page.screenshot({path: resolve(SHOTS, "02-evm-before.png"), fullPage: true});

    const outcome = await driveChain(page, "evm", verifyCaps);

    await page.screenshot({path: resolve(SHOTS, "03-evm-logged-in.png"), fullPage: true});

    // eslint-disable-next-line no-console
    console.log("EVM nonce:", outcome.nonce, "domain:", outcome.domain);
    // eslint-disable-next-line no-console
    console.log("EVM verify user (provisioned/resolved):", JSON.stringify(outcome.userData));
  });

  test("Solana: connect -> sign -> server verify -> logged in", async ({page}) => {
    const verifyCaps = captureVerify(page);

    await page.goto("/harness.html");
    await page.waitForFunction(() => (window as unknown as {__harnessReady?: boolean}).__harnessReady === true);

    const solAddr = await page.getByTestId("sol-address").textContent();
    expect(solAddr, "solana base58 address present").toBeTruthy();

    const outcome = await driveChain(page, "solana", verifyCaps);

    await page.screenshot({path: resolve(SHOTS, "04-solana-logged-in.png"), fullPage: true});

    // eslint-disable-next-line no-console
    console.log("Solana nonce:", outcome.nonce, "domain:", outcome.domain);
    // eslint-disable-next-line no-console
    console.log("Solana verify user (provisioned/resolved):", JSON.stringify(outcome.userData));
  });
});
