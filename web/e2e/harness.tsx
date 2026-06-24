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

// E2E harness that exercises the REAL production wallet-login code.
//
// It imports getWalletChains() + authViaWallet() straight from
// ../src/auth/WalletConnect.tsx (only ../Setting is aliased to a 2-symbol shim
// so the whole admin app doesn't get bundled). The 7-chain picker it renders is
// the production CHAINS x ENABLED_CHAINS list; each button runs the production
// connect -> /v1/iam/web3/nonce -> connector.signLogin -> /v1/iam/web3/verify
// flow against the REAL IAM server proxied at /v1/iam.
//
// The only mock is the wallet signer (e2e/mock-wallet.ts): real secp256k1 /
// ed25519 keys behind the EIP-1193 / Wallet-Standard surface the connectors
// expect. So the server's walletconnect.VerifyProof verifies a genuine
// signature — true end-to-end, just without a funded extension.
//
// Reload handling: production authViaWallet calls window.location.reload() on a
// successful non-redirect login (for app-hanzo signup the payload is a user
// object, not an http URL → the reload branch). location.reload is
// non-configurable in Chromium, so we DON'T fight it: the wrapped fetch persists
// the /verify outcome to sessionStorage synchronously the instant it returns
// (before reload runs), and on (re)mount the harness restores that state — so
// the "logged in" screenshot is clean whether or not the page reloaded. The
// reload IS the genuine production logged-in navigation; the evidence survives.

import React from "react";
import {createRoot} from "react-dom/client";

import {installMockWallets} from "./mock-wallet";
// REAL production code under test:
import {getWalletChains, CHAINS, type Chain} from "../src/auth/WalletConnect";

// The application/organization the harness verifies against (seeded by the e2e
// backend init data: app-hanzo, org hanzo, enableSignUp=true).
const APPLICATION = {name: "app-hanzo", organization: "hanzo"} as const;

const LOGIN_KEY = "__hanzo_e2e_login"; // sessionStorage key (survives reload)

interface LoginOutcome {
  chain: Chain;
  ok: boolean;
  verifyStatus: number;
  msg?: string;
  userData?: unknown; // the provisioned/resolved user id the server returns
  nonce?: string;
  domain?: string;
  at: number;
}

interface NetCall {
  url: string;
  method: string;
  status: number;
  requestBody?: unknown;
  responseBody?: unknown;
  at: number;
}
declare global {
  interface Window {
    __netCalls?: NetCall[];
    __mockAddrs?: {evmAddress: string; solanaAddress: string};
    __harnessReady?: boolean;
    __settingEvents?: Array<{kind: string; arg1: string; arg2?: string; at: number}>;
    __lastVerify?: LoginOutcome;
  }
}
window.__netCalls = [];

// Transparent fetch passthrough that (a) records nonce + verify calls for the
// spec to read, and (b) the instant a /web3/verify response arrives, persists
// the login outcome to sessionStorage + window so it survives the production
// reload. Requests are never altered.
const realFetch = window.fetch.bind(window);
let pendingChain: Chain | null = null;
let lastNonce: {nonce?: string; domain?: string} = {};
window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const method = (init?.method ?? "GET").toUpperCase();
  const res = await realFetch(input, init);
  if (url.includes("/web3/")) {
    const clone = res.clone();
    let responseBody: unknown;
    try {
      responseBody = await clone.json();
    } catch {
      responseBody = await clone.text().catch(() => undefined);
    }
    let requestBody: unknown;
    if (init?.body && typeof init.body === "string") {
      try {
        requestBody = JSON.parse(init.body);
      } catch {
        requestBody = init.body;
      }
    }
    window.__netCalls!.push({url, method, status: res.status, requestBody, responseBody, at: Date.now()});

    if (url.includes("/web3/nonce")) {
      const d = (responseBody as {data?: {nonce?: string; domain?: string}})?.data;
      lastNonce = {nonce: d?.nonce, domain: d?.domain};
    }
    if (url.includes("/web3/verify") && method === "POST") {
      const body = responseBody as {status?: string; msg?: string; data?: {data?: unknown}};
      const outcome: LoginOutcome = {
        chain: pendingChain ?? ("evm" as Chain),
        ok: body?.status === "ok",
        verifyStatus: res.status,
        msg: body?.msg,
        userData: body?.data?.data,
        nonce: lastNonce.nonce,
        domain: lastNonce.domain,
        at: Date.now(),
      };
      window.__lastVerify = outcome;
      try {
        sessionStorage.setItem(LOGIN_KEY, JSON.stringify(outcome));
      } catch {
        /* sessionStorage may be unavailable; window.__lastVerify still set */
      }
    }
  }
  return res;
};

const addrs = installMockWallets();
window.__mockAddrs = addrs;

const chains = getWalletChains(); // REAL production picker entries (one per ENABLED chain)

function readPersistedOutcome(): LoginOutcome | null {
  try {
    const raw = sessionStorage.getItem(LOGIN_KEY);
    return raw ? (JSON.parse(raw) as LoginOutcome) : null;
  } catch {
    return null;
  }
}

function App(): React.ReactElement {
  // Restore any prior outcome (e.g. after production reloaded the page).
  const restored = readPersistedOutcome();
  const [status, setStatus] = React.useState<string>(
    restored ? (restored.ok ? `LOGGED IN via ${restored.chain} — server verify ok` : `verify FAILED (${restored.chain})`) : "idle",
  );
  const [outcome, setOutcome] = React.useState<LoginOutcome | null>(restored);
  const [activeChain, setActiveChain] = React.useState<Chain | null>(null);

  const run = async (chain: Chain, onClick: (app: unknown, provider: unknown, method: string) => void): Promise<void> => {
    // Fresh attempt — clear any restored state.
    try {
      sessionStorage.removeItem(LOGIN_KEY);
    } catch {/* noop */}
    window.__lastVerify = undefined;
    setOutcome(null);
    setActiveChain(chain);
    setStatus(`connecting ${chain}...`);
    window.__settingEvents = [];
    pendingChain = chain;

    // Drive the REAL production onClick (authViaWallet). method="signup" so a
    // first-seen wallet provisions + logs in under app-hanzo. This may call
    // window.location.reload() on success — the persisted outcome survives it.
    onClick(APPLICATION, {type: chain}, "signup");

    // Poll for the verify outcome (set synchronously by the fetch wrapper) or an
    // error toast. If production reloads first, App re-mounts and restores the
    // outcome from sessionStorage, so this loop is just the no-reload path.
    for (let i = 0; i < 80; i++) {
      await new Promise((r) => setTimeout(r, 200));
      const v = window.__lastVerify;
      if (v) {
        setOutcome(v);
        setStatus(v.ok ? `LOGGED IN via ${chain} — server verify ok` : `verify FAILED (${chain}): ${v.msg}`);
        return;
      }
      const errEv = (window.__settingEvents ?? []).find((e) => e.kind === "showMessage" && e.arg1 === "error");
      if (errEv) {
        setStatus(`error (${chain}): ${errEv.arg2}`);
        return;
      }
    }
    setStatus(`timeout waiting for ${chain}`);
  };

  const state = status.startsWith("LOGGED IN") ? "logged-in" : status.includes("FAILED") || status.includes("error") ? "error" : "idle";

  return (
    <div style={{fontFamily: "system-ui, sans-serif", background: "#0a0a0a", color: "#fafafa", minHeight: "100vh", padding: 32}}>
      <h1 style={{fontSize: 22, marginBottom: 4}}>Hanzo IAM — Multi-chain Wallet Login (e2e harness)</h1>
      <p style={{color: "#a3a3a3", marginTop: 0, fontSize: 13}}>
        Real <code>getWalletChains()</code> + <code>authViaWallet()</code> from <code>WalletConnect.tsx</code>.
        Mock signer only. Server: <code>/v1/iam/web3/*</code>.
      </p>

      <div style={{margin: "8px 0 18px", fontSize: 12, color: "#737373"}}>
        CHAINS exported by WalletConnect: <span data-testid="all-chains">{CHAINS.join(", ")}</span>
        <br />
        EVM mock address: <span data-testid="evm-address">{addrs.evmAddress}</span>
        <br />
        Solana mock address: <span data-testid="sol-address">{addrs.solanaAddress}</span>
      </div>

      <div data-testid="chain-picker" style={{display: "grid", gridTemplateColumns: "repeat(2, minmax(260px, 320px))", gap: 12, maxWidth: 680}}>
        {chains.map(({chain, label, onClick}) => (
          <button
            key={chain}
            data-testid={`wallet-chain-${chain}`}
            onClick={() => void run(chain, onClick)}
            style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "14px 18px", background: activeChain === chain ? "#262626" : "#171717",
              color: "#fafafa", border: "1px solid #262626", borderRadius: 10,
              fontSize: 15, fontWeight: 600, cursor: "pointer", textAlign: "left",
            }}
          >
            <span>{label}</span>
            <span style={{color: "#737373", fontSize: 12, fontWeight: 400}}>{chain}</span>
          </button>
        ))}
      </div>

      <div
        id="status"
        data-testid="status"
        data-state={state}
        style={{
          marginTop: 24, padding: "14px 18px", borderRadius: 10, fontSize: 15, fontWeight: 600,
          background: state === "logged-in" ? "#052e16" : state === "error" ? "#450a0a" : "#171717",
          border: `1px solid ${state === "logged-in" ? "#16a34a" : state === "error" ? "#dc2626" : "#262626"}`,
          color: state === "logged-in" ? "#4ade80" : state === "error" ? "#f87171" : "#a3a3a3",
        }}
      >
        {status}
      </div>

      {outcome ? (
        <pre
          data-testid="outcome"
          style={{marginTop: 16, padding: 16, background: "#0f0f0f", border: "1px solid #262626", borderRadius: 10, fontSize: 12, color: "#a3a3a3", maxWidth: 680, overflowX: "auto"}}
        >
          {JSON.stringify(outcome, null, 2)}
        </pre>
      ) : null}
    </div>
  );
}

const root = createRoot(document.getElementById("root")!);
root.render(<App />);
window.__harnessReady = true;
