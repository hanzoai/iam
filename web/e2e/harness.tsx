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

// E2E harness that exercises the REAL production wallet-login code, rendered in
// a faithful, BRAND-THEMED login page (lux.id vs iam.hanzo.ai).
//
// It imports getWalletChains() + authViaWallet() straight from
// ../src/auth/WalletConnect.tsx (only ../Setting is aliased to a 2-symbol shim
// so the whole admin app doesn't get bundled). The 7-chain picker it renders is
// the production CHAINS x ENABLED_CHAINS list, and each entry's `icon` is the
// production ChainIcon SVG (same marks the login page draws). Each button runs
// the production connect -> /v1/iam/web3/nonce -> connector.signLogin ->
// /v1/iam/web3/verify flow against the REAL IAM server proxied at /v1/iam.
//
// Brand theming: `?brand=lux|hanzo` switches the logo, name, and accent so the
// SAME login flow is captured under BOTH brand themes — exactly how the real
// lux.id / iam.hanzo.ai login pages differ (logo + colors by host/brand). The
// wallet picker sits alongside social (Google/GitHub) + email/password, so the
// screenshots show how wallet-connect fits the login page in context.
//
// The only mock is the wallet signer (e2e/mock-wallet.ts): real secp256k1 /
// ed25519 keys behind the EIP-1193 / Wallet-Standard surface the connectors
// expect. So the server's walletconnect.VerifyProof verifies a genuine
// signature — true end-to-end, just without a funded extension.
//
// Reload handling: production authViaWallet calls window.location.reload() on a
// successful non-redirect login. location.reload is non-configurable in
// Chromium, so we DON'T fight it: the wrapped fetch persists the /verify
// outcome to sessionStorage synchronously the instant it returns (before reload
// runs), and on (re)mount the harness restores that state — so the "logged in"
// screenshot is clean whether or not the page reloaded. The reload IS the
// genuine production logged-in navigation; the evidence survives.

import React from "react";
import {createRoot} from "react-dom/client";

import {installMockWallets} from "./mock-wallet";
// REAL production code under test:
import {getWalletChains, CHAINS, type Chain} from "../src/auth/WalletConnect";

// The application/organization the harness verifies against (seeded by the e2e
// backend init data: app-hanzo, org hanzo, enableSignUp=true).
const APPLICATION = {name: "app-hanzo", organization: "hanzo"} as const;

const LOGIN_KEY = "__hanzo_e2e_login"; // sessionStorage key (survives reload)

// --- Brand theming (mirrors how the real login differs by host/brand) --------

type BrandKey = "lux" | "hanzo";

interface BrandTheme {
  key: BrandKey;
  /** The IAM host the brand serves under. */
  host: string;
  /** Product name shown in the header. */
  name: string;
  /** Accent color for the primary CTA + active chain. */
  accent: string;
  accentText: string;
  /** Inline logo mark (monochrome, white on the dark login surface). */
  logo: React.ReactElement;
}

// Hanzo "H" mark (from web/public/img/hanzo-logo-dark.svg) and the Lux triangle
// (from lux build/public/lux-logo-white.svg) — the canonical brand marks.
const HANZO_LOGO = (
  <svg width={34} height={34} viewBox="0 0 24 24" aria-label="Hanzo">
    <path d="M3 2 H7 V10 H17 V2 H21 V22 H17 V14 H7 V22 H3 Z" fill="#ffffff" />
  </svg>
);
const LUX_LOGO = (
  <svg width={34} height={34} viewBox="0 0 100 100" aria-label="Lux">
    <path d="M50 85 L15 25 L85 25 Z" fill="#ffffff" />
  </svg>
);

const BRANDS: Record<BrandKey, BrandTheme> = {
  hanzo: {
    key: "hanzo",
    host: "iam.hanzo.ai",
    name: "Hanzo",
    accent: "#ffffff",
    accentText: "#000000",
    logo: HANZO_LOGO,
  },
  lux: {
    key: "lux",
    host: "lux.id",
    name: "Lux",
    accent: "#ffffff",
    accentText: "#000000",
    logo: LUX_LOGO,
  },
};

function currentBrand(): BrandTheme {
  const p = new URLSearchParams(window.location.search).get("brand");
  return p === "lux" ? BRANDS.lux : BRANDS.hanzo;
}

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

const chains = getWalletChains(); // REAL production picker entries (one per ENABLED chain), each with an `icon`

function readPersistedOutcome(): LoginOutcome | null {
  try {
    const raw = sessionStorage.getItem(LOGIN_KEY);
    return raw ? (JSON.parse(raw) as LoginOutcome) : null;
  } catch {
    return null;
  }
}

// --- Presentational bits (login-page chrome around the REAL picker) -----------

function SocialButton({label, mark}: {label: string; mark: React.ReactNode}): React.ReactElement {
  return (
    <button
      type="button"
      style={{
        display: "flex", alignItems: "center", gap: 10, width: "100%",
        padding: "10px 14px", background: "#171717", color: "#e5e5e5",
        border: "1px solid #262626", borderRadius: 8, fontSize: 14,
        fontWeight: 500, cursor: "pointer",
      }}
    >
      <span style={{width: 20, height: 20, display: "inline-flex", alignItems: "center", justifyContent: "center"}}>{mark}</span>
      <span>{label}</span>
    </button>
  );
}

const GoogleMark = (
  <svg width={18} height={18} viewBox="0 0 24 24"><path fill="#fff" d="M12 11v3.2h5.2A4.5 4.5 0 0 1 7.5 12a4.5 4.5 0 0 1 7.6-3.3l2.3-2.3A8 8 0 1 0 20 12c0-.4 0-.7-.1-1z" /></svg>
);
const GithubMark = (
  <svg width={18} height={18} viewBox="0 0 24 24"><path fill="#fff" d="M12 2a10 10 0 0 0-3.2 19.5c.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.3-3.4-1.3-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.6-1.4-2.2-.300000000000001-4.6-1.1-4.6-5a4 4 0 0 1 1-2.7c-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.4.2 2.4.1 2.7a4 4 0 0 1 1 2.7c0 3.9-2.4 4.7-4.6 5 .4.3.7.9.7 1.8v2.6c0 .3.2.6.7.5A10 10 0 0 0 12 2z" /></svg>
);

function App(): React.ReactElement {
  const brand = currentBrand();
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
  const loggedIn = state === "logged-in";

  return (
    <div
      data-brand={brand.key}
      style={{
        fontFamily: "system-ui, -apple-system, sans-serif", background: "#0a0a0a",
        color: "#fafafa", minHeight: "100vh", display: "flex",
        alignItems: "flex-start", justifyContent: "center", padding: "48px 16px",
      }}
    >
      <div
        data-testid="login-card"
        style={{
          width: "100%", maxWidth: 420, background: "#0d0d0d",
          border: "1px solid #1f1f1f", borderRadius: 16, padding: 32,
          boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
        }}
      >
        {/* Brand header — logo + name, differs lux.id vs iam.hanzo.ai */}
        <div style={{display: "flex", flexDirection: "column", alignItems: "center", gap: 10, marginBottom: 8}}>
          <div data-testid="brand-logo">{brand.logo}</div>
          <div style={{fontSize: 20, fontWeight: 700, letterSpacing: -0.3}} data-testid="brand-name">
            Sign in to {brand.name}
          </div>
          <div style={{fontSize: 12, color: "#737373"}} data-testid="brand-host">{brand.host}</div>
        </div>

        {loggedIn ? (
          <div
            data-testid="success-panel"
            style={{
              marginTop: 24, padding: "20px 18px", borderRadius: 12, textAlign: "center",
              background: "#052e16", border: "1px solid #16a34a", color: "#4ade80",
            }}
          >
            <div style={{fontSize: 28, marginBottom: 6}}>✓</div>
            <div style={{fontSize: 16, fontWeight: 700}}>Signed in to {brand.name}</div>
            <div style={{fontSize: 13, color: "#86efac", marginTop: 4}}>
              {outcome?.chain?.toUpperCase()} wallet verified — welcome.
            </div>
            <pre
              data-testid="outcome"
              style={{marginTop: 14, padding: 12, background: "#04220f", border: "1px solid #14532d", borderRadius: 8, fontSize: 11, color: "#bbf7d0", textAlign: "left", overflowX: "auto"}}
            >
              {JSON.stringify(outcome, null, 2)}
            </pre>
          </div>
        ) : null}

        {!loggedIn ? (
          <>
            {/* Social — the unified-auth options at the top of the login page */}
            <div style={{display: "flex", flexDirection: "column", gap: 8, marginTop: 20}}>
              <SocialButton label="Continue with Google" mark={GoogleMark} />
              <SocialButton label="Continue with GitHub" mark={GithubMark} />
            </div>

            {/* Email + password */}
            <div style={{display: "flex", alignItems: "center", gap: 10, margin: "18px 0"}}>
              <div style={{flex: 1, height: 1, background: "#1f1f1f"}} />
              <div style={{fontSize: 11, color: "#525252"}}>OR</div>
              <div style={{flex: 1, height: 1, background: "#1f1f1f"}} />
            </div>
            <input
              placeholder="Email"
              style={{width: "100%", boxSizing: "border-box", padding: "10px 12px", background: "#141414", border: "1px solid #262626", borderRadius: 8, color: "#e5e5e5", fontSize: 14, marginBottom: 8}}
            />
            <input
              placeholder="Password"
              type="password"
              style={{width: "100%", boxSizing: "border-box", padding: "10px 12px", background: "#141414", border: "1px solid #262626", borderRadius: 8, color: "#e5e5e5", fontSize: 14, marginBottom: 8}}
            />
            <button
              type="button"
              style={{width: "100%", padding: "11px 12px", background: brand.accent, color: brand.accentText, border: "none", borderRadius: 8, fontSize: 14, fontWeight: 700, cursor: "pointer"}}
            >
              Sign in
            </button>

            {/* Wallet — the multi-chain connect option, in context */}
            <div style={{display: "flex", alignItems: "center", gap: 10, margin: "20px 0 14px"}}>
              <div style={{flex: 1, height: 1, background: "#1f1f1f"}} />
              <div style={{fontSize: 11, color: "#525252"}}>OR CONNECT A WALLET</div>
              <div style={{flex: 1, height: 1, background: "#1f1f1f"}} />
            </div>

            <div
              data-testid="chain-picker"
              style={{display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8}}
            >
              {chains.map(({chain, label, icon, onClick}) => {
                const active = activeChain === chain;
                return (
                  <button
                    key={chain}
                    data-testid={`wallet-chain-${chain}`}
                    onClick={() => void run(chain, onClick)}
                    style={{
                      display: "flex", alignItems: "center", gap: 9,
                      padding: "11px 12px", background: active ? "#1f1f1f" : "#141414",
                      color: "#fafafa", border: `1px solid ${active ? brand.accent : "#262626"}`,
                      borderRadius: 9, fontSize: 13, fontWeight: 600, cursor: "pointer",
                      textAlign: "left",
                    }}
                  >
                    <span style={{display: "inline-flex", width: 20, height: 20, alignItems: "center", justifyContent: "center", color: "#fafafa"}}>
                      {icon}
                    </span>
                    <span style={{whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"}}>{label}</span>
                  </button>
                );
              })}
            </div>
          </>
        ) : null}

        {/* Status — ALWAYS present (the spec waits on data-state to flip to
            logged-in even after the success panel replaces the form above). */}
        <div
          id="status"
          data-testid="status"
          data-state={state}
          style={{
            marginTop: 16, padding: "10px 12px", borderRadius: 8, fontSize: 13, fontWeight: 600,
            background: state === "logged-in" ? "#052e16" : state === "error" ? "#450a0a" : "#141414",
            border: `1px solid ${state === "logged-in" ? "#16a34a" : state === "error" ? "#dc2626" : "#1f1f1f"}`,
            color: state === "logged-in" ? "#4ade80" : state === "error" ? "#f87171" : "#737373",
            display: loggedIn ? "none" : "block",
          }}
        >
          {status === "idle" ? "Pick a chain to sign in with your wallet" : status}
        </div>

        {/* Debug strip the spec reads (mock addresses + the full CHAINS list). */}
        <div style={{marginTop: 14, fontSize: 10, color: "#3f3f3f", wordBreak: "break-all"}}>
          <span data-testid="all-chains" style={{display: "none"}}>{CHAINS.join(", ")}</span>
          <span data-testid="evm-address" style={{display: "none"}}>{addrs.evmAddress}</span>
          <span data-testid="sol-address" style={{display: "none"}}>{addrs.solanaAddress}</span>
          7 chains: {CHAINS.join(" · ")}
        </div>
      </div>
    </div>
  );
}

const root = createRoot(document.getElementById("root")!);
root.render(<App />);
window.__harnessReady = true;
