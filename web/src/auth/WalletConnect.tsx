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

// Multi-chain wallet login (HIP-0111) -- the canonical path that talks to
// /v1/iam/web3/{nonce,verify}. Added ALONGSIDE the legacy Web3Auth.tsx
// (@web3-onboard, EVM-only, signature-UNVERIFIED) path; that path + the dead
// idp/{metamask,web3onboard}.go are removed in a follow-up once this is live.
//
// Flow per chain (orthogonal -- connection is browser-side, verification is the
// server's; the server runs the SAME walletconnect.VerifyProof Go + TS share):
//   1. connector.connect()           -> Account {chain,address,publicKey?}
//   2. GET  /v1/iam/web3/nonce        -> LoginChallenge {domain,uri,nonce,...}
//   3. connector.signLogin(acct, ch)  -> SignedProof {chain,scheme,...,signature}
//   4. POST /v1/iam/web3/verify       -> {status:"ok", data:<session/redirect>}
//
// HIP-0111: hit /v1/iam/web3/* directly. NEVER /api/, NEVER /oauth.
//
// ----------------------------------------------------------------------------
// INTEGRATION SEAM (TODO): the browser connectors live in
// @luxwallet/connect/connectors -- being built in parallel (the Go/TS verifiers
// are done; the connectors are the next SDK milestone). Until that package is a
// dependency, CONNECTORS is empty and a wallet button throws a clear
// "connector not wired yet" error rather than silently no-op'ing. When the SDK
// ships, replace registerConnectors() below with the real imports; nothing else
// here changes -- the server flow (nonce/verify) is complete and tested.
//
// Wiring (one line once @luxwallet/connect is added to web/package.json):
//   import {EvmConnector, SolanaConnector, ...} from "@luxwallet/connect/connectors";
//   registerConnectors({evm: new EvmConnector(), solana: new SolanaConnector(), ...});
// ----------------------------------------------------------------------------

import i18next from "i18next";
import {goToLink, showMessage} from "../Setting";

// --- Types (mirror @luxwallet/connect; defined locally so this compiles before
// the SDK is a dependency). Keep in lockstep with the SDK's TS types. ---------

export type Chain = "evm" | "solana" | "bitcoin" | "ton" | "xrp";

export const CHAINS: Chain[] = ["evm", "solana", "bitcoin", "ton", "xrp"];

export interface Account {
  chain: Chain;
  address: string;
  publicKey?: string;
  walletId?: string;
}

export interface LoginChallenge {
  domain: string;
  uri: string;
  statement?: string;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  version?: string;
  resources?: string[];
}

export interface SignedProof {
  chain: Chain;
  scheme: string;
  address: string;
  publicKey?: string;
  message: string;
  signature: string;
  extra?: Record<string, unknown>;
}

export interface WalletConnector {
  connect(): Promise<Account>;
  signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof>;
  disconnect(): Promise<void>;
}

const CHAIN_LABEL: Record<Chain, string> = {
  evm: "Ethereum / EVM",
  solana: "Solana",
  bitcoin: "Bitcoin",
  ton: "TON",
  xrp: "XRP Ledger",
};

// Backend verifiers that are live today. Bitcoin/TON/XRP Go ports are stubs that
// fail closed, so the picker is gated to the verified set (PLAN.md risk 5).
// Widen this only when BOTH the chain's TS and Go verifiers are green AND its
// connector is registered below.
const ENABLED_CHAINS: Chain[] = ["evm", "solana"];

// --- Connector registry (the integration seam). Empty until the SDK ships. ---

const CONNECTORS: Partial<Record<Chain, WalletConnector>> = {};

/**
 * registerConnectors wires the @luxwallet/connect browser connectors. Call once
 * at app init when the SDK is available. See the INTEGRATION SEAM note above.
 */
export function registerConnectors(connectors: Partial<Record<Chain, WalletConnector>>) {
  Object.assign(CONNECTORS, connectors);
}

function getConnector(chain: Chain): WalletConnector {
  const c = CONNECTORS[chain];
  if (!c) {
    // Loud, actionable failure -- never a silent no-op.
    throw new Error(
      `wallet connector for "${chain}" is not wired yet ` +
        "(@luxwallet/connect/connectors pending; call registerConnectors())",
    );
  }
  return c;
}

// --- Server flow (complete + matches the Go handlers) ------------------------

function apiBase() {
  // Same-origin canonical IAM API root. The brand host (hanzo.id) proxies
  // /v1/iam/* to iam.hanzo.ai; never construct an /api/ path.
  return "/v1/iam";
}

async function fetchNonce(chain: Chain, address: string): Promise<LoginChallenge> {
  const url = `${apiBase()}/web3/nonce?chain=${encodeURIComponent(chain)}&address=${encodeURIComponent(address)}`;
  const res = await fetch(url, {method: "GET", credentials: "include"});
  const body = await res.json();
  if (body.status !== "ok") {
    throw new Error(body.msg || "failed to obtain login nonce");
  }
  // body.data is the Web3NonceResponse, shaped as a LoginChallenge.
  return body.data as LoginChallenge;
}

async function postVerify(application, organization, method: string, proof: SignedProof) {
  const res = await fetch(`${apiBase()}/web3/verify`, {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      organization,
      application,
      method,
      chain: proof.chain,
      scheme: proof.scheme,
      address: proof.address,
      publicKey: proof.publicKey,
      message: proof.message,
      signature: proof.signature,
      extra: proof.extra,
    }),
  });
  return res.json();
}

/**
 * Drive one chain end-to-end: connect -> nonce -> sign -> verify -> redirect.
 * Used by the picker; also callable directly for a single-chain button. Mirrors
 * the success handling of the password/OAuth path (Web3Auth.tsx).
 */
export async function authViaWallet(application, provider, method: string, chain: Chain) {
  let connector: WalletConnector;
  try {
    connector = getConnector(chain);
  } catch (err) {
    showMessage("error", `${i18next.t("login:Wallet sign-in failed")}: ${err?.message ?? err}`);
    return;
  }

  try {
    const account: Account = await connector.connect();

    const challenge: LoginChallenge = await fetchNonce(chain, account.address);

    // The connector renders the challenge to the canonical CAIP-122 message
    // (TON uses its ton_proof envelope internally) and asks the wallet to sign.
    const proof: SignedProof = await connector.signLogin(account, challenge);

    const result = await postVerify(
      application?.name ?? provider?.application,
      application?.organization ?? provider?.organization,
      method || "signup",
      proof,
    );

    if (result.status === "ok") {
      // Mirror the password/OAuth success path: HandleLoggedIn returns either a
      // redirect target or a logged-in payload the SPA consumes.
      if (typeof result.data === "string" && result.data.startsWith("http")) {
        goToLink(result.data);
      } else if (result.data?.redirectUrl) {
        goToLink(result.data.redirectUrl);
      } else {
        window.location.reload();
      }
    } else {
      showMessage("error", `${i18next.t("login:Wallet sign-in failed")}: ${result.msg}`);
    }
  } catch (err) {
    showMessage("error", `${i18next.t("login:Wallet sign-in failed")}: ${err?.message ?? err}`);
  } finally {
    try {
      await connector.disconnect();
    } catch (_) {
      /* best-effort */
    }
  }
}

/**
 * The multi-chain picker the login page renders. Returns one entry per ENABLED
 * chain with metadata + an onClick, so SelfLoginButton / LoginPage can render
 * buttons. Only chains that are BOTH enabled (server-verified) AND have a
 * registered connector are returned, so the UI never shows a dead button.
 */
export function getWalletChains() {
  return CHAINS.filter((c) => ENABLED_CHAINS.includes(c) && Boolean(CONNECTORS[c])).map((c) => ({
    chain: c,
    label: CHAIN_LABEL[c],
    onClick: (application, provider, method) => authViaWallet(application, provider, method, c),
  }));
}

/**
 * isWalletLoginReady reports whether at least one chain is enabled AND wired, so
 * callers can decide whether to render the picker at all (avoids an empty group
 * while the connectors are still being built in parallel).
 */
export function isWalletLoginReady(): boolean {
  return getWalletChains().length > 0;
}
