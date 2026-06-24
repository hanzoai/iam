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

// Multi-chain wallet login (HIP-0111) -- the ONE canonical path that talks to
// /v1/iam/web3/{nonce,verify}. This is the only wallet login path in the app;
// the legacy @web3-onboard / @metamask/eth-sig-util Web3Auth.tsx is deleted.
//
// Flow per chain (orthogonal -- connection is browser-side via @luxwallet/connect,
// verification is the server's; the server runs the SAME walletconnect.VerifyProof
// Go that the TS verifier mirrors):
//   1. connector.connect()           -> Account {chain,address,publicKey?}
//   2. GET  /v1/iam/web3/nonce        -> LoginChallenge {domain,uri,nonce,...}
//   3. connector.signLogin(acct, ch)  -> SignedProof {chain,scheme,...,signature}
//   4. POST /v1/iam/web3/verify       -> {status:"ok", data:<session/redirect>}
//
// HIP-0111: hit /v1/iam/web3/* directly. NEVER /api/, NEVER /oauth.
//
// Connectors come from @luxwallet/connect (MIT, zero GPL, no WalletConnect /
// projectId). EVM uses viem; Solana the injected provider; Bitcoin sats-connect;
// TON @tonconnect/sdk; XRP @crossmarkio/sdk. Per-chain peer libs are loaded
// lazily by the SDK connector only when that chain is used.

import i18next from "i18next";
import {goToLink, showMessage} from "../Setting";
import {
  getConnector,
  type Account,
  type Chain,
  type LoginChallenge,
  type SignedProof,
  type WalletConnector,
} from "@luxwallet/connect";

export type {Chain} from "@luxwallet/connect";

export const CHAINS: Chain[] = ["evm", "solana", "bitcoin", "ton", "xrp"];

const CHAIN_LABEL: Record<Chain, string> = {
  evm: "Ethereum / EVM",
  solana: "Solana",
  bitcoin: "Bitcoin",
  ton: "TON",
  xrp: "XRP Ledger",
};

// Backend verifiers live in IAM via connect/go v0.1.1 VerifyProof — all five are
// real (evm/solana + ton.go/xrp.go/bitcoin.go, 67 Go tests), dispatched in
// object/web3_auth.go. The full bridge login set is enabled out of the box.
const ENABLED_CHAINS: Chain[] = ["evm", "solana", "bitcoin", "ton", "xrp"];

// Map an admin-configured provider.type onto a chain. EVM is the default for the
// generic wallet button (MetaMask/Web3Onboard/Web3 all imply EVM); a provider
// MAY encode an explicit chain via provider.type or provider.metadata.
const TYPE_TO_CHAIN: Record<string, Chain> = {
  metamask: "evm",
  web3onboard: "evm",
  web3: "evm",
  evm: "evm",
  ethereum: "evm",
  solana: "solana",
  phantom: "solana",
  bitcoin: "bitcoin",
  ton: "ton",
  xrp: "xrp",
  xrpl: "xrp",
};

export function providerChain(provider): Chain {
  const raw = (provider?.type ?? "").toString().toLowerCase();
  if (TYPE_TO_CHAIN[raw]) {
    return TYPE_TO_CHAIN[raw];
  }
  // provider.metadata may carry {"chain":"solana"}; honor it if present.
  try {
    if (provider?.metadata) {
      const meta = JSON.parse(provider.metadata);
      const c = (meta?.chain ?? "").toString().toLowerCase();
      if (TYPE_TO_CHAIN[c]) {
        return TYPE_TO_CHAIN[c];
      }
    }
  } catch (_) {
    /* metadata is free-form admin text; ignore parse errors */
  }
  return "evm";
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
 * Mirrors the success handling of the password/OAuth path: HandleLoggedIn on the
 * server returns either a redirect target or a logged-in payload the SPA
 * consumes, exactly like an OAuth callback.
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
 * authViaProvider is the entrypoint ProviderButton calls for any Web3 provider
 * button. It maps the admin-configured provider onto a chain, then runs the
 * native flow. One way: every wallet button funnels through here.
 */
export function authViaProvider(application, provider, method: string) {
  return authViaWallet(application, provider, method, providerChain(provider));
}

/**
 * The multi-chain picker the login page can render. Returns one entry per ENABLED
 * chain with metadata + an onClick. Only server-verified chains are returned so
 * the UI never shows a dead button.
 */
export function getWalletChains() {
  return CHAINS.filter((c) => ENABLED_CHAINS.includes(c)).map((c) => ({
    chain: c,
    label: CHAIN_LABEL[c],
    onClick: (application, provider, method) => authViaWallet(application, provider, method, c),
  }));
}

/**
 * isWalletLoginReady reports whether at least one chain is enabled, so callers
 * can decide whether to render the picker at all.
 */
export function isWalletLoginReady(): boolean {
  return getWalletChains().length > 0;
}
