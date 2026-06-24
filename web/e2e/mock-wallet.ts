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

// In-page MOCK wallet providers that produce GENUINELY VALID signatures.
//
// This is the only thing mocked in the wallet-login e2e: the signer. Everything
// else is real — the @luxwallet/connect connectors discover and drive these
// providers exactly as they would MetaMask / Phantom, and the IAM server runs
// its real walletconnect.VerifyProof over the resulting proof.
//
//   EVM    : window.ethereum, EIP-6963 announce + EIP-1193 request handling.
//            personal_sign signs with a fixed secp256k1 test key via viem, so
//            the server recovers the same address it sees in eth_requestAccounts.
//   Solana : window.solana, ed25519 signMessage via @noble/curves; the base58
//            public key IS the address the server decodes as the verifying key.
//
// No extension, no funds, no network — just real crypto behind the injected
// EIP-1193 / Wallet-Standard surface the production connectors expect.

import {privateKeyToAccount} from "viem/accounts";
import {ed25519} from "@noble/curves/ed25519";
import bs58 from "bs58";

// --- Fixed test keys (NOT secrets; throwaway, only ever sign login challenges) ---

// secp256k1 private key for the EVM mock. viem derives the checksummed address.
const EVM_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;

// ed25519 seed (32 bytes) for the Solana mock.
const SOLANA_SEED = new Uint8Array([
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
]);

// --- helpers ---------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// personal_sign delivers the message either as a UTF-8 string or as 0x-hex of
// the UTF-8 bytes (viem sends hex). Normalize back to the original string so we
// sign exactly the bytes the wallet was asked to sign.
function decodePersonalSignData(data: string): string {
  if (typeof data === "string" && data.startsWith("0x")) {
    try {
      return new TextDecoder().decode(hexToBytes(data));
    } catch {
      return data;
    }
  }
  return data;
}

export interface MockWalletHandles {
  evmAddress: string;
  solanaAddress: string;
}

// installMockWallets injects window.ethereum (EIP-6963 + EIP-1193) and
// window.solana, returning the addresses the connectors will report. Idempotent.
export function installMockWallets(): MockWalletHandles {
  const account = privateKeyToAccount(EVM_PRIVATE_KEY);
  const evmAddress = account.address;

  const solPub = ed25519.getPublicKey(SOLANA_SEED);
  const solanaAddress = bs58.encode(solPub);

  // ---------- EVM: EIP-1193 provider ----------
  const ethereum = {
    isMetaMask: true,
    _isHanzoMockWallet: true,
    async request({method, params}: {method: string; params?: unknown[]}): Promise<unknown> {
      switch (method) {
        case "eth_requestAccounts":
        case "eth_accounts":
          return [evmAddress];
        case "eth_chainId":
          return "0x1"; // mainnet; signing does not depend on it
        case "personal_sign": {
          // viem custom transport calls personal_sign with [dataHex, address].
          const raw = (params?.[0] as string) ?? "";
          const message = decodePersonalSignData(raw);
          // Real EIP-191 personal_sign over the message via the test key.
          return account.signMessage({message});
        }
        case "wallet_requestPermissions":
          return [{parentCapability: "eth_accounts"}];
        default:
          throw Object.assign(new Error(`mock-evm: unsupported method ${method}`), {code: 4200});
      }
    },
    on() {/* no-op event surface */},
    removeListener() {/* no-op */},
  };

  (window as unknown as {ethereum?: unknown}).ethereum = ethereum;

  // EIP-6963 multi-injection: answer eip6963:requestProvider with an announce.
  const info = {
    uuid: "11111111-1111-1111-1111-111111111111",
    name: "Hanzo Mock Wallet",
    icon: "data:image/svg+xml;base64,PHN2Zy8+",
    rdns: "ai.hanzo.mockwallet",
  };
  const announce = (): void => {
    window.dispatchEvent(
      new CustomEvent("eip6963:announceProvider", {
        detail: Object.freeze({info, provider: ethereum}),
      }),
    );
  };
  window.addEventListener("eip6963:requestProvider", announce as EventListener);
  announce();

  // ---------- Solana: injected Wallet-Standard-ish provider ----------
  const publicKeyObj = {
    toBytes: () => solPub,
    toString: () => solanaAddress,
  };
  const solana = {
    isPhantom: true,
    _isHanzoMockWallet: true,
    publicKey: publicKeyObj,
    async connect() {
      return {publicKey: publicKeyObj};
    },
    async disconnect() {/* no-op */},
    async signMessage(message: Uint8Array): Promise<{signature: Uint8Array}> {
      // Real ed25519 signature over the raw UTF-8 message bytes.
      const signature = ed25519.sign(message, SOLANA_SEED);
      return {signature};
    },
  };
  (window as unknown as {solana?: unknown}).solana = solana;

  return {evmAddress, solanaAddress};
}

// Expose on window so the Playwright spec (and the harness) can install + read
// the addresses without bundling crypto into the test runner.
(window as unknown as {__installMockWallets?: typeof installMockWallets}).__installMockWallets =
  installMockWallets;
