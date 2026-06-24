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

// ChainIcon — the 7 login-chain logo marks for the multi-chain wallet picker,
// rendered as plain web <svg> (IAM web is plain React + Vite, NOT
// react-native-web, so it can't pull in @luxwallet/ui's react-native-svg
// without dragging the whole RN/tamagui stack in). The geometry MIRRORS the
// ONE source of truth — @luxwallet/ui `src/chain-icon-paths.ts` — verbatim, so
// both surfaces draw byte-identical marks. Keep the two in sync.
//
// Monochrome: fill/stroke default to currentColor, so each mark inherits the
// brand text color (lux.id / hanzo.id monochrome theme) while keeping its own
// silhouette. MIT, our own simplified renderings — no trademarked asset files.

import React from "react";
import {type Chain} from "@luxwallet/connect";

interface IconPath {
  d: string;
  fill?: "solid" | "none";
  fillRule?: "evenodd" | "nonzero";
  strokeWidth?: number;
}

interface IconGeometry {
  viewBox: string;
  paths: IconPath[];
}

// Mirror of @luxwallet/ui CHAIN_ICON_PATHS (keep in sync).
const CHAIN_ICON_PATHS: Record<Chain, IconGeometry> = {
  // Ethereum / EVM — the canonical diamond: upper + lower faceted halves.
  evm: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M12 2 L12 9.7 L18.5 12.6 Z", fill: "solid"},
      {d: "M12 2 L5.5 12.6 L12 9.7 Z", fill: "solid"},
      {d: "M12 16.1 L12 22 L18.5 13.8 Z", fill: "solid"},
      {d: "M12 22 L12 16.1 L5.5 13.8 Z", fill: "solid"},
      {d: "M12 14.9 L18.5 12.6 L12 9.7 Z", fill: "solid", fillRule: "evenodd"},
      {d: "M5.5 12.6 L12 14.9 L12 9.7 Z", fill: "solid", fillRule: "evenodd"},
    ],
  },
  // Solana — three left-slanted bars, the signature wordmark.
  solana: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M6.5 5.2 H19 a0.6 0.6 0 0 1 0.42 1.02 l-1.9 1.9 a1.2 1.2 0 0 1-0.85 0.35 H4.6 a0.6 0.6 0 0 1-0.42-1.02 l1.9-1.9 a1.2 1.2 0 0 1 0.85-0.35 Z", fill: "solid"},
      {d: "M6.5 10.5 H19 a0.6 0.6 0 0 1 0.42 1.02 l-1.9 1.9 a1.2 1.2 0 0 1-0.85 0.35 H4.6 a0.6 0.6 0 0 1-0.42-1.02 l1.9-1.9 a1.2 1.2 0 0 1 0.85-0.35 Z", fill: "solid"},
      {d: "M6.5 15.8 H19 a0.6 0.6 0 0 1 0.42 1.02 l-1.9 1.9 a1.2 1.2 0 0 1-0.85 0.35 H4.6 a0.6 0.6 0 0 1-0.42-1.02 l1.9-1.9 a1.2 1.2 0 0 1 0.85-0.35 Z", fill: "solid"},
    ],
  },
  // Bitcoin — roundel with the double-barred B (₿).
  bitcoin: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M12 2 a10 10 0 1 0 0 20 a10 10 0 0 0 0-20 Z M12 4 a8 8 0 1 1 0 16 a8 8 0 0 1 0-16 Z", fill: "solid", fillRule: "evenodd"},
      {d: "M10.2 6.6 v1.4 M13.0 6.6 v1.4 M10.2 16 v1.4 M13.0 16 v1.4", fill: "none", strokeWidth: 1.3},
      {d: "M8.6 8 H13.4 a2.1 2.1 0 0 1 0 4.2 H8.6 Z M8.6 12 H13.8 a2.1 2.1 0 0 1 0 4.2 H8.6 Z M8.6 8 V16.2 M8.6 8 H7.4 M8.6 16.2 H7.4", fill: "none", strokeWidth: 1.3},
    ],
  },
  // TON — faceted gem inside a roundel.
  ton: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M12 2 a10 10 0 1 0 0 20 a10 10 0 0 0 0-20 Z M12 4 a8 8 0 1 1 0 16 a8 8 0 0 1 0-16 Z", fill: "solid", fillRule: "evenodd"},
      {d: "M7.5 8.2 H16.5 L12 17.2 Z M12 8.2 V17.2", fill: "none", strokeWidth: 1.4},
    ],
  },
  // XRP — the interlocked X (Ripple mark): four strokes meeting at center.
  xrp: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M4 5 h3.2 a2.2 2.2 0 0 1 1.7 0.82 L12 9.7 l3.1-3.88 A2.2 2.2 0 0 1 16.8 5 H20", fill: "none", strokeWidth: 1.9},
      {d: "M4 19 h3.2 a2.2 2.2 0 0 0 1.7-0.82 L12 14.3 l3.1 3.88 A2.2 2.2 0 0 0 16.8 19 H20", fill: "none", strokeWidth: 1.9},
    ],
  },
  // Polkadot — the dot ring: six satellites around a hub.
  polkadot: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M12 3.2 a2 2.6 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M12 18.2 a2 2.6 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M5.5 6.9 a2 2.6 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M18.5 6.9 a2 2.6 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M5.5 14.5 a2 2.6 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M18.5 14.5 a2 2.6 0 1 0 0.001 0 Z", fill: "solid"},
    ],
  },
  // Cardano — ADA atom: central node + ring of orbiting satellites.
  cardano: {
    viewBox: "0 0 24 24",
    paths: [
      {d: "M12 9.4 a2.6 2.6 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M12 2.6 a1.5 1.5 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M12 19.9 a1.5 1.5 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M4.1 7.1 a1.5 1.5 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M19.9 7.1 a1.5 1.5 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M4.1 16.4 a1.5 1.5 0 1 0 0.001 0 Z", fill: "solid"},
      {d: "M19.9 16.4 a1.5 1.5 0 1 0 0.001 0 Z", fill: "solid"},
    ],
  },
};

export interface ChainIconProps {
  chain: Chain;
  /** Square size in px (width = height). Default 20. */
  size?: number;
  /** Fill/stroke color. Default "currentColor" (inherits brand text color). */
  color?: string;
}

/**
 * ChainIcon renders one chain's logo mark. Used by the multi-chain wallet
 * picker on the lux.id / hanzo.id login page (see WalletConnect.getWalletChains).
 */
export function ChainIcon({chain, size = 20, color = "currentColor"}: ChainIconProps): React.ReactElement {
  const geom = CHAIN_ICON_PATHS[chain];
  return (
    <svg
      width={size}
      height={size}
      viewBox={geom.viewBox}
      role="img"
      aria-label={chain}
      style={{display: "inline-block", flex: "0 0 auto"}}
    >
      {geom.paths.map((p, i) =>
        p.fill === "none" ? (
          <path
            key={i}
            d={p.d}
            fill="none"
            stroke={color}
            strokeWidth={p.strokeWidth ?? 1.5}
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ) : (
          <path key={i} d={p.d} fill={color} fillRule={p.fillRule ?? "nonzero"} />
        ),
      )}
    </svg>
  );
}
