// Login Showcase — brand-neutral right panel for split-screen login
// Shows org name + tagline. No carousel, no testimonials, no vendor branding.
// Per-org content is display name + one-liner only.

import React from "react";

interface LoginShowcaseProps {
  application?: {
    organization?: string;
    displayName?: string;
  };
}

const orgDisplay: Record<string, { name: string; tagline: string }> = {
  liquidity: {name: "", tagline: "Digital Securities Platform"},
  hanzo: {name: "Hanzo", tagline: "AI Infrastructure"},
  lux: {name: "Lux", tagline: "Blockchain Infrastructure"},
  zoo: {name: "Zoo", tagline: "Open AI Research"},
  pars: {name: "Pars", tagline: "Digital Identity"},
  : {name: "", tagline: "Biometric Security"},
};

export default function LoginShowcase({application}: LoginShowcaseProps) {
  const orgName = application?.organization || "";
  const org = orgDisplay[orgName];
  const displayName = org?.name || application?.displayName || "Sign In";
  const tagline = org?.tagline || "";

  return (
    <div className="hanzo-showcase">
      <div className="showcase-content">
        <div className="showcase-brand">
          <div className="showcase-brand-name">{displayName}</div>
          {tagline && <div className="showcase-brand-tagline">{tagline}</div>}
        </div>
      </div>
    </div>
  );
}
