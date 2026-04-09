// Login Showcase — brand-neutral right panel for split-screen login
// Reads display name + description from the application object.
// No hardcoded org content — all branding comes from IAM database config.

import React from "react";

interface LoginShowcaseProps {
  application?: {
    organization?: string;
    displayName?: string;
    description?: string;
  };
}

export default function LoginShowcase({application}: LoginShowcaseProps) {
  const displayName = application?.displayName || "Sign In";
  const tagline = application?.description || "";

  return (
    <div className="brand-showcase">
      <div className="showcase-content">
        <div className="showcase-brand">
          <div className="showcase-brand-name">{displayName}</div>
          {tagline && <div className="showcase-brand-tagline">{tagline}</div>}
        </div>
      </div>
    </div>
  );
}
