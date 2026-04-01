// Hanzo AI Showcase Component for Login Page
// Displays animated product features + real testimonials on the right side of split-screen login
// Content is per-organization — each org can have its own showcase slides and quotes

import React, {useEffect, useState, useCallback} from "react";

// ── Type definitions ─────────────────────────────────────────────────────

interface Slide {
  icon: string;
  title: string;
  desc: string;
}

interface Testimonial {
  name: string;
  role: string;
  text: string;
}

interface OrgContent {
  badge: string;
  title: string;
  subtitle: string;
  slides: Slide[];
  testimonials: Testimonial[];
}

interface HanzoShowcaseProps {
  application?: {
    organization?: string;
  };
}

interface SlideIconProps {
  name: string;
}

// ── Per-org showcase content ──────────────────────────────────────────────
// Each org gets its own set of product slides and testimonials.
// Falls back to "hanzo" content for orgs without custom content.

const orgContent: Record<string, OrgContent> = {
  hanzo: {
    badge: "AI Infrastructure",
    title: "Build with Hanzo",
    subtitle: "Enterprise AI platform powering the next generation of intelligent applications",
    slides: [
      {icon: "chat", title: "Hanzo Chat", desc: "Unified AI chat with 14 Zen models and 100+ providers"},
      {icon: "code", title: "Hanzo MCP", desc: "260+ Model Context Protocol tools for AI agents"},
      {icon: "cloud", title: "Hanzo Cloud", desc: "Deploy AI workloads with one command to global edge"},
      {icon: "shield", title: "Hanzo KMS", desc: "Zero-trust secrets management with Universal Auth"},
      {icon: "flow", title: "Hanzo Flow", desc: "Visual AI workflow builder with drag-and-drop"},
      {icon: "search", title: "Hanzo Search", desc: "AI-powered search with generative UI responses"},
      {icon: "bot", title: "Hanzo Bot", desc: "Multi-agent orchestration framework for complex tasks"},
      {icon: "studio", title: "Hanzo Studio", desc: "Visual AI engine for image, video, and 3D generation"},
    ],
    testimonials: [
      {
        name: "David Chen",
        role: "CTO, Techstars '22 Cohort",
        text: "Hanzo cut our AI infrastructure setup from weeks to hours. The unified gateway alone saved us from managing 6 different provider integrations.",
      },
      {
        name: "Sarah Kim",
        role: "VP Engineering, Series B Startup",
        text: "We migrated from a patchwork of AI services to Hanzo Cloud and reduced our inference costs by 40% while improving latency across all regions.",
      },
      {
        name: "Marcus Rivera",
        role: "Lead ML Engineer",
        text: "The MCP tools are a game-changer for agent development. Our team ships AI features 3x faster since adopting the Hanzo stack.",
      },
      {
        name: "Priya Patel",
        role: "Head of AI, Enterprise SaaS",
        text: "Hanzo's KMS and zero-trust auth gave us SOC 2 compliance out of the box. Security that actually makes development faster, not slower.",
      },
    ],
  },

  lux: {
    badge: "Blockchain Infrastructure",
    title: "Build on Lux",
    subtitle: "Multi-consensus blockchain with post-quantum security and sub-second finality",
    slides: [
      {icon: "chain", title: "Lux Network", desc: "Sub-second finality with novel Snow consensus"},
      {icon: "shield", title: "Post-Quantum", desc: "Future-proof cryptography for long-term security"},
      {icon: "code", title: "Lux EVM", desc: "Full EVM compatibility with enhanced performance"},
      {icon: "cloud", title: "App Chains", desc: "Deploy dedicated L2/L3 chains for your application"},
    ],
    testimonials: [
      {
        name: "Alex Torres",
        role: "DeFi Protocol Lead",
        text: "Lux's multi-consensus architecture lets us run our DEX on a dedicated chain while settling to the main network. Best of both worlds.",
      },
      {
        name: "Nina Volkov",
        role: "Blockchain Security Researcher",
        text: "The post-quantum roadmap is why we chose Lux. When quantum computing threatens existing chains, Lux will already be protected.",
      },
    ],
  },

  zoo: {
    badge: "Open AI Research",
    title: "Zoo Labs",
    subtitle: "Decentralized AI research network advancing open science and frontier models",
    slides: [
      {icon: "brain", title: "Decentralized AI", desc: "Community-driven training across distributed compute"},
      {icon: "science", title: "DeSci", desc: "Decentralized science research coordination"},
      {icon: "gov", title: "ZIPs", desc: "Zoo Improvement Proposals for open governance"},
      {icon: "model", title: "Open Models", desc: "Frontier models released under open licenses"},
    ],
    testimonials: [
      {
        name: "Dr. James Liu",
        role: "Research Scientist, Zoo Foundation",
        text: "Zoo's decentralized training protocol proved that community-coordinated AI can match centralized labs on benchmark quality.",
      },
    ],
  },

  pars: {
    badge: "Digital Identity",
    title: "Pars Network",
    subtitle: "Sovereign digital identity and verifiable credentials for the next web",
    slides: [
      {icon: "id", title: "Pars ID", desc: "Self-sovereign identity with verifiable credentials"},
      {icon: "shield", title: "Privacy-First", desc: "Zero-knowledge proofs for selective disclosure"},
    ],
    testimonials: [],
  },

  securegate: {
    badge: "Biometric Security",
    title: "SecureGate",
    subtitle: "AI-powered identity verification for events, venues, and access control",
    slides: [
      {icon: "id", title: "Face Recognition", desc: "Real-time identification with 512-d ArcFace embeddings"},
      {icon: "shield", title: "Weapon Detection", desc: "YOLO-based firearm and knife detection on live feeds"},
      {icon: "search", title: "Smart Timeline", desc: "Automated occupancy tracking and presence analytics"},
      {icon: "bot", title: "Deepfake Guard", desc: "AI-powered liveness detection against spoofing attacks"},
    ],
    testimonials: [
      {
        name: "Event Director",
        role: "Major Venue Operator",
        text: "SecureGate replaced our entire badge-checking process. Attendees walk in, get recognized instantly, and we have a complete timeline of every room.",
      },
      {
        name: "Security Lead",
        role: "Conference Organizer",
        text: "The weapon detection caught a concealed knife during setup that our metal detectors missed. The real-time alerts to our team were invaluable.",
      },
    ],
  },

  liquidity: {
    badge: "Digital Securities",
    title: "Liquidity.io",
    subtitle: "SEC-registered ATS for tokenized securities trading and settlement",
    slides: [
      {icon: "flow", title: "Smart Order Router", desc: "Best execution across 16 venues and providers"},
      {icon: "chain", title: "On-Chain Settlement", desc: "Atomic settlement on Liquid EVM with MPC custody"},
      {icon: "shield", title: "Compliance Built-In", desc: "Reg D, Rule 144, AML/KYC enforced at protocol level"},
      {icon: "code", title: "White-Label", desc: "Launch your own BD with full branding and data isolation"},
    ],
    testimonials: [
      {
        name: "Compliance Officer",
        role: "Introducing Broker-Dealer",
        text: "The on-chain compliance modules mean we never have to worry about Rule 144 lockup violations. The smart contracts enforce it automatically.",
      },
    ],
  },
};

// ── Slide icon renderer ──────────────────────────────────────────────────

const slideIcons: Record<string, React.ReactNode> = {
  chat: <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />,
  code: <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" />,
  cloud: <path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z" />,
  shield: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  flow: <><circle cx="12" cy="12" r="3" /><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83" /></>,
  search: <><circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" /></>,
  bot: <><rect x="3" y="11" width="18" height="10" rx="2" /><circle cx="12" cy="5" r="2" /><path d="M12 7v4M8 16h0M16 16h0" /></>,
  studio: <><rect x="2" y="2" width="20" height="20" rx="2.18" /><path d="M7 2v20M17 2v20M2 12h20M2 7h5M2 17h5M17 17h5M17 7h5" /></>,
  chain: <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />,
  brain: <path d="M12 2a7 7 0 017 7c0 2.38-1.19 4.47-3 5.74V17a2 2 0 01-2 2h-4a2 2 0 01-2-2v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 017-7zM9 21h6M10 17v4M14 17v4" />,
  science: <path d="M10 2v7.527a2 2 0 01-.211.896L4.72 20.55a1 1 0 00.9 1.45h12.76a1 1 0 00.9-1.45l-5.069-10.127A2 2 0 0114 9.527V2M8.5 2h7M7 16h10" />,
  gov: <path d="M3 21h18M3 10h18M5 6l7-3 7 3M4 10v11M20 10v11M8 14v3M12 14v3M16 14v3" />,
  model: <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M9 9h6v6H9z" /><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3" /></>,
  id: <><rect x="2" y="5" width="20" height="14" rx="2" /><circle cx="8" cy="12" r="2" /><path d="M14 10h4M14 14h2" /></>,
};

function SlideIcon({name}: SlideIconProps) {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {slideIcons[name] || slideIcons.code}
    </svg>
  );
}

// ── Main component ───────────────────────────────────────────────────────

export default function HanzoShowcase({application}: HanzoShowcaseProps) {
  const [currentSlide, setCurrentSlide] = useState<number>(0);
  const [currentTestimonial, setCurrentTestimonial] = useState<number>(0);
  const [slideDirection, setSlideDirection] = useState<"in" | "out">("in");

  // Resolve org content — fall back to generic (not hanzo-branded)
  const orgName = application?.organization || "hanzo";
  const genericContent: OrgContent = {
    badge: "Secure Access",
    title: application?.organization
      ? (orgContent[orgName]?.title || application.organization)
      : "Sign In",
    subtitle: "Identity and access management powered by Hanzo IAM",
    slides: [
      {icon: "shield", title: "Secure Auth", desc: "OAuth 2.0, OIDC, SAML, and WebAuthn out of the box"},
      {icon: "id", title: "Multi-Tenant", desc: "Isolated organizations with per-tenant branding"},
      {icon: "code", title: "Developer-First", desc: "SDKs, APIs, and MCP tools for rapid integration"},
    ],
    testimonials: [],
  };
  const content = orgContent[orgName] || genericContent;
  const slides = content.slides;
  const testimonials = content.testimonials.length > 0
    ? content.testimonials
    : [];

  const nextSlide = useCallback(() => {
    setSlideDirection("out");
    setTimeout(() => {
      setCurrentSlide((prev) => (prev + 1) % slides.length);
      setSlideDirection("in");
    }, 300);
  }, [slides.length]);

  useEffect(() => {
    const interval = setInterval(nextSlide, 4000);
    return () => clearInterval(interval);
  }, [nextSlide]);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTestimonial((prev) => (prev + 1) % testimonials.length);
    }, 7000);
    return () => clearInterval(interval);
  }, [testimonials.length]);

  const slide = slides[currentSlide];
  const testimonial = testimonials[currentTestimonial];

  return (
    <div className="hanzo-showcase">
      <div className="showcase-bg-pattern" />
      <div className="showcase-orb showcase-orb-1" />
      <div className="showcase-orb showcase-orb-2" />

      <div className="showcase-content">
        {/* Header */}
        <div className="showcase-header">
          <div className="showcase-badge">
            <svg className="showcase-sparkle" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 3l1.09 4.26L17 8.27l-3.91.91L12 13l-1.09-3.82L7 8.27l3.91-.91L12 3z" fill="currentColor" />
            </svg>
            <span>{content.badge}</span>
          </div>
          <h2 className="showcase-title">{content.title}</h2>
          <p className="showcase-subtitle">{content.subtitle}</p>
        </div>

        {/* Product slide carousel */}
        <div className="showcase-chat-box">
          <div className="showcase-chat-inner">
            <div className="showcase-indicator" />
            <div className="showcase-chat-content">
              <div className={`showcase-slide ${slideDirection}`}>
                <div className="showcase-slide-icon">
                  <SlideIcon name={slide.icon} />
                </div>
                <div className="showcase-slide-text">
                  <p className="showcase-slide-title">{slide.title}</p>
                  <p className="showcase-slide-desc">{slide.desc}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Slide dots */}
          <div className="showcase-chat-footer">
            <div className="showcase-slide-dots">
              {slides.map((_: Slide, index: number) => (
                <button
                  key={index}
                  className={`showcase-dot ${currentSlide === index ? "active" : ""}`}
                  onClick={() => { setCurrentSlide(index); setSlideDirection("in"); }}
                />
              ))}
            </div>
          </div>
        </div>

        {/* Testimonial — only shown if org has testimonials */}
        {testimonials.length > 0 && (
          <div className="showcase-testimonial">
            <div className="showcase-testimonial-content">
              <svg className="showcase-quote-icon" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" opacity="0.3">
                <path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h3.983v10h-9.983z" />
              </svg>
              <p className="showcase-testimonial-text">&ldquo;{testimonial.text}&rdquo;</p>
              <div className="showcase-testimonial-author">
                <div className="showcase-avatar">
                  {testimonial.name.split(" ").map((n: string) => n[0]).join("")}
                </div>
                <div className="showcase-author-info">
                  <span className="showcase-author-name">{testimonial.name}</span>
                  <span className="showcase-author-role">{testimonial.role}</span>
                </div>
              </div>
            </div>

            <div className="showcase-testimonial-dots">
              {testimonials.map((_: Testimonial, index: number) => (
                <button
                  key={index}
                  className={`showcase-dot ${currentTestimonial === index ? "active" : ""}`}
                  onClick={() => setCurrentTestimonial(index)}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
