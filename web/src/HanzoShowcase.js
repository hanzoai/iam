// Hanzo AI Showcase Component for Login Page
// Displays animated content on the right side of the split-screen login

import React, {useEffect, useState} from "react";

// Animated ideas/prompts that cycle through
const ideas = [
  "Build a SaaS dashboard with real-time analytics",
  "Create an AI-powered chat application",
  "Design a modern e-commerce platform",
  "Develop a social media scheduler with AI",
  "Build a cryptocurrency trading dashboard",
  "Create a video streaming platform like Netflix",
  "Design a project management tool with AI insights",
  "Build a marketplace for digital products",
  "Create a learning management system",
  "Develop a fitness tracking app with AI coach",
];

// Testimonials from real users
const testimonials = [
  {
    name: "Giovanna Mingarelli",
    role: "CEO, M Corp",
    avatar: "GM",
    text: "Hanzo AI is amazing! It's revolutionizing how we build and deploy applications. The speed and quality of what we can create now is a total game-changer.",
  },
  {
    name: "Ben Chu",
    role: "Tech Lead, Startup",
    avatar: "BC",
    text: "Hanzo is the best! Highly recommend this great service for anyone interested in AI development. Better than competitors, intuitive interface.",
  },
  {
    name: "Ole Brereton",
    role: "CTO, Innovation Labs",
    avatar: "OB",
    text: "Setting the bar for innovation, development and execution. World class leaders in the future of AI-powered development tools.",
  },
  {
    name: "Lisa Goodman",
    role: "Product Manager",
    avatar: "LG",
    text: "As someone who values efficiency and quality, Hanzo AI is exactly what modern development needs. It's a smart, exciting way to build products.",
  },
];

export default function HanzoShowcase() {
  const [currentIdea, setCurrentIdea] = useState(0);
  const [currentTestimonial, setCurrentTestimonial] = useState(0);
  const [isTyping, setIsTyping] = useState(true);

  useEffect(() => {
    const interval = setInterval(() => {
      setIsTyping(false);
      setTimeout(() => {
        setCurrentIdea((prev) => (prev + 1) % ideas.length);
        setIsTyping(true);
      }, 500);
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const testimonialInterval = setInterval(() => {
      setCurrentTestimonial((prev) => (prev + 1) % testimonials.length);
    }, 6000);

    return () => clearInterval(testimonialInterval);
  }, []);

  const testimonial = testimonials[currentTestimonial];

  return (
    <div className="hanzo-showcase">
      {/* Background Pattern */}
      <div className="showcase-bg-pattern" />

      {/* Animated Gradient Orbs */}
      <div className="showcase-orb showcase-orb-1" />
      <div className="showcase-orb showcase-orb-2" />

      {/* Content */}
      <div className="showcase-content">
        <div className="showcase-header">
          <div className="showcase-badge">
            <svg className="showcase-sparkle" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 3l1.09 4.26L17 8.27l-3.91.91L12 13l-1.09-3.82L7 8.27l3.91-.91L12 3z" fill="currentColor" />
            </svg>
            <span>AI-powered development</span>
          </div>

          <h2 className="showcase-title">Start building in seconds</h2>
          <p className="showcase-subtitle">Describe your idea and watch AI bring it to life instantly</p>
        </div>

        {/* Chat-like Input Preview */}
        <div className="showcase-chat-box">
          <div className="showcase-chat-inner">
            <div className="showcase-indicator" />
            <div className="showcase-chat-content">
              <p className="showcase-label">TRY SOMETHING LIKE</p>
              <div className="showcase-idea-container">
                <p className={`showcase-idea ${isTyping ? "typing" : "fade"}`}>
                  {ideas[currentIdea]}
                  <span className="showcase-cursor" />
                </p>
              </div>
            </div>
          </div>

          <div className="showcase-chat-footer">
            <div className="showcase-chat-actions">
              <button className="showcase-action-btn">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                </svg>
              </button>
              <button className="showcase-action-btn">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z" />
                </svg>
              </button>
            </div>
            <button className="showcase-generate-btn">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="currentColor" />
              </svg>
              Generate
            </button>
          </div>
        </div>

        {/* Testimonial Section */}
        <div className="showcase-testimonial">
          <div className="showcase-testimonial-content">
            <svg className="showcase-quote-icon" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" opacity="0.3">
              <path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h3.983v10h-9.983z" />
            </svg>
            <p className="showcase-testimonial-text">&ldquo;{testimonial.text}&rdquo;</p>
            <div className="showcase-testimonial-author">
              <div className="showcase-avatar">{testimonial.avatar}</div>
              <div className="showcase-author-info">
                <span className="showcase-author-name">{testimonial.name}</span>
                <span className="showcase-author-role">{testimonial.role}</span>
              </div>
            </div>
          </div>

          {/* Testimonial Dots */}
          <div className="showcase-testimonial-dots">
            {testimonials.map((_, index) => (
              <button
                key={index}
                className={`showcase-dot ${currentTestimonial === index ? "active" : ""}`}
                onClick={() => setCurrentTestimonial(index)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
