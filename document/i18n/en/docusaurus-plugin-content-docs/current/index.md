---
title: SkillHub Documentation
sidebar_position: 1
description: Enterprise-grade open source agent skill registry for governed, self-hosted publishing, discovery, and team collaboration
---

# SkillHub

<section className="hero-section">
  <div className="container">
    <div className="hero-shell">
      <div className="hero-content">
        <div className="hero-badge">Self-hosted Registry for Agent Skills</div>
        <h1 className="hero-section__title">Ship reusable AI skills with governed discovery, review, and deployment.</h1>
        <div className="hero-section__tagline">{`Astron SkillHub gives teams a polished internal registry for publishing, discovering, versioning, and operating reusable agent skill packages without the usual AI-generated design smell.`}</div>
        <div className="hero-section__cta">
          <a href="/getting-started/quick-start" className="btn-primary">Deploy Now</a>
          <a href="/getting-started/overview" className="btn-secondary">Explore Architecture</a>
        </div>
        <div className="hero-proof">
          <span>Semantic versioning</span>
          <span>Namespace governance</span>
          <span>Security scanning</span>
          <span>CLI compatibility</span>
        </div>
      </div>
      <div className="hero-visual">
        <div className="hero-logo-card">
          <img src="/img/astron-skillhub-logo.svg" alt="Astron SkillHub" className="hero-logo" />
          <div className="hero-logo-card__membership">
            <a className="hero-logo-card__membership-link" href="https://aaif.io/" target="_blank" rel="noopener noreferrer" aria-label="Agentic AI Foundation (opens in new tab)">
              <img src="https://cdn.sanity.io/images/4o10fa7h/production/16dd7d8270b673d376cadca831ab3d5ea003bb89-838x203.svg" alt="Agentic AI Foundation (AAIF)" width="838" height="203" className="hero-logo-card__membership-logo" />
            </a>
            <div className="hero-logo-card__membership-label">AAIF Associate Member</div>
          </div>
        </div>
        <div className="hero-stats">
          <div className="hero-stat">
            <strong>1</strong>
            <span>Registry for teams, governance, and runtime docs</span>
          </div>
          <div className="hero-stat">
            <strong>3</strong>
            <span>Core workflows: publish, discover, review</span>
          </div>
          <div className="hero-stat">
            <strong>24/7</strong>
            <span>Suitable for always-on internal skill operations</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

---

## Why Teams Choose SkillHub

<div className="feature-grid">
  <div className="enterprise-value-card enterprise-value-card--featured">
    <div className="enterprise-value-card__eyebrow">Publishing</div>
    <h3 className="enterprise-value-card__title">Versioned delivery without registry chaos</h3>
    <div className="enterprise-value-card__description">{`Semantic versioning, channel tags, and immutable package history make skill publishing feel predictable for both platform teams and daily contributors.`}</div>
    <div className="enterprise-value-card__list">
      <span>Semantic versioning</span>
      <span>Tags like beta / stable / latest</span>
      <span>Download and rollback friendly</span>
    </div>
  </div>
  <div className="enterprise-value-card">
    <div className="enterprise-value-card__eyebrow">Discovery</div>
    <h3 className="enterprise-value-card__title">Search that respects permissions</h3>
    <div className="enterprise-value-card__description">{`Full-text search and structured filters help users find the right skill quickly while still honoring namespace visibility and governance boundaries.`}</div>
  </div>
  <div className="enterprise-value-card">
    <div className="enterprise-value-card__eyebrow">Collaboration</div>
    <h3 className="enterprise-value-card__title">Namespaces built for real teams</h3>
    <div className="enterprise-value-card__description">{`Organize skills by owner, domain, or department and pair that structure with Owner, Admin, and Member roles that match enterprise workflows.`}</div>
  </div>
  <div className="enterprise-value-card">
    <div className="enterprise-value-card__eyebrow">Governance</div>
    <h3 className="enterprise-value-card__title">Review, audit, and promote with confidence</h3>
    <div className="enterprise-value-card__description">{`Promotion review flows, audit logs, and optional security scanning make it easier to move skills from local innovation to governed organizational reuse.`}</div>
  </div>
</div>

---

## Built For Mature Delivery

<div className="story-grid">
  <div className="story-card">
    <h3>Less AI-looking chrome, more product-grade clarity</h3>
    <div className="story-card__body">{`The public docs experience is tuned for cleaner typography, tighter spacing, stronger visual hierarchy, and fewer generic gradients so the brand feels deliberate rather than over-generated.`}</div>
  </div>
  <div className="story-card">
    <h3>Designed around modern system thinking</h3>
    <div className="story-card__body">{`The refreshed layout borrows the discipline of modern component systems such as shadcn/ui and utility-first design tokens, even though this site remains a Docusaurus documentation experience.`}</div>
  </div>
  <div className="story-card">
    <h3>International first, localized by default switch</h3>
    <div className="story-card__body">{`English now leads as the default locale for broader reach, while the Chinese translation remains one click away through the built-in locale switcher.`}</div>
  </div>
</div>

---

## Current Coverage

<div className="coverage-panel">
  <div className="feature-tags">
    <span className="feature-tag">Self-hosted</span>
    <span className="feature-tag">Version Control</span>
    <span className="feature-tag">Full-text Search</span>
    <span className="feature-tag">Namespaces</span>
    <span className="feature-tag">Review Workflow</span>
    <span className="feature-tag">Semantic Versioning</span>
    <span className="feature-tag">RBAC Permissions</span>
    <span className="feature-tag">Audit Logs</span>
    <span className="feature-tag">Security Scanning</span>
    <span className="feature-tag">CLI Compatibility</span>
  </div>
</div>

---

## Quick Start

<div className="quick-start-panel">
  <div className="quick-start-code">
    <code>$ curl -fsSL https://raw.githubusercontent.com/iflytek/skillhub/main/scripts/runtime.sh | sh -s -- up</code>
  </div>
  <div className="quick-start-hints">
    <div className="quick-start-hint">
      <span className="quick-start-hint__label">Default Admin</span>
      <strong>admin / ChangeMe!2026</strong>
    </div>
    <div className="quick-start-hint">
      <span className="quick-start-hint__label">Local Web UI</span>
      <strong>http://localhost:3000</strong>
    </div>
    <div className="quick-start-hint">
      <span className="quick-start-hint__label">Registry API</span>
      <strong>http://localhost:8080</strong>
    </div>
  </div>
</div>

---

## Next Steps

- [Quick Start](./getting-started/quick-start) - Deploy SkillHub with one command
- [Overview](./getting-started/overview) - Learn how the platform is positioned
- [Publish Workflow](./user-guide/publishing/publish) - Publish your first skill package
- [Single Machine Deployment](./administration/deployment/single-machine) - Run the production-ready stack
