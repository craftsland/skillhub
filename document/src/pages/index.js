import React from 'react'
import Layout from '@theme/Layout'
import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import useBaseUrl from '@docusaurus/useBaseUrl'
import { useLocation } from '@docusaurus/router'

const aaifLogoUrl =
  'https://cdn.sanity.io/images/4o10fa7h/production/16dd7d8270b673d376cadca831ab3d5ea003bb89-838x203.svg'

function getLocaleDocsPath(locale) {
  return locale === 'zh-CN' ? '/zh-CN/docs' : '/docs'
}

export default function Home() {
  const { siteConfig, i18n } = useDocusaurusContext()
  const location = useLocation()
  const isChinese = location.pathname.startsWith('/zh-CN')
  const locale = isChinese ? 'zh-CN' : i18n.currentLocale
  const docsBase = getLocaleDocsPath(locale)
  const logoUrl = useBaseUrl('/img/astron-skillhub-logo.svg')

  return (
    <Layout
      title={translate({
        id: 'homepage.title',
        message: 'Astron SkillHub',
      })}
      description={translate({
        id: 'homepage.description',
        message:
          'Enterprise-grade open source agent skill registry for governed, self-hosted publishing, discovery, and team collaboration.',
      })}>
      <main className="landing-page">
        <section className="hero-section hero-section--landing">
          <div className="container">
            <div className="hero-shell">
              <div className="hero-content">
                <div className="hero-badge">
                  <Translate id="homepage.hero.badge">Self-hosted Registry for Agent Skills</Translate>
                </div>
                <h1 className="hero-section__title">
                  <Translate id="homepage.hero.title">
                    Ship reusable AI skills with governed delivery.
                  </Translate>
                </h1>
                <div className="hero-section__tagline">
                  <Translate id="homepage.hero.tagline">
                    Astron SkillHub gives teams a polished internal registry for publishing, discovering,
                    versioning, and operating reusable agent skill packages without the usual AI-generated
                    design smell.
                  </Translate>
                </div>
                <div className="hero-section__cta">
                  <Link className="btn-primary" to={`${docsBase}/getting-started/quick-start`}>
                    <Translate id="homepage.hero.cta.primary">Deploy Now</Translate>
                  </Link>
                  <Link className="btn-secondary" to={`${docsBase}/getting-started/overview`}>
                    <Translate id="homepage.hero.cta.secondary">Explore Architecture</Translate>
                  </Link>
                </div>
                <div className="hero-proof">
                  <span><Translate id="homepage.hero.proof.versioning">Semantic versioning</Translate></span>
                  <span><Translate id="homepage.hero.proof.namespace">Namespace governance</Translate></span>
                  <span><Translate id="homepage.hero.proof.scanner">Security scanning</Translate></span>
                  <span><Translate id="homepage.hero.proof.cli">CLI compatibility</Translate></span>
                </div>
              </div>
              <div className="hero-visual">
                <div className="hero-logo-card">
                  <img src={logoUrl} alt="Astron SkillHub" className="hero-logo" />
                  <div className="hero-logo-card__membership">
                    <a
                      className="hero-logo-card__membership-link"
                      href="https://aaif.io/"
                      target="_blank"
                      rel="noopener noreferrer"
                      aria-label={translate({
                        id: 'homepage.hero.membership.ariaLabel',
                        message: 'Agentic AI Foundation website (opens in a new tab)',
                      })}>
                      <img
                        src={aaifLogoUrl}
                        alt={translate({
                          id: 'homepage.hero.membership.logoAlt',
                          message: 'Agentic AI Foundation (AAIF)',
                        })}
                        width="838"
                        height="203"
                        className="hero-logo-card__membership-logo"
                      />
                    </a>
                    <div className="hero-logo-card__membership-label">
                      <Translate id="homepage.hero.membership">AAIF Associate Member</Translate>
                    </div>
                  </div>
                </div>
                <div className="hero-stats">
                  <div className="hero-stat">
                    <strong>1</strong>
                    <span>
                      <Translate id="homepage.hero.stat.one">
                        Registry for teams, governance, and runtime docs
                      </Translate>
                    </span>
                  </div>
                  <div className="hero-stat">
                    <strong>3</strong>
                    <span>
                      <Translate id="homepage.hero.stat.three">
                        Core workflows: publish, discover, review
                      </Translate>
                    </span>
                  </div>
                  <div className="hero-stat">
                    <strong>24/7</strong>
                    <span>
                      <Translate id="homepage.hero.stat.alwaysOn">
                        Suitable for always-on internal skill operations
                      </Translate>
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section">
          <div className="container">
            <h2>
              <Translate id="homepage.why.title">Why Teams Choose SkillHub</Translate>
            </h2>
            <div className="feature-grid">
              <div className="enterprise-value-card enterprise-value-card--featured">
                <div className="enterprise-value-card__eyebrow">
                  <Translate id="homepage.why.publishing.eyebrow">Publishing</Translate>
                </div>
                <h3 className="enterprise-value-card__title">
                  <Translate id="homepage.why.publishing.title">
                    Versioned delivery without registry chaos
                  </Translate>
                </h3>
                <div className="enterprise-value-card__description">
                  <Translate id="homepage.why.publishing.description">
                    Semantic versioning, channel tags, and immutable package history make skill publishing
                    feel predictable for both platform teams and daily contributors.
                  </Translate>
                </div>
                <div className="enterprise-value-card__list">
                  <span><Translate id="homepage.why.publishing.tag1">Semantic versioning</Translate></span>
                  <span><Translate id="homepage.why.publishing.tag2">Tags like beta / stable / latest</Translate></span>
                  <span><Translate id="homepage.why.publishing.tag3">Download and rollback friendly</Translate></span>
                </div>
              </div>
              <div className="enterprise-value-card">
                <div className="enterprise-value-card__eyebrow">
                  <Translate id="homepage.why.discovery.eyebrow">Discovery</Translate>
                </div>
                <h3 className="enterprise-value-card__title">
                  <Translate id="homepage.why.discovery.title">Search that respects permissions</Translate>
                </h3>
                <div className="enterprise-value-card__description">
                  <Translate id="homepage.why.discovery.description">
                    Full-text search and structured filters help users find the right skill quickly while
                    still honoring namespace visibility and governance boundaries.
                  </Translate>
                </div>
              </div>
              <div className="enterprise-value-card">
                <div className="enterprise-value-card__eyebrow">
                  <Translate id="homepage.why.collaboration.eyebrow">Collaboration</Translate>
                </div>
                <h3 className="enterprise-value-card__title">
                  <Translate id="homepage.why.collaboration.title">Namespaces built for real teams</Translate>
                </h3>
                <div className="enterprise-value-card__description">
                  <Translate id="homepage.why.collaboration.description">
                    Organize skills by owner, domain, or department and pair that structure with Owner,
                    Admin, and Member roles that match enterprise workflows.
                  </Translate>
                </div>
              </div>
              <div className="enterprise-value-card">
                <div className="enterprise-value-card__eyebrow">
                  <Translate id="homepage.why.governance.eyebrow">Governance</Translate>
                </div>
                <h3 className="enterprise-value-card__title">
                  <Translate id="homepage.why.governance.title">Review, audit, and promote with confidence</Translate>
                </h3>
                <div className="enterprise-value-card__description">
                  <Translate id="homepage.why.governance.description">
                    Promotion review flows, audit logs, and optional security scanning make it easier to
                    move skills from local innovation to governed organizational reuse.
                  </Translate>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section">
          <div className="container">
            <h2>
              <Translate id="homepage.mature.title">Built For Mature Delivery</Translate>
            </h2>
            <div className="story-grid">
              <div className="story-card">
                <h3>
                  <Translate id="homepage.mature.card1.title">
                    Less AI-looking chrome, more product-grade clarity
                  </Translate>
                </h3>
                <div className="story-card__body">
                  <Translate id="homepage.mature.card1.body">
                    The public docs experience is tuned for cleaner typography, tighter spacing, stronger
                    visual hierarchy, and fewer generic gradients so the brand feels deliberate rather than
                    over-generated.
                  </Translate>
                </div>
              </div>
              <div className="story-card">
                <h3>
                  <Translate id="homepage.mature.card2.title">
                    Designed around modern system thinking
                  </Translate>
                </h3>
                <div className="story-card__body">
                  <Translate id="homepage.mature.card2.body">
                    The refreshed layout borrows the discipline of modern component systems such as
                    shadcn/ui and utility-first design tokens, even though this site remains a Docusaurus
                    documentation experience.
                  </Translate>
                </div>
              </div>
              <div className="story-card">
                <h3>
                  <Translate id="homepage.mature.card3.title">
                    International first, localized by default switch
                  </Translate>
                </h3>
                <div className="story-card__body">
                  <Translate id="homepage.mature.card3.body">
                    English now leads as the default locale for broader reach, while the Chinese translation
                    remains one click away through the built-in locale switcher.
                  </Translate>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section">
          <div className="container">
            <h2>
              <Translate id="homepage.coverage.title">Current Coverage</Translate>
            </h2>
            <div className="coverage-panel">
              <div className="feature-tags">
                <span className="feature-tag"><Translate id="homepage.coverage.tag1">Self-hosted</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag2">Version Control</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag3">Full-text Search</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag4">Namespaces</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag5">Review Workflow</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag6">Semantic Versioning</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag7">RBAC Permissions</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag8">Audit Logs</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag9">Security Scanning</Translate></span>
                <span className="feature-tag"><Translate id="homepage.coverage.tag10">CLI Compatibility</Translate></span>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section">
          <div className="container">
            <h2>
              <Translate id="homepage.quickstart.title">Quick Start</Translate>
            </h2>
            <div className="quick-start-panel">
              <div className="quick-start-code">
                <code>$ curl -fsSL https://raw.githubusercontent.com/iflytek/skillhub/main/scripts/runtime.sh | sh -s -- up</code>
              </div>
              <div className="quick-start-hints">
                <div className="quick-start-hint">
                  <span className="quick-start-hint__label">
                    <Translate id="homepage.quickstart.adminLabel">Default Admin</Translate>
                  </span>
                  <strong>admin / ChangeMe!2026</strong>
                </div>
                <div className="quick-start-hint">
                  <span className="quick-start-hint__label">
                    <Translate id="homepage.quickstart.uiLabel">Local Web UI</Translate>
                  </span>
                  <strong>http://localhost:3000</strong>
                </div>
                <div className="quick-start-hint">
                  <span className="quick-start-hint__label">
                    <Translate id="homepage.quickstart.apiLabel">Registry API</Translate>
                  </span>
                  <strong>http://localhost:8080</strong>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section landing-section--compact">
          <div className="container">
            <h2>
              <Translate id="homepage.next.title">Next Steps</Translate>
            </h2>
            <ul className="landing-links">
              <li>
                <Link to={`${docsBase}/getting-started/quick-start`}>
                  <Translate id="homepage.next.link1">Quick Start</Translate>
                </Link>
                {' - '}
                <Translate id="homepage.next.desc1">Deploy SkillHub with one command</Translate>
              </li>
              <li>
                <Link to={`${docsBase}/getting-started/overview`}>
                  <Translate id="homepage.next.link2">Overview</Translate>
                </Link>
                {' - '}
                <Translate id="homepage.next.desc2">Learn how the platform is positioned</Translate>
              </li>
              <li>
                <Link to={`${docsBase}/user-guide/publishing/publish`}>
                  <Translate id="homepage.next.link3">Publish Workflow</Translate>
                </Link>
                {' - '}
                <Translate id="homepage.next.desc3">Publish your first skill package</Translate>
              </li>
              <li>
                <Link to={`${docsBase}/administration/deployment/single-machine`}>
                  <Translate id="homepage.next.link4">Single Machine Deployment</Translate>
                </Link>
                {' - '}
                <Translate id="homepage.next.desc4">Run the production-ready stack</Translate>
              </li>
            </ul>
          </div>
        </section>
      </main>
    </Layout>
  )
}
