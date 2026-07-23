import { themes as prismThemes } from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'SkillHub',
  tagline: 'Enterprise-grade Open Source Agent Skill Registry',

  url: 'https://www.astron-skillhub.org',
  baseUrl: '/',

  organizationName: 'iflytek',
  projectName: 'skillhub',

  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'zh-CN'],
    localeConfigs: {
      'en': {
        label: 'English',
        htmlLang: 'en',
      },
      'zh-CN': {
        label: '中文',
        htmlLang: 'zh-CN',
      },
    },
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/docs',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/iflytek/skillhub/edit/main/document/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        logo: {
          alt: 'Astron SkillHub Logo',
          src: 'img/astron-skillhub-logo.svg',
        },
        items: [
          {
            to: '/docs/getting-started/quick-start',
            position: 'left',
            label: 'Quick Start',
          },
          {
            to: '/docs/getting-started/overview',
            position: 'left',
            label: 'Overview',
          },
          {
            to: '/docs/user-guide/publishing/publish',
            position: 'left',
            label: 'Publish Workflow',
          },
          {
            to: '/docs/administration/deployment/single-machine',
            position: 'left',
            label: 'Single Node',
          },
          {
            type: 'localeDropdown',
            position: 'right',
          },
          {
            href: 'https://github.com/iflytek/skillhub',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Documentation',
            items: [
              {
                label: 'Quick Start',
                to: '/docs/getting-started/quick-start',
              },
              {
                label: 'Deployment',
                to: '/docs/administration/deployment/single-machine',
              },
              {
                label: 'API Reference',
                to: '/docs/developer/api/overview',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/iflytek/skillhub',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} iFlytek. Built with Docusaurus.`,
      },
      metadata: [
        {
          name: 'keywords',
          content: 'SkillHub, skill registry, agent skills, self-hosted, enterprise ai',
        },
      ],
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['java', 'bash', 'yaml', 'json'],
      },
    }),
  plugins: [
    [
      '@docusaurus/plugin-client-redirects',
      {
        createRedirects(existingPath) {
          if (existingPath === '/docs/' || existingPath === '/zh-CN/docs/') {
            return undefined;
          }

          if (existingPath.includes('/docs/')) {
            return [existingPath.replace('/docs', '')];
          }

          return undefined;
        },
        redirects: [
          {
            from: ['/quickstart.html'],
            to: '/docs/getting-started/quick-start',
          },
          {
            from: ['/introduction.html'],
            to: '/docs/getting-started/overview',
          },
          {
            from: ['/faq.html'],
            to: '/docs/reference/faq',
          },
          {
            from: ['/guide/skill-publish.html'],
            to: '/docs/user-guide/publishing/publish',
          },
          {
            from: ['/guide/skill-discovery.html'],
            to: '/docs/user-guide/discovery/search',
          },
          {
            from: ['/guide/namespace.html'],
            to: '/docs/user-guide/collaboration/namespaces',
          },
          {
            from: ['/guide/review.html'],
            to: '/docs/administration/governance/review-workflow',
          },
          {
            from: ['/guide/social.html'],
            to: '/docs/user-guide/discovery/ratings',
          },
          {
            from: ['/guide/scanner.html'],
            to: '/docs/administration/security/scanner',
          },
        ],
      },
    ],
  ],
};

export default config;
