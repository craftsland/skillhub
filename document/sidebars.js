/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    'index',
    {
      type: 'category',
      label: 'Getting Started',
      link: {
        type: 'generated-index',
      },
      items: [
        'getting-started/overview',
        'getting-started/quick-start',
        'getting-started/use-cases',
      ],
    },
    {
      type: 'category',
      label: 'Administration Guide',
      link: {
        type: 'generated-index',
      },
      items: [
        {
          type: 'category',
          label: 'Deployment Guide',
          items: [
            'administration/deployment/single-machine',
            'administration/deployment/kubernetes',
            'administration/deployment/configuration',
          ],
        },
        {
          type: 'category',
          label: 'Security & Compliance',
          items: [
            'administration/security/authentication',
            'administration/security/authorization',
            'administration/security/audit-logs',
            'administration/security/scanner',
          ],
        },
        {
          type: 'category',
          label: 'Governance & Operations',
          items: [
            'administration/governance/namespaces',
            'administration/governance/review-workflow',
            'administration/governance/user-management',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'User Guide',
      link: {
        type: 'generated-index',
      },
      items: [
        {
          type: 'category',
          label: 'Publishing Skills',
          items: [
            'user-guide/publishing/create-skill',
            'user-guide/publishing/publish',
            'user-guide/publishing/versioning',
          ],
        },
        {
          type: 'category',
          label: 'Discovery & Usage',
          items: [
            'user-guide/discovery/search',
            'user-guide/discovery/install',
            'user-guide/discovery/ratings',
          ],
        },
        {
          type: 'category',
          label: 'Collaboration',
          items: [
            'user-guide/collaboration/namespaces',
            'user-guide/collaboration/promotion',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Developer Reference',
      link: {
        type: 'generated-index',
      },
      items: [
        {
          type: 'category',
          label: 'API Reference',
          items: [
            'developer/api/overview',
            'developer/api/public',
            'developer/api/authenticated',
            'developer/api/cli-compat',
          ],
        },
        {
          type: 'category',
          label: 'Architecture',
          items: [
            'developer/architecture/overview',
            'developer/architecture/domain-model',
            'developer/architecture/security',
          ],
        },
        {
          type: 'category',
          label: 'Extensions & Integrations',
          items: [
            'developer/plugins/skill-protocol',
            'developer/plugins/storage-spi',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      link: {
        type: 'generated-index',
      },
      items: [
        'reference/faq',
        'reference/troubleshooting',
        'reference/changelog',
        'reference/roadmap',
      ],
    },
  ],
};

export default sidebars;
