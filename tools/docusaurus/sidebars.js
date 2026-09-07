// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').Config} */
const sidebars = {
  tutorialSidebar: [
    {
      type: 'doc',
      id: 'index',
      label: 'Introduction',
    },
    {
      type: 'doc',
      id: 'oauth-login',
      label: 'OAuth login',
    },
    {
      type: 'doc',
      id: 'company-access',
      label: 'Company access',
    },
    {
      type: 'doc',
      id: 'jwks',
      label: 'JWKS',
    },
    {
      type: 'doc',
      id: 'metrics',
      label: 'Metrics',
    },
    {
      type: 'doc',
      id: 'RELEASES',
      label: 'Releases',
    },
  ],
};

module.exports = sidebars;
