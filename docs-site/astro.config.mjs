import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://secuardenai.github.io',
  base: '/secuarden-cli',
  output: 'static',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'Secuarden CLI',
      description: 'Capture, inspect, and verify evidence from AI-assisted development.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/secuardenai/secuarden-cli' }],
      customCss: ['./src/styles/custom.css'],
      head: [{ tag: 'meta', attrs: { name: 'robots', content: 'noindex, nofollow' } }],
      sidebar: [
        { label: 'Get started', items: [
          { label: 'Overview', slug: 'index' },
          { label: 'Install', slug: 'get-started/install' },
          { label: 'Your first captured session', slug: 'get-started/first-session' },
        ] },
        { label: 'Agent setup', items: [
          { label: 'Claude Code', slug: 'agents/claude-code' },
          { label: 'Codex', slug: 'agents/codex' },
        ] },
        { label: 'Investigate changes', items: [
          { label: 'Reports and dashboard', slug: 'guides/reports' },
          { label: 'Prompt-to-merge chain', slug: 'guides/chain' },
        ] },
        { label: 'Capture integrity', items: [
          { label: 'Embedded contracts', slug: 'integrity/contracts' },
          { label: 'Monitor configuration', slug: 'integrity/monitoring' },
          { label: 'Verify and export', slug: 'integrity/verification' },
        ] },
        { label: 'Reference', items: [
          { label: 'CLI commands', slug: 'reference/commands' },
          { label: 'Configuration and privacy', slug: 'reference/configuration' },
        ] },
        { label: 'Troubleshooting', items: [
          { label: 'Capture and setup', slug: 'troubleshooting' },
        ] },
        { label: 'Releases', items: [
          { label: 'Versions and upgrades', slug: 'releases' },
        ] },
      ],
    }),
  ],
});
