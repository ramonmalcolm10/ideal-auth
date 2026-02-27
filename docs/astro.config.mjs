import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://ramonmalcolm10.github.io',
  base: '/ideal-auth',
  integrations: [
    starlight({
      title: 'ideal-auth',
      description: 'Auth primitives for the JS ecosystem. Zero framework dependencies.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/ramonmalcolm10/ideal-auth' },
      ],
      components: {
        SocialIcons: './src/components/SocialIcons.astro',
      },
      editLink: {
        baseUrl: 'https://github.com/ramonmalcolm10/ideal-auth/edit/main/docs/',
      },
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { slug: 'getting-started' },
            { slug: 'configuration' },
            { slug: 'troubleshooting' },
          ],
        },
        {
          label: 'Framework Guides',
          autogenerate: { directory: 'frameworks' },
        },
        {
          label: 'Guides',
          autogenerate: { directory: 'guides' },
        },
        {
          label: 'Security',
          autogenerate: { directory: 'security' },
        },
        {
          label: 'Migration',
          autogenerate: { directory: 'migration' },
        },
        {
          label: 'API Reference',
          autogenerate: { directory: 'api' },
        },
      ],
    }),
  ],
});
