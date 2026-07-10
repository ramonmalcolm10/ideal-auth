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
        Head: './src/components/Head.astro',
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
          items: [{ autogenerate: { directory: 'frameworks' } }],
        },
        {
          label: 'Guides',
          items: [{ autogenerate: { directory: 'guides' } }],
        },
        {
          label: 'Security',
          items: [{ autogenerate: { directory: 'security' } }],
        },
        {
          label: 'Migration',
          items: [{ autogenerate: { directory: 'migration' } }],
        },
        {
          label: 'API Reference',
          items: [{ autogenerate: { directory: 'api' } }],
        },
      ],
    }),
  ],
});
