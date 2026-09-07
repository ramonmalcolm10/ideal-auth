import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import nimbus, {
  defineConfig as defineNimbusConfig,
} from "@cloudflare/nimbus-docs";
import { tableScroll } from "@cloudflare/nimbus-docs/markdown";

const nimbusConfig = defineNimbusConfig({
  // GitHub Pages *project* site, so the canonical origin carries the repo
  // path — it drives canonical URLs, absolute OG image URLs, robots.txt, the
  // sitemap and the links in /llms.txt, all of which must resolve under
  // /ideal-auth.
  site: "https://ramonmalcolm10.github.io/ideal-auth",
  title: "ideal-auth",
  description:
    "Auth primitives for the JS ecosystem. Zero framework dependencies.",
  locale: "en",
  github: "https://github.com/ramonmalcolm10/ideal-auth",
  socialImageAlt: "ideal-auth documentation",
  sidebar: {
    items: [
      { label: "Getting started", link: "/getting-started" },
      { label: "Configuration", link: "/configuration" },
      { label: "Troubleshooting", link: "/troubleshooting" },
      { label: "Framework guides", autogenerate: { directory: "frameworks" } },
      { label: "Guides", autogenerate: { directory: "guides" } },
      { label: "Security", autogenerate: { directory: "security" } },
      { label: "Migration", autogenerate: { directory: "migration" } },
      { label: "API reference", autogenerate: { directory: "api" } },
    ],
  },
});

export default defineConfig({
  // nimbus:adapter
  output: "static",
  // Split across site + base because this is a project site: Astro needs the
  // bare origin plus the sub-path, while Nimbus wants the full canonical
  // origin above. Sub-path support is what kept these docs on Starlight —
  // nimbus-docs <=0.11 dropped `base` from sidebar links, the favicon and
  // shiki.css (cloudflare/nimbus#105, fixed in #112/#114).
  site: "https://ramonmalcolm10.github.io",
  base: "/ideal-auth",
  // Tailwind v4 via its Vite plugin (the integration Astro recommends for
  // Tailwind v4 — replaces the PostCSS plugin, which doesn't build under
  // Astro 7's Vite 8 bundler).
  vite: {
    plugins: [tailwindcss()],
  },
  // Replaces the ClientRouter the Starlight build injected through a custom
  // Head override: hover-prefetch makes full-page navigation feel instant
  // without shipping a client-side router.
  prefetch: {
    prefetchAll: true,
    defaultStrategy: "hover",
  },
  integrations: [
    nimbus(nimbusConfig, {
      rules: {
        "nimbus/frontmatter-shape": "error",
        "nimbus/internal-link": "error",
      },
      markdown: {
        hastPlugins: [tableScroll()],
      },
    }),
  ],
});
