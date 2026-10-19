// SessLint marketing site. Static output only: no server, no adapters.
// SITE_URL / SITE_BASE let the same build target GitHub Pages
// (https://hpnchanel.github.io/sesslint) or a custom domain later.
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

const site = process.env.SITE_URL ?? "https://hpnchanel.github.io";
const base = process.env.SITE_BASE ?? "/sesslint";

export default defineConfig({
  site,
  base,
  trailingSlash: "ignore",
  output: "static",
  build: { format: "directory" },
  integrations: [
    sitemap({
      i18n: { defaultLocale: "en", locales: { en: "en-US", vi: "vi-VN" } },
    }),
  ],
  devToolbar: { enabled: false },
});
