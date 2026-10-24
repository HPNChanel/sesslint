// SessLint marketing site. Static output only: no server, no adapters.
// SITE_URL (see site.config.mjs) targets GitHub Pages or a custom domain.
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import { siteLocation } from "./site.config.mjs";

const { origin: site, base } = siteLocation();

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
