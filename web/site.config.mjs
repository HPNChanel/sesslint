// Where the site is served. One setting, SITE_URL, is the full public URL:
//   https://hpnchanel.github.io/sesslint   GitHub Pages project URL (default)
//   https://sesslint.example               custom domain served at the root
// Astro's site/base, the e2e server, the Playwright baseURL and the docs URL
// all derive from it, so moving to a custom domain changes no code.
export const DEFAULT_SITE_URL = "https://hpnchanel.github.io/sesslint";

/**
 * @param {Record<string, string | undefined>} [env]
 * @returns {{ url: string, origin: string, base: string, prefix: string }}
 *   base is Astro's `base` ("/" at a domain root); prefix is the same path
 *   without a trailing slash ("" at a domain root).
 */
export function siteLocation(env = process.env) {
  const raw = env.SITE_URL?.trim() || DEFAULT_SITE_URL;
  const url = new URL(raw);
  if (url.protocol !== "https:" && url.hostname !== "localhost") {
    throw new Error(`SITE_URL must be https: ${raw}`);
  }
  const prefix = url.pathname.replace(/\/+$/, "");
  return { url: `${url.origin}${prefix}`, origin: url.origin, base: prefix || "/", prefix };
}
