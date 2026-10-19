// robots.txt follows SITE_URL/SITE_BASE so a custom domain needs no edit.
import type { APIRoute } from "astro";
import { asset } from "../i18n";

export const GET: APIRoute = ({ site }) => {
  const origin = site ?? new URL("https://hpnchanel.github.io");
  const body = [
    "User-agent: *",
    "Allow: /",
    `Disallow: ${asset("/checkout/")}`,
    `Disallow: ${asset("/vi/checkout/")}`,
    `Sitemap: ${new URL(asset("/sitemap-index.xml"), origin).toString()}`,
    "",
  ].join("\n");
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
};
