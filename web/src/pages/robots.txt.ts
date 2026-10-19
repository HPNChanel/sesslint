// robots.txt follows SITE_URL (site.config.mjs) so a custom domain needs no edit.
import type { APIRoute } from "astro";
import { absolute, asset } from "../i18n";

export const GET: APIRoute = () => {
  const body = [
    "User-agent: *",
    "Allow: /",
    `Disallow: ${asset("/checkout/")}`,
    `Disallow: ${asset("/vi/checkout/")}`,
    `Sitemap: ${absolute(asset("/sitemap-index.xml"))}`,
    "",
  ].join("\n");
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
};
