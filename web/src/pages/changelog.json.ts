// JSON Feed 1.1 of released versions, built from CHANGELOG.md.
import type { APIRoute } from "astro";
import { released } from "../lib/changelog";
import { inline } from "../lib/markdown";
import { site } from "../lib/site";
import { absolute, asset } from "../i18n";

export const GET: APIRoute = () => {
  const items = released(site().releases).map((r) => ({
    id: `sesslint-v${r.version}`,
    url: absolute(asset(`/changelog/${r.version}/`)),
    title: `SessLint v${r.version}`,
    date_published: r.date ? `${r.date}T00:00:00Z` : undefined,
    content_html: r.sections
      .map((s) => `<h3>${s.kind}</h3><ul>${s.entries.map((e) => `<li>${inline(e.markdown)}</li>`).join("")}</ul>`)
      .join(""),
    _sesslint: { hash: r.hash, prev: r.prev },
  }));
  const feed = {
    version: "https://jsonfeed.org/version/1.1",
    title: "SessLint changelog",
    home_page_url: absolute(asset("/changelog/")),
    feed_url: absolute(asset("/changelog.json")),
    items,
  };
  return new Response(`${JSON.stringify(feed, null, 2)}\n`, {
    headers: { "Content-Type": "application/feed+json; charset=utf-8" },
  });
};
