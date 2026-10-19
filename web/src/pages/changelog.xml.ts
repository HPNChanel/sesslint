// Atom feed of released versions, built from CHANGELOG.md.
import type { APIRoute } from "astro";
import { released } from "../lib/changelog";
import { escapeHtml, inline } from "../lib/markdown";
import { site } from "../lib/site";

export const GET: APIRoute = ({ site: origin }) => {
  const base = new URL(import.meta.env.BASE_URL, origin ?? "https://hpnchanel.github.io");
  const rels = released(site().releases);
  const updated = rels[0]?.date ? `${rels[0].date}T00:00:00Z` : "1970-01-01T00:00:00Z";
  const entries = rels
    .map((r) => {
      const url = new URL(`changelog/${r.version}/`, base).toString();
      const html = r.sections
        .map((s) => `<h3>${s.kind}</h3><ul>${s.entries.map((e) => `<li>${inline(e.markdown)}</li>`).join("")}</ul>`)
        .join("");
      return `  <entry>
    <id>${url}</id>
    <title>SessLint v${r.version}</title>
    <link href="${url}"/>
    <updated>${r.date ?? "1970-01-01"}T00:00:00Z</updated>
    <content type="html">${escapeHtml(html)}</content>
  </entry>`;
    })
    .join("\n");
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${new URL("changelog/", base).toString()}</id>
  <title>SessLint changelog</title>
  <link href="${new URL("changelog/", base).toString()}"/>
  <link rel="self" href="${new URL("changelog.xml", base).toString()}"/>
  <updated>${updated}</updated>
${entries}
</feed>
`;
  return new Response(xml, { headers: { "Content-Type": "application/atom+xml; charset=utf-8" } });
};
