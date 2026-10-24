// Atom feed of released versions, built from CHANGELOG.md.
import type { APIRoute } from "astro";
import { released } from "../lib/changelog";
import { escapeHtml, inline } from "../lib/markdown";
import { site } from "../lib/site";
import { absolute, asset } from "../i18n";

export const GET: APIRoute = () => {
  const rels = released(site().releases);
  const updated = rels[0]?.date ? `${rels[0].date}T00:00:00Z` : "1970-01-01T00:00:00Z";
  const entries = rels
    .map((r) => {
      const url = absolute(asset(`/changelog/${r.version}/`));
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
  <id>${absolute(asset("/changelog/"))}</id>
  <title>SessLint changelog</title>
  <link href="${absolute(asset("/changelog/"))}"/>
  <link rel="self" href="${absolute(asset("/changelog.xml"))}"/>
  <updated>${updated}</updated>
${entries}
</feed>
`;
  return new Response(xml, { headers: { "Content-Type": "application/atom+xml; charset=utf-8" } });
};
