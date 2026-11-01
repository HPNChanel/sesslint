// Atom feed of released versions, built from CHANGELOG.md.
import type { APIRoute } from "astro";
import { escapeHtml, inline } from "../lib/markdown";
import { publishedSite, site } from "../lib/site";
import { absolute, asset } from "../i18n";

export const GET: APIRoute = async () => {
  const publication = await publishedSite();
  const published = new Map(publication.releases.map((release) => [release.version, release]));
  const rels = site().releases.filter((r) => !r.unreleased && published.has(r.version));
  const updated = published.get(rels[0]?.version ?? "")?.publishedAt ?? "1970-01-01T00:00:00Z";
  const entries = rels
    .map((r) => {
      const url = absolute(asset(`/changelog/${r.version}/`));
      const html = r.sections
        .map((s) => `<h3>${s.kind}</h3><ul>${s.entries.map((e) => `<li>${inline(e.markdown)}</li>`).join("")}</ul>`)
        .join("");
      const publishedAt = published.get(r.version)?.publishedAt ?? "1970-01-01T00:00:00Z";
      return `  <entry>
    <id>${url}</id>
    <title>SessLint v${r.version}</title>
    <link href="${url}"/>
    <updated>${publishedAt}</updated>
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
