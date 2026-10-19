// Inline markdown for changelog entries. Raw HTML in the source is shown as
// text (e.g. `<source>` placeholders), never interpreted.
import { Marked } from "marked";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ESC[c] ?? c);
}

const md = new Marked({
  gfm: true,
  async: false,
  renderer: {
    html: ({ text }) => escapeHtml(text),
  },
});

export function inline(markdown: string): string {
  return md.parseInline(markdown) as string;
}
