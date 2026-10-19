// Relative release ages ("26 days ago") computed in the browser so the
// static build stays byte-deterministic.
export function initAgo() {
  const now = Date.now();
  for (const el of document.querySelectorAll<HTMLTimeElement>("time[data-ago]")) {
    const iso = el.getAttribute("datetime");
    if (!iso) continue;
    const days = Math.round((Date.parse(`${iso}T00:00:00Z`) - now) / 86_400_000);
    const lang = el.dataset.ago === "vi" ? "vi" : "en";
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
    const abs = Math.abs(days);
    el.textContent =
      abs < 31 ? rtf.format(days, "day") : abs < 365 ? rtf.format(Math.round(days / 30), "month") : rtf.format(Math.round(days / 365), "year");
    el.title = iso;
  }
}
