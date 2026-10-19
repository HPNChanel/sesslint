// Locale plumbing. English lives at the root, Vietnamese under /vi/.
// Pages are thin wrappers that pass `lang` to a shared view.
import { en, type Dict } from "./en";
import { vi } from "./vi";

export const LANGS = ["en", "vi"] as const;
export type Lang = (typeof LANGS)[number];

const DICTS: Record<Lang, Dict> = { en, vi };

export function t(lang: Lang): Dict {
  return DICTS[lang];
}

export const HTML_LANG: Record<Lang, string> = { en: "en", vi: "vi" };

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

/** Absolute site path for `path` ("/pricing") in `lang`, honouring the base. */
export function href(lang: Lang, path = "/"): string {
  const clean = path.startsWith("/") ? path : `/${path}`;
  const localized = lang === "en" ? clean : `/vi${clean === "/" ? "/" : clean}`;
  return `${BASE}${localized}`;
}

/** Base-relative URL for a non-localized asset or route (feeds, docs). */
export function asset(path: string): string {
  return `${BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

/** Strip base and locale prefix: "/sesslint/vi/pricing/" → "/pricing/". */
export function routeOf(pathname: string): string {
  let p = pathname;
  if (BASE && p.startsWith(BASE)) p = p.slice(BASE.length);
  if (p === "/vi" || p.startsWith("/vi/")) p = p.slice(3);
  return p || "/";
}

export function other(lang: Lang): Lang {
  return lang === "en" ? "vi" : "en";
}

const DATE_LOCALE: Record<Lang, string> = { en: "en-US", vi: "vi-VN" };

export function formatDate(lang: Lang, iso: string): string {
  return new Intl.DateTimeFormat(DATE_LOCALE[lang], {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(new Date(`${iso}T00:00:00Z`));
}
