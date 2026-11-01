/** Build-time navigation only. This URL never grants rights or enables checkout. */
export function accountUrl(raw: string | undefined): string | null {
  if (!raw?.trim()) return null;
  let url: URL;
  try { url = new URL(raw.trim()); } catch { throw new Error("PUBLIC_ACCOUNT_URL must be an absolute HTTPS account URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || !["/", "/account", "/account/"].includes(url.pathname)) {
    throw new Error("PUBLIC_ACCOUNT_URL must use HTTPS and /account without credentials, query or fragment");
  }
  return `${url.origin}/account`;
}
