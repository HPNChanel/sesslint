// Best-effort OS/arch detection for the Download page. Uses UA Client Hints
// where available (Chromium), falls back to the UA string. Only ever used to
// highlight a binary; every option stays visible.
export type Platform = { os: "linux" | "macos" | "windows"; label: string; arch: string | null };

type UAData = {
  platform?: string;
  getHighEntropyValues?: (hints: string[]) => Promise<{ architecture?: string; bitness?: string }>;
};

const LABELS = { linux: "Linux", macos: "macOS", windows: "Windows" } as const;

function osFrom(s: string): Platform["os"] | null {
  const v = s.toLowerCase();
  if (/android|iphone|ipad/.test(v)) return null;
  if (v.includes("win")) return "windows";
  if (v.includes("mac")) return "macos";
  if (v.includes("linux") || v.includes("x11")) return "linux";
  return null;
}

export async function detectPlatform(): Promise<Platform | null> {
  const nav = navigator as Navigator & { userAgentData?: UAData };
  const ua = nav.userAgentData;
  const os = osFrom(ua?.platform || navigator.userAgent);
  if (!os) return null;
  let arch: string | null = null;
  try {
    const hi = await ua?.getHighEntropyValues?.(["architecture", "bitness"]);
    if (hi?.architecture === "arm") arch = "arm64";
    else if (hi?.architecture === "x86") arch = hi.bitness === "32" ? "x86" : "x86_64";
  } catch {
    // Hints unavailable or denied; the OS alone is enough.
  }
  return { os, label: LABELS[os], arch };
}
