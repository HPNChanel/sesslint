// Clipboard with visible, announced feedback: "copied ✓ (exit 0)".
let live: HTMLElement | null = null;

function announce(msg: string) {
  if (!live) {
    live = document.createElement("div");
    live.className = "sr-only";
    live.setAttribute("aria-live", "polite");
    document.body.append(live);
  }
  live.textContent = msg;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.append(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    ta.remove();
    return ok;
  }
}

/** Delegated handler for any `[data-copy]` button. */
export function initCopy() {
  document.addEventListener("click", async (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("[data-copy]");
    if (!btn) return;
    const text = btn.dataset.copy ?? "";
    const ok = await copyText(text);
    const msg = ok ? (btn.dataset.copied ?? "copied") : (btn.dataset.copyFailed ?? "copy failed");
    const label = btn.querySelector<HTMLElement>("[data-copy-label]") ?? btn;
    const prev = label.dataset.original ?? label.textContent ?? "";
    label.dataset.original = prev;
    label.textContent = msg;
    btn.classList.toggle("is-copied", ok);
    announce(msg);
    window.setTimeout(() => {
      label.textContent = prev;
      btn.classList.remove("is-copied");
    }, 1800);
  });
}
