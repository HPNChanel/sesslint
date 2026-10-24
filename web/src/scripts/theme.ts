// Theme: follows the OS until the visitor picks one; the choice is a
// per-viewer convenience in localStorage (guarded: storage may be blocked).
type Theme = "light" | "dark";

function systemTheme(): Theme {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function currentTheme(): Theme {
  const t = document.documentElement.dataset.theme;
  return t === "light" || t === "dark" ? t : systemTheme();
}

function label() {
  const stored = document.documentElement.dataset.theme;
  for (const el of document.querySelectorAll<HTMLElement>("[data-theme-label]")) {
    el.textContent = stored ? `theme:${stored}` : `theme:auto(${systemTheme()})`;
  }
}

export function toggleTheme() {
  const next: Theme = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem("sl-theme", next);
  } catch {
    /* storage unavailable: theme still applies for this page */
  }
  label();
}

export function initTheme() {
  label();
  for (const b of document.querySelectorAll("[data-theme-toggle]")) b.addEventListener("click", toggleTheme);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", label);
}
