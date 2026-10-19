// <sl-tabs>: WAI-ARIA tabs (automatic activation, roving tabindex). Markup is
// server-rendered with role=tab/tabpanel; this only wires selection and keys.
class Tabs extends HTMLElement {
  connectedCallback() {
    const tabs = Array.from(this.querySelectorAll<HTMLElement>("[role=tab]"));
    const select = (tab: HTMLElement, focus = false) => {
      for (const t of tabs) {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        const panel = document.getElementById(t.getAttribute("aria-controls") ?? "");
        if (panel) panel.hidden = !on;
      }
      if (focus) tab.focus();
    };
    for (const t of tabs) {
      t.addEventListener("click", () => select(t));
      t.addEventListener("keydown", (e) => {
        const i = tabs.indexOf(t);
        const keys: Record<string, number> = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 };
        const next = keys[e.key];
        if (next === undefined) return;
        e.preventDefault();
        const tab = tabs[(next + tabs.length) % tabs.length];
        if (tab) select(tab, true);
      });
    }
  }
}

if (!customElements.get("sl-tabs")) customElements.define("sl-tabs", Tabs);
