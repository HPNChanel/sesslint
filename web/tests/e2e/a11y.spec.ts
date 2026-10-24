import AxeBuilder from "@axe-core/playwright";
import { ALL, expect, test } from "./fixtures";

for (const scheme of ["dark", "light"] as const) {
  for (const path of ALL) {
    test(`axe: /${path} (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await page.goto(path);
      const { violations } = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
      const serious = violations.filter((v) => v.impact === "serious" || v.impact === "critical");
      expect(
        serious.map((v) => `${v.id}: ${v.nodes.length}× ${v.nodes[0]?.target.join(" ")}`),
        `/${path}`,
      ).toEqual([]);
    });
  }
}
