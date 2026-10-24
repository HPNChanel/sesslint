import { test as base, expect } from "@playwright/test";

/** Every page, both locales. Paths are relative to the site base. */
export const ROUTES = ["", "download/", "pricing/", "checkout/?tier=max&own=plus", "changelog/", "rules/"] as const;
export const ALL = ROUTES.flatMap((r) => [r, `vi/${r}`]);

/**
 * The live-release ribbon is the site's only third-party request. Stub it so
 * tests never touch the network; `latestTag` lets a test simulate a release
 * newer than the build.
 */
export const test = base.extend<{ latestTag: string | null; stubGithub: void; errors: string[] }>({
  latestTag: [null, { option: true }],
  stubGithub: [
    async ({ page, latestTag }, use) => {
      const tag = latestTag ?? "v0.0.0";
      await page.route("https://api.github.com/**", (route) =>
        route.fulfill({ json: { tag_name: tag, html_url: `https://github.com/HPNChanel/sesslint/releases/tag/${tag}` } }),
      );
      await use();
    },
    { auto: true },
  ],
  errors: async ({ page }, use) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });
    await use(errors);
  },
});

export { expect };
