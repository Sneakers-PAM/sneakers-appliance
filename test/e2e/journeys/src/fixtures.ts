// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { test as base, expect, type Page } from "@playwright/test";

import { settledCertificate, spkiPinOf } from "@/certificate";

export { expect };

/** Takes a full-page screenshot into the journey's report, numbered in step order. */
export type Shot = (name: string) => Promise<void>;

/**
 * What the screenshots hide: the authenticator keys and QR codes, the setup token and the other
 * one-line values the pages print in code. They're the run's own throwaway values for a box
 * that only exists inside the run, but a screenshot needn't carry them.
 */
const secrets = (page: Page) => [page.locator("code"), page.locator("svg:has(> title)")];

export const test = base.extend<{ shot: Shot }, { boxPin: string }>({
  /**
   * The box's own certificate, trusted the way its admin trusts it: fetched from :8443, its
   * fingerprint checked against the one the console shows (once the two have settled), then
   * its key pinned. The browser takes that one key and nothing else (Chromium's
   * --ignore-certificate-errors-spki-list, for the pinned SPKI only); every other certificate
   * is checked as usual.
   */
  boxPin: [
    async ({}, use) => {
      await use(spkiPinOf(await settledCertificate(8443)));
    },
    { scope: "worker", timeout: 8 * 60_000 },
  ],
  launchOptions: [
    async ({ boxPin, launchOptions }, use) => {
      await use({
        ...launchOptions,
        args: [...(launchOptions.args ?? []), `--ignore-certificate-errors-spki-list=${boxPin}`],
      });
    },
    { scope: "worker" },
  ],
  shot: async ({ page }, use, testInfo) => {
    let n = 0;
    await use(async (name) => {
      n += 1;
      await testInfo.attach(`${String(n).padStart(2, "0")} ${name}`, {
        body: await page.screenshot({ fullPage: true, mask: secrets(page) }),
        contentType: "image/png",
      });
    });
  },
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Opens a page once the box answers it: after a restart the port is closed for a while. */
export const openWhenUp = async (page: Page, url: string, timeoutMs: number): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const response = await page.goto(url, { timeout: 30_000 });
      if (response?.ok()) return;
    } catch (error) {
      if (Date.now() > deadline) throw error;
    }
    if (Date.now() > deadline) throw new Error(`${url} didn't answer in ${String(timeoutMs / 1000)}s`);
    await sleep(5000);
  }
};
