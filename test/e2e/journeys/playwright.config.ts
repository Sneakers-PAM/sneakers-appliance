// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "@playwright/test";

/**
 * The sign-off journeys against one booted box (docs/testing.md#the-browser-journeys). They run
 * in order, one at a time, each on the state the one before left: first-run setup makes the
 * appliance admin, Updates installs the product, Email sets the relay the product's codes go
 * out through, and so on. Every journey keeps its trace and a screenshot of each step.
 */
export default defineConfig({
  expect: { timeout: 30_000 },
  forbidOnly: !!process.env.CI,
  fullyParallel: false,
  outputDir: "test-results",
  projects: [
    // The helpers the journeys stand on (the TOTP codes, reading the console), no box or browser.
    { name: "units", testDir: "units" },
    { dependencies: ["units"], name: "chromium", testDir: "specs", use: { browserName: "chromium" } },
  ],
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  retries: 0,
  timeout: 10 * 60_000,
  use: {
    acceptDownloads: true,
    actionTimeout: 60_000,
    headless: true,
    navigationTimeout: 2 * 60_000,
    // The driver's proxy to the box's address (test/image/journeys); unset, the journeys can't run.
    proxy: process.env.JOURNEYS_PROXY ? { server: process.env.JOURNEYS_PROXY } : undefined,
    screenshot: "on",
    trace: "on",
    viewport: { height: 900, width: 1440 },
  },
  workers: 1,
});
