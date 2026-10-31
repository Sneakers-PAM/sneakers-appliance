// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@/fixtures";
import { notAvailable } from "@/flows/appliance";
import { signedInToAppliance } from "@/session";

/** What the box does today: BackupService answers "Not available in this release". */
const NOT_YET = "the box serves BackupService as not available in this release";

test("Backups: the page, then a backup run and its set", async ({ page, shot }) => {
  test.setTimeout(20 * 60_000);
  await signedInToAppliance(page);
  await page.getByRole("complementary", { name: "Sidebar" }).getByRole("link", { exact: true, name: "Backups" }).click();
  const unavailable = notAvailable(page, "Backups");
  await expect(unavailable.or(page.getByRole("heading", { level: 1, name: "Backups" }))).toBeVisible();
  await shot("the Backups page");
  test.skip(await unavailable.isVisible(), NOT_YET);

  const sets = page.getByRole("table").filter({ has: page.getByRole("columnheader", { name: "Taken" }) });
  const before = await sets.getByRole("row").count();
  await page.getByRole("button", { name: "Run now" }).click();
  await expect.poll(() => sets.getByRole("row").count(), { timeout: 15 * 60_000 }).toBeGreaterThan(before);
  await shot("the new backup set");
});
