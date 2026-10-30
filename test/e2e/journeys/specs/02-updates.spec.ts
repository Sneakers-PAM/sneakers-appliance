// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { need } from "@/env";
import { test } from "@/fixtures";
import { INSTALL_TIMEOUT_MS, installProduct } from "@/flows/appliance";
import { signedInToAppliance } from "@/session";
import { nextCode } from "@/state";

test("Updates: the product bundle uploaded, verified, staged and installed", async ({ page, shot }) => {
  test.setTimeout(INSTALL_TIMEOUT_MS + 45 * 60_000);
  await signedInToAppliance(page);
  await installProduct(
    page,
    need("JOURNEYS_PRODUCT_BUNDLE"),
    need("JOURNEYS_PRODUCT_VERSION"),
    () => nextCode("appliance"),
    shot,
  );
});
