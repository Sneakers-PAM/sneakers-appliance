// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { boxAddress } from "@/env";
import { test } from "@/fixtures";
import { checkNetwork } from "@/flows/appliance";
import { signedInToAppliance } from "@/session";

test("Network: the box's address, and the checks for its link and address", async ({ page, shot }) => {
  await signedInToAppliance(page);
  await checkNetwork(page, boxAddress());
  await shot("the network checks");
});
