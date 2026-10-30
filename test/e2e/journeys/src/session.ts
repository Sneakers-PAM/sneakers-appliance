// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import type { Page } from "@playwright/test";

import { adminUrl } from "@/env";
import { openWhenUp } from "@/fixtures";
import { answerStepUps, signInToAppliance } from "@/flows/appliance";
import { account, nextCode } from "@/state";

/**
 * A journey's start on :8443: the sign-in with the admin first-run setup made, and every
 * step-up the journey meets answered with a fresh code.
 */
export const signedInToAppliance = async (page: Page): Promise<void> => {
  const admin = account("appliance");
  const code = () => nextCode("appliance");
  await openWhenUp(page, adminUrl("/"), 5 * 60_000);
  await signInToAppliance(page, admin.name, admin.password, code);
  await answerStepUps(page, code);
};
