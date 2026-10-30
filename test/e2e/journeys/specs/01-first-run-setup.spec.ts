// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { checkedCertificate, spkiPinOf } from "@/certificate";
import { attachConsole, SETUP_CODE_ON_CONSOLE, waitForConsole } from "@/console";
import { adminUrl, boxAddress } from "@/env";
import { expect, openWhenUp, test } from "@/fixtures";
import { answerStepUps, firstRunSetup, signInToAppliance } from "@/flows/appliance";
import { newPassword, nextCode, saveAccount } from "@/state";

const escaped = (s: string) => s.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("first-run setup on :8443, then the first sign-in once the box restarts", async ({ boxPin, page, shot }, testInfo) => {
  test.setTimeout(25 * 60_000);
  const admin = "journeys";
  const password = newPassword();

  const code = await test.step("the console shows the setup page, its certificate and a setup code", async () => {
    await waitForConsole(new RegExp(`Open this address in your browser: .*https://${escaped(boxAddress())}:8443`), 10 * 60_000);
    const match = await waitForConsole(SETUP_CODE_ON_CONSOLE, 3 * 60_000);
    await attachConsole(testInfo, "first boot");
    return match[1] ?? "";
  });

  await test.step("the :8443 certificate is the one the console shows", async () => {
    expect(spkiPinOf(await checkedCertificate(8443))).toBe(boxPin);
  });

  await test.step("the six setup steps", async () => {
    await openWhenUp(page, adminUrl("/setup"), 2 * 60_000);
    // A step-up (making the recovery key) is answered from the authenticator the admin
    // step sets up.
    await answerStepUps(page, () => nextCode("appliance"));
    await firstRunSetup(page, {
      admin,
      after: shot,
      code,
      onSecret: (secret) => {
        saveAccount("appliance", { lastStep: 0, name: admin, password, secret });
        return () => nextCode("appliance");
      },
      password,
    });
    await shot("the box restarts");
  });

  await test.step("the box restarts into normal operation", async () => {
    await waitForConsole(/Health /, 15 * 60_000);
    await waitForConsole(new RegExp(`Admin https://${escaped(boxAddress())}:8443`), 5 * 60_000);
    await attachConsole(testInfo, "normal operation");
    expect(spkiPinOf(await checkedCertificate(8443)), "the certificate is kept across the restart").toBe(boxPin);
  });

  await test.step("the first sign-in", async () => {
    await openWhenUp(page, adminUrl("/"), 5 * 60_000);
    await signInToAppliance(page, admin, password, () => nextCode("appliance"));
    await shot("signed in");
  });
});
