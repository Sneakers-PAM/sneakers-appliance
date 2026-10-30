// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@/fixtures";
import { sendTestEmail, setMailRelay } from "@/flows/appliance";
import { relay, waitForMail } from "@/mail";
import { signedInToAppliance } from "@/session";

/** Addresses on the reserved example domain: nothing outside the run ever sees them. */
const FROM = "sneakers@example.org";
const TO = "owner@example.org";

test("Email: the relay set with STARTTLS and its CA, and a test email that arrives", async ({ page, shot }) => {
  test.setTimeout(20 * 60_000);
  await signedInToAppliance(page);
  const { ca, host, port } = relay();
  await setMailRelay(page, { ca, from: FROM, host, port });
  await shot("the relay saved");
  const sent = new Date(Date.now() - 5000);
  await sendTestEmail(page, TO);
  await shot("the test sent");
  const mail = await waitForMail(TO, sent);
  expect(mail.subject.length, "the test email's subject").toBeGreaterThan(0);
});
