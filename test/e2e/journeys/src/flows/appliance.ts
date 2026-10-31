// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";

/** A source of authenticator codes, each from a step the box hasn't seen yet. */
export type Codes = () => Promise<string>;

/**
 * The step-up prompt every sensitive :8443 action shares ("Confirm it's you"). Registered once
 * per page, it answers the prompt with a fresh code whenever it appears, as the admin would.
 */
export const answerStepUps = async (page: Page, code: Codes): Promise<void> => {
  const prompt = page.getByRole("dialog", { name: "Confirm it's you" });
  await page.addLocatorHandler(prompt, async () => {
    await prompt.getByLabel("Authenticator code").first().fill(await code());
    await prompt.getByRole("button", { name: "Verify code" }).click();
    await expect(prompt).toBeHidden({ timeout: 60_000 });
  });
};

/** Opens a page from the admin's sidebar, as a person clicks through. */
export const openFromSidebar = async (page: Page, name: string): Promise<void> => {
  await page.getByRole("complementary", { name: "Sidebar" }).getByRole("link", { exact: true, name }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
};

/** Signs in on the :8443 sign-in page with the name, the password and a code. */
export const signInToAppliance = async (
  page: Page,
  admin: string,
  password: string,
  code: Codes,
): Promise<void> => {
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Admin name").fill(admin);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByLabel("Authenticator code").first().fill(await code());
  await page.getByRole("button", { exact: true, name: "Sign in" }).click();
  await page.waitForURL("**/home");
  await expect(page.getByRole("heading", { level: 1, name: "Status" })).toBeVisible();
};

/** The first-run setup's steps, in the order the stepper shows them. */
export interface SetupSteps {
  /** After each step, with its name: the journey takes its screenshot there. */
  after: (step: string) => Promise<void>;
  admin: string;
  /** The setup code the console shows. */
  code: string;
  /** Called with the authenticator secret the box hands out; answers codes for it from then on. */
  onSecret: (secret: string) => Codes;
  password: string;
}

/**
 * Step 1 to 6 of the :8443 setup page: the console's code, the first admin's name, password and
 * authenticator, a recovery key the box makes, the network and protection the box chose, then
 * one sign-in and Finish. Answers once the page says the box is restarting.
 */
export const firstRunSetup = async (page: Page, steps: SetupSteps): Promise<void> => {
  await expect(page.getByRole("heading", { name: /^Step 1 of 6/ })).toBeVisible();
  await page.getByLabel("Setup code").fill(steps.code);
  await page.getByRole("button", { name: "Continue" }).click();
  await steps.after("the setup code");

  await expect(page.getByRole("heading", { name: "Step 2 of 6: Create the first admin" })).toBeVisible();
  await page.getByLabel("Admin name").fill(steps.admin);
  await page.getByLabel("Password", { exact: true }).fill(steps.password);
  await page.getByLabel("Password again", { exact: true }).fill(steps.password);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Step 2 of 6: Add your authenticator" })).toBeVisible();
  const key = page.getByText("Can't scan? Type this key:").locator("xpath=following-sibling::code[1]");
  const code = steps.onSecret((await key.innerText()).replaceAll(/\s/g, ""));
  await steps.after("the authenticator");
  await page.getByLabel("6-digit code from the app").first().fill(await code());
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: /^Step 3 of 6/ })).toBeVisible();
  const generate = page.getByRole("form", { name: "Generate a recovery key" });
  await generate.getByLabel("Label").fill("journeys");
  const download = page.waitForEvent("download");
  await generate.getByRole("button", { name: "Generate a key pair" }).click();
  await download;
  await expect(page.getByText("Save the private key now")).toBeVisible();
  await page.getByRole("button", { name: "I saved it" }).click();
  await expect(page.getByRole("list", { name: "Recovery keys" }).getByRole("listitem")).toHaveCount(1);
  await steps.after("a recovery key");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: /^Step 4 of 6/ })).toBeVisible();
  await expect(page.getByText("These are the settings the box has now.")).toBeVisible();
  await steps.after("the network");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: /^Step 5 of 6/ })).toBeVisible();
  await expect(page.getByText("The box chose this from its hardware.")).toBeVisible();
  await steps.after("the protection");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: /^Step 6 of 6/ })).toBeVisible();
  const single = page.getByRole("checkbox", { name: "I understand. Go on with one admin." });
  if (await single.isVisible()) await single.check();
  await expect(page.getByLabel("Admin name")).toHaveValue(steps.admin);
  await page.getByLabel("Password", { exact: true }).fill(steps.password);
  await page.getByLabel("Authenticator code").first().fill(await code());
  await steps.after("sign in and finish");
  await page.getByRole("button", { name: "Sign in and finish" }).click();
  await expect(page.getByText("Setup is closed. The box restarts into normal operation")).toBeVisible({
    timeout: 60_000,
  });
};

/** How long a product install may take: the box imports every image, then waits for each phase. */
export const INSTALL_TIMEOUT_MS = 30 * 60_000;

/**
 * The Updates page: updates apply only when an owner applies them (so the daily window can't
 * apply what the journey stages first), the product bundle uploaded under Install an update,
 * verified and staged, then applied with its version typed and a fresh code, until the
 * Product card shows it running.
 */
export const installProduct = async (
  page: Page,
  bundle: string,
  version: string,
  code: Codes,
  after: (step: string) => Promise<void>,
): Promise<void> => {
  await openFromSidebar(page, "Updates");
  const manual = page.getByRole("radiogroup", { name: "When updates apply" }).getByRole("radio", { name: "Manual only" });
  await manual.click();
  await page.getByRole("button", { name: "Save update window" }).click();
  await expect(manual).toBeChecked();
  await expect(page.getByText("Manual only: an owner applies each update.")).toBeVisible();
  await after("updates apply by hand");

  await page.getByLabel("Update .bin file").setInputFiles(bundle);
  await page.getByRole("button", { exact: true, name: "Upload" }).click();
  const result = page.getByRole("region", { name: "Verify result" });
  await expect(result.getByText("Not checked yet")).toBeVisible({ timeout: 20 * 60_000 });
  await after("the bundle uploaded");
  await result.getByRole("button", { name: "Verify and stage" }).click();
  await expect(result.getByText("Verified", { exact: true })).toBeVisible({ timeout: 20 * 60_000 });
  await expect(result.getByText("Verified against this appliance's release key")).toBeVisible();
  await after("verified and staged");

  const product = page.getByRole("region", { name: "Product" });
  await product.getByRole("button", { name: "Apply update" }).click();
  const confirm = page.getByRole("dialog", { name: "Install the product update" });
  await confirm.getByLabel(`Type ${version} to confirm`).fill(version);
  await confirm.getByLabel("Authenticator code").first().fill(await code());
  await after("install confirmed");
  await confirm.getByRole("button", { name: "Install and restart the product" }).click();

  // The install's steps show on the Product card while it runs (k0s, the images, each phase,
  // the health check, 443) and go once it's done; a failed one stays, saying so.
  const progress = product.getByRole("region", { name: "Update progress" });
  const failed = product.getByText("The last update didn't finish");
  await expect(progress).toBeVisible({ timeout: 2 * 60_000 });
  await after("the install under way");
  await expect
    .poll(async () => (await progress.isVisible()) && !(await failed.isVisible()), {
      intervals: [5000],
      message: "the install's steps on the Product card",
      timeout: INSTALL_TIMEOUT_MS,
    })
    .toBe(false);
  await expect(failed).toBeHidden();
  await expect(progress).toBeHidden();
  await expect(product.getByText("running", { exact: true })).toBeVisible();
  const applied = page
    .getByRole("table", { name: "Update history" })
    .getByRole("row")
    .filter({ hasText: version })
    .filter({ hasNotText: /\bstage\b/ })
    .first();
  await expect(applied).toContainText("ok");
  await after("the product running");
};

/** The Email page's relay: the host, port and From, STARTTLS with the certificate checked against a CA. */
export interface Relay {
  ca: string;
  from: string;
  host: string;
  port: string;
}

/** Sets the product's mail relay on the Email page and saves it, which applies the product again. */
export const setMailRelay = async (page: Page, { ca, from, host, port }: Relay): Promise<void> => {
  await openFromSidebar(page, "Email");
  await page.getByLabel("Relay host", { exact: true }).fill(host);
  await page.getByLabel("Port", { exact: true }).fill(port);
  await page.getByLabel("From address", { exact: true }).fill(from);
  await page.getByRole("radiogroup", { name: "TLS" }).getByRole("radio", { name: "STARTTLS" }).click();
  await expect(page.getByRole("switch", { name: "Verify the certificate" })).toBeChecked();
  await page.getByLabel("Relay CA", { exact: true }).fill(ca);
  await expect(page.getByText("Mail and the relay password are sent unencrypted")).toBeHidden();
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Saved: the product is applied again")).toBeVisible({ timeout: 10 * 60_000 });
  await expect(page.getByText("Relay set", { exact: true })).toBeVisible();
};

/** Send test email on the Email page, to an address; answers once the page says it was sent. */
export const sendTestEmail = async (page: Page, to: string): Promise<void> => {
  await page.getByLabel("Send a test to", { exact: true }).fill(to);
  await page.getByRole("button", { name: "Send test email" }).click();
  await expect(page.getByRole("status").filter({ hasText: /^Sent:/ })).toBeVisible({ timeout: 2 * 60_000 });
};

/** The Network page: the box's address, and Run checks with the link and the address OK. */
export const checkNetwork = async (page: Page, address: string): Promise<void> => {
  await openFromSidebar(page, "Network");
  await expect(page.getByRole("paragraph").filter({ hasText: address }).first()).toBeVisible();
  await page.getByRole("button", { name: "Run checks" }).click();
  const checks = page.getByRole("table").filter({ has: page.getByRole("columnheader", { name: "Check" }) });
  await expect(checks.getByRole("row", { name: /^link OK/ })).toBeVisible({ timeout: 60_000 });
  await expect(checks.getByRole("row", { name: new RegExp(`^address OK .*\\b${address.replaceAll(".", "\\.")}/`) })).toBeVisible();
};

/** What a page says when the box doesn't have its service yet. */
export const notAvailable = (page: Page, name: string) =>
  page.getByText(`${name}: not available in this release`);
