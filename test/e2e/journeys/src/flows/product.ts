// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";

import { type Codes, openFromSidebar } from "@/flows/appliance";

/** The product's first admin, as the admin web's setup page takes it. */
export interface ProductAdmin {
  email: string;
  name: string;
  password: string;
  username: string;
}

/**
 * The one-time setup token the product exposes on :8443's Status page (Product values), read
 * with Show as an owner does, and the product page the box says to use it at.
 */
export const readSetupToken = async (page: Page): Promise<{ link: string; token: string }> => {
  await openFromSidebar(page, "Status");
  const values = page.getByRole("region", { name: "Product values" });
  await values.getByRole("button", { name: "Show Sneakers setup token" }).click();
  const shown = values.locator("code").first();
  await expect(shown).toBeVisible();
  const token = (await shown.getAttribute("title")) ?? "";
  const link = (await values.getByRole("link").first().getAttribute("href")) ?? "";
  expect(token, "the setup token").not.toBe("");
  return { link, token };
};

/**
 * The admin web's first-run setup (/admin/setup): the first admin with the setup token, the
 * built-ins, then the emailed code that verifies the address, up to "You're all set".
 */
export const productAdminSetup = async (
  page: Page,
  url: string,
  admin: ProductAdmin,
  token: string,
  emailedCode: () => Promise<string>,
  after: (step: string) => Promise<void>,
): Promise<void> => {
  await page.goto(url);
  await expect(page.getByRole("heading", { name: "Set up Sneakers-PAM" })).toBeVisible();
  await page.getByLabel(/^Username/).fill(admin.username);
  await page.getByLabel(/^Display name/).fill(admin.name);
  await page.getByLabel(/^Email/).fill(admin.email);
  await page.getByLabel(/^Password/).fill(admin.password);
  await page.getByLabel(/^Confirm password/).fill(admin.password);
  await page.getByLabel(/^Setup token/).fill(token);
  await after("the first admin");
  await page.getByRole("button", { name: "Create admin" }).click();
  await expect(page.getByRole("heading", { name: "Verify your email" })).toBeVisible({ timeout: 2 * 60_000 });
  await after("the built-ins installed");
  await page.getByLabel("6-digit code").first().fill(await emailedCode());
  await expect(page.getByRole("heading", { name: "You're all set" })).toBeVisible({ timeout: 60_000 });
  await after("you're all set");
  await page.getByRole("link", { name: "Continue to sign-in" }).click();
  await page.waitForURL(/\/sign-in/);
};

/** How a sign-in's second step is answered. */
export interface SecondFactor {
  /** A code the product emailed, asked for after Send code. */
  emailed: () => Promise<string>;
  /** Called with the authenticator secret when the product asks to set one up; answers its codes. */
  onSecret: (secret: string) => Codes;
  /** Codes from the authenticator set up earlier, if there is one. */
  totp?: Codes;
}

const signedIn = (page: Page) => !/\/(sign-in|enroll)(\?|$)/.test(new URL(page.url()).pathname + "?");

/**
 * The product's sign-in, as the staff web and the admin web share it: the local login (past the
 * SSO button when there is one), then whatever second step the product asks for. A code is the
 * authenticator's when one is set up, else an emailed one. When the product asks for a second
 * factor to be set up, an authenticator is enrolled from the key the page shows. Answers once
 * the app is open with the admin's name on its account button.
 */
export const signInToProduct = async (
  page: Page,
  start: string,
  admin: ProductAdmin,
  factor: SecondFactor,
  after: (step: string) => Promise<void>,
): Promise<void> => {
  await page.goto(start);
  const local = page.getByRole("link", { name: "Use local login instead" });
  const identifier = page.getByLabel("Username or email");
  await expect(local.or(identifier)).toBeVisible();
  if (await local.isVisible()) await local.click();
  await identifier.fill(admin.username);
  await page.getByLabel("Password", { exact: true }).fill(admin.password);
  await after("the local login");
  await page.getByRole("button", { exact: true, name: "Sign in" }).click();

  const askCode = page.getByRole("heading", { name: "Enter your code" });
  const askEnrol = page.getByRole("heading", { name: /^(Set up a second factor to continue|Protect your account)$/ });
  const deadline = Date.now() + 2 * 60_000;
  let totp = factor.totp;
  while (!signedIn(page) || (await askEnrol.isVisible())) {
    if (Date.now() > deadline) throw new Error(`the sign-in at ${start} never opened the app`);
    if (await askCode.isVisible()) {
      const second = page.getByRole("radiogroup", { name: "Second factor" });
      if (totp) {
        if (await second.isVisible()) await second.getByRole("radio", { name: "Authenticator" }).click();
        await page.getByLabel("6-digit code").first().fill(await totp());
      } else {
        await second.getByRole("radio", { name: "Email" }).click();
        await page.getByRole("button", { name: "Send code" }).click();
        await page.getByLabel("6-digit code").first().fill(await factor.emailed());
      }
      await after("the second step");
      // A full code may submit by itself; Verify is for when it doesn't.
      await page.getByRole("button", { exact: true, name: "Verify" }).click({ timeout: 5000 }).catch(() => {});
      await expect(askCode).toBeHidden({ timeout: 60_000 });
      continue;
    }
    if (await askEnrol.isVisible()) {
      const key = page.getByText("Can't scan? Enter this key:").locator("xpath=following-sibling::span[1]");
      await expect(key).not.toHaveText("…");
      totp = factor.onSecret((await key.innerText()).replaceAll(/\s/g, ""));
      await after("set up an authenticator");
      await page.getByLabel("6-digit code").first().fill(await totp());
      await page.getByRole("button", { name: "Confirm & continue" }).click({ timeout: 5000 }).catch(() => {});
      await expect(askEnrol).toBeHidden({ timeout: 60_000 });
      continue;
    }
    await page.waitForTimeout(500);
  }
  await expect(page.getByRole("button", { name: new RegExp(admin.name) }).first()).toBeVisible({ timeout: 60_000 });
};
