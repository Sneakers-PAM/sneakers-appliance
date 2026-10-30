// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { checkedCertificate, spkiPinOf } from "@/certificate";
import { productUrl } from "@/env";
import { expect, test } from "@/fixtures";
import { type ProductAdmin, productAdminSetup, readSetupToken, signInToProduct } from "@/flows/product";
import { codeIn, waitForMail } from "@/mail";
import { signedInToAppliance } from "@/session";
import { account, newPassword, nextCode, saveAccount } from "@/state";

const emailed = (to: string) => async () => codeIn(await waitForMail(to, new Date(Date.now() - 5000)));

const factor = (admin: ProductAdmin) => ({
  emailed: emailed(admin.email),
  onSecret: (secret: string) => {
    saveAccount("product", { ...account("product"), secret });
    return () => nextCode("product");
  },
  totp: account("product").secret ? () => nextCode("product") : undefined,
});

const productAdmin = (): ProductAdmin => {
  const saved = account("product");
  return { email: saved.email ?? "", name: "Journeys Admin", password: saved.password, username: saved.name };
};

test.describe.configure({ mode: "serial" });

test("the product's first admin, with the setup token from :8443 and the emailed code", async ({ boxPin, page, shot }) => {
  test.setTimeout(15 * 60_000);
  await test.step("443 serves the certificate the console shows", async () => {
    expect(spkiPinOf(await checkedCertificate(443))).toBe(boxPin);
  });
  await signedInToAppliance(page);
  const { link, token } = await readSetupToken(page);
  await shot("the setup token");
  expect(new URL(link).origin, "the setup token's page is on this box").toBe(new URL(productUrl()).origin);
  saveAccount("product", { email: "admin@example.org", lastStep: 0, name: "journeys", password: newPassword(), secret: "" });
  const admin = productAdmin();
  await productAdminSetup(page, link, admin, token, emailed(admin.email), shot);
});

test("sign-in to the admin web", async ({ page, shot }) => {
  test.setTimeout(10 * 60_000);
  const admin = productAdmin();
  await signInToProduct(page, productUrl("/admin/"), admin, factor(admin), shot);
  await expect(page).toHaveURL(/\/admin\//);
  await shot("the admin web");
});

test("sign-in to the staff web", async ({ page, shot }) => {
  test.setTimeout(10 * 60_000);
  const admin = productAdmin();
  await signInToProduct(page, productUrl("/"), admin, factor(admin), shot);
  await expect(page).not.toHaveURL(/\/admin\//);
  await shot("the staff web");
});
