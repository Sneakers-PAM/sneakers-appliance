// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "@/fixtures";

/**
 * The add-on modules' on and off switches. No add-on ships yet and the box serves
 * ModulesService as "Not available in this release", so these stay stubs, skipped with the
 * reason, until the add-ons land.
 */
const NOT_YET = "no add-on module ships yet, and the box serves ModulesService as not available in this release";

test("Add-on modules: an add-on switched on", () => {
  test.skip(true, NOT_YET);
});

test("Add-on modules: the add-on switched off again", () => {
  test.skip(true, NOT_YET);
});
