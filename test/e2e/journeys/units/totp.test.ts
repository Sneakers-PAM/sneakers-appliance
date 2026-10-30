// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

import { base32Decode, stepOf, totpAt } from "@/totp";

// RFC 6238's SHA-1 key, "12345678901234567890", in base32.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // gitleaks:allow (RFC 6238's published test key)

test("base32 decodes the RFC 6238 key, with the spaces and padding a page may show", () => {
  expect(base32Decode(RFC_SECRET).toString("ascii")).toBe("12345678901234567890");
  expect(base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq==").toString("ascii")).toBe("12345678901234567890");
  expect(() => base32Decode("not base32!")).toThrow("isn't base32");
});

test("the codes are RFC 6238's SHA-1 test values, to six digits", () => {
  for (const [seconds, code] of [
    [59, "287082"],
    [1_111_111_109, "081804"],
    [1_234_567_890, "005924"],
    [2_000_000_000, "279037"],
  ] as const) {
    expect(totpAt(RFC_SECRET, stepOf(seconds * 1000)), `at ${String(seconds)}s`).toBe(code);
  }
});
