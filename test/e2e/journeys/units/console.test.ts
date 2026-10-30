// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

import { fingerprintOnConsole, SETUP_CODE_ON_CONSOLE } from "@/console";

const FINGERPRINT = "7C2E91AB4F06D3E8B15A6C902E7F0A4DE38B5C219FD076A4C1E90B3F8D62A7C5";

// The screens as the driver serves them: the rows joined as they wrap, blanks squeezed
// (docs/console.md has both).
const FIRST_BOOT =
  "| Sneakers-PAM Appliance | | 0.1.0 | | Open this address in your browser: | | https://192.0.2.10:8443 | " +
  "| Certificate fingerprint | | 7C2E 91AB 4F06 D3E8 B15A 6C90 2E7F 0A4D | | E38B 5C21 9FD0 76A4 C1E9 0B3F 8D62 A7C5 | " +
  "| Setup code 7PQK-NMS9-XD2A-4KJW expires in 59 min | | Protection REDUCED no TPM, no Secure Boot |";
const STATUS =
  "| Health OK all services running | | Admin https://192.0.2.10:8443 | | SSH 192.0.2.10:22 | " +
  "| key from :8443 Access, then TOTP | | Fingerprints | | :8443 7C2E 91AB 4F06 D3E8 B15A 6C90 2E7F 0A4D | " +
  "| E38B 5C21 9FD0 76A4 C1E9 0B3F 8D62 A7C5 | | ssh SHA256:yskn evuN I/Ng 13w+ vvxl QW6F | | R Recover access |";

test("the :8443 fingerprint reads off the first-boot screen and the status screen", () => {
  expect(fingerprintOnConsole(FIRST_BOOT)).toBe(FINGERPRINT);
  expect(fingerprintOnConsole(STATUS)).toBe(FINGERPRINT);
});

test("a screen without the whole fingerprint answers nothing", () => {
  expect(fingerprintOnConsole("")).toBeUndefined();
  expect(fingerprintOnConsole("Starting | the network (12 s)")).toBeUndefined();
  expect(fingerprintOnConsole("Certificate fingerprint 7C2E 91AB")).toBeUndefined();
});

test("the setup code reads off the first-boot screen", () => {
  expect(FIRST_BOOT.match(SETUP_CODE_ON_CONSOLE)?.[1]).toBe("7PQK-NMS9-XD2A-4KJW");
});
