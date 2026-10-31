// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import type { TestInfo } from "@playwright/test";

import { need } from "@/env";

/**
 * The box's console, as the person at the desk reads it: the driver (test/image/journeys) reads
 * the VM's display off QEMU and serves it on JOURNEYS_CONSOLE. While the box restarts there is
 * no display, and a read waits.
 */
const consoleUrl = (path: string) => `${need("JOURNEYS_CONSOLE")}${path}`;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The display now, its rows joined as they wrap and blanks squeezed: "" while the box is down. */
export const readConsole = async (): Promise<string> => {
  const response = await fetch(consoleUrl("/screen"));
  if (response.status === 503) return "";
  if (!response.ok) throw new Error(`the console reader answered ${String(response.status)}`);
  return ((await response.json()) as { text: string }).text;
};

/** Waits until the console shows re, and answers the match. */
export const waitForConsole = async (re: RegExp, timeoutMs: number): Promise<RegExpMatchArray> => {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  for (;;) {
    last = await readConsole();
    const match = last.match(re);
    if (match) return match;
    if (Date.now() > deadline) {
      throw new Error(`the console never showed ${String(re)} in ${String(timeoutMs / 1000)}s; it shows:\n${last}`);
    }
    await sleep(1000);
  }
};

/** Attaches a picture of the console to the journey's report. */
export const attachConsole = async (testInfo: TestInfo, name: string): Promise<void> => {
  const response = await fetch(consoleUrl("/screenshot"));
  if (!response.ok) return;
  await testInfo.attach(`console: ${name}`, {
    body: Buffer.from(await response.arrayBuffer()),
    contentType: "image/png",
  });
};

/**
 * The :8443 certificate's SHA-256 fingerprint as the console shows it, in groups of four over
 * two lines: on the first-boot screen under "Certificate fingerprint", on the status screen as
 * the ":8443" line under "Fingerprints". The groups are the first sixteen four-digit hex words
 * after the label, so whatever the screen draws between the two lines doesn't matter. Answered
 * as 64 upper-case hex digits, or undefined while the screen doesn't show it.
 */
export const fingerprintOnConsole = (text: string): string | undefined => {
  const label = /Certificate fingerprint|Fingerprints\W+:8443/.exec(text);
  if (!label) return undefined;
  const groups = text.slice(label.index + label[0].length).match(/\b[0-9A-F]{4}\b/g) ?? [];
  return groups.length >= 16 ? groups.slice(0, 16).join("") : undefined;
};

export const consoleFingerprint = async (timeoutMs = 3 * 60_000): Promise<string> => {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  for (;;) {
    last = await readConsole();
    const found = fingerprintOnConsole(last);
    if (found) return found;
    if (Date.now() > deadline) {
      throw new Error(`the console never showed the :8443 certificate's fingerprint; it shows:\n${last}`);
    }
    await sleep(1000);
  }
};

/** The one-time setup code the first-boot screen shows. */
export const SETUP_CODE_ON_CONSOLE = /Setup code ([0-9A-Z]{4}(?:-[0-9A-Z]{4}){3})/;
