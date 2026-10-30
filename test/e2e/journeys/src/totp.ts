// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { createHmac } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** The 30-second step RFC 6238 counts in, the one every authenticator on the box uses. */
export const STEP_SECONDS = 30;

/** Decodes an RFC 4648 base32 secret, the form the enrolment pages show (spaces and padding allowed). */
export const base32Decode = (secret: string): Buffer => {
  const clean = secret.toUpperCase().replaceAll(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error("the TOTP secret isn't base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
};

/** The step a time falls in. */
export const stepOf = (ms: number): number => Math.floor(ms / 1000 / STEP_SECONDS);

/** The six-digit HMAC-SHA1 code of one step (RFC 6238 over RFC 4226). */
export const totpAt = (secret: string, step: number): string => {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = (mac.at(-1) ?? 0) & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7f_ff_ff_ff) % 1_000_000;
  return String(code).padStart(6, "0");
};
