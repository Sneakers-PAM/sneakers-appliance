// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

import { need } from "@/env";
import { stepOf, totpAt } from "@/totp";

/**
 * One account the journeys made on the box: its name, password and authenticator secret. They
 * are made in the run for a box that only exists inside it, and are kept in the run's state
 * file (JOURNEYS_STATE, outside the uploaded artifacts) so a later journey can sign in.
 */
export interface Account {
  email?: string;
  /** The last TOTP step used: the box takes each step's code once. */
  lastStep: number;
  name: string;
  password: string;
  secret: string;
}

interface State {
  appliance?: Account;
  product?: Account;
}

type Which = keyof State;

const file = () => need("JOURNEYS_STATE");

const read = (): State =>
  existsSync(file()) ? (JSON.parse(readFileSync(file(), "utf8")) as State) : {};

const write = (state: State) => {
  const tmp = `${file()}.tmp`;
  writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  renameSync(tmp, file());
};

/** A password made for this run: long, and never one a breached-password list holds. */
export const newPassword = (): string => `journeys ${randomBytes(18).toString("base64url")}`;

export const saveAccount = (which: Which, account: Account): void => {
  write({ ...read(), [which]: account });
};

/** The account an earlier journey made, or a clear failure naming that journey. */
export const account = (which: Which): Account => {
  const found = read()[which];
  if (!found) {
    throw new Error(
      which === "appliance"
        ? "no appliance admin yet: the first-run setup journey makes it"
        : "no product admin yet: the product setup journey makes it",
    );
  }
  return found;
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The next authenticator code for an account: it waits for a step not used yet, since the box
 * refuses a step's code the second time, and records the step.
 */
export const nextCode = async (which: Which): Promise<string> => {
  const current = account(which);
  while (stepOf(Date.now()) <= current.lastStep) await sleep(1000);
  const step = stepOf(Date.now());
  saveAccount(which, { ...current, lastStep: step });
  return totpAt(current.secret, step);
};
