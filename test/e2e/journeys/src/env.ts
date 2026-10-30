// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the image suite's journeys driver (test/image/journeys) hands the journeys. Each is read
 * when a journey needs it, so listing the journeys (`playwright test --list`) needs none.
 */
export const need = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is not set: the journeys run against a booted box, started by go test -tags image ./test/image/journeys/`,
    );
  }
  return value;
};

/** The box's management address: the one the console shows, as a browser on its network uses it. */
export const boxAddress = (): string => need("JOURNEYS_BOX");

/** The :8443 appliance admin. */
export const adminUrl = (path = "/"): string => `https://${boxAddress()}:8443${path}`;

/** The product on 443. */
export const productUrl = (path = "/"): string => `https://${boxAddress()}${path}`;
