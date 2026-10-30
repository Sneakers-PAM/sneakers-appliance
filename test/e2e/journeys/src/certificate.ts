// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash, type X509Certificate } from "node:crypto";
import { connect } from "node:tls";

import { consoleFingerprint } from "@/console";
import { boxAddress } from "@/env";

/**
 * The certificate the box serves on a port, read off the handshake. Nothing is sent over the
 * connection: the certificate is only trusted once its fingerprint matches the console's.
 */
export const servedCertificate = (port: number): Promise<X509Certificate> =>
  new Promise((resolve, reject) => {
    const socket = connect({ host: boxAddress(), port, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerX509Certificate();
      socket.destroy();
      if (cert) resolve(cert);
      else reject(new Error(`${boxAddress()}:${String(port)} served no certificate`));
    });
    socket.setTimeout(15_000, () => {
      socket.destroy();
      reject(new Error(`${boxAddress()}:${String(port)} didn't finish a TLS handshake in 15s`));
    });
    socket.on("error", reject);
  });

/** SHA-256 over the DER certificate, as 64 upper-case hex digits: what the console shows. */
export const fingerprintOf = (cert: X509Certificate): string =>
  cert.fingerprint256.replaceAll(":", "").toUpperCase();

/** The base64 SHA-256 of the certificate's SubjectPublicKeyInfo, Chromium's SPKI pin. */
export const spkiPinOf = (cert: X509Certificate): string =>
  createHash("sha256")
    .update(cert.publicKey.export({ format: "der", type: "spki" }))
    .digest("base64");

/**
 * Fetches the box's certificate on a port and checks its fingerprint against the one the
 * console shows, as the person setting the box up does on the first visit. Answers the
 * checked certificate, or fails naming both fingerprints.
 */
export const checkedCertificate = async (port: number): Promise<X509Certificate> => {
  const [cert, onConsole] = await Promise.all([servedCertificate(port), consoleFingerprint()]);
  const served = fingerprintOf(cert);
  if (served !== onConsole) {
    throw new Error(
      `${boxAddress()}:${String(port)} serves a certificate with fingerprint ${served}, but the console shows ${onConsole}`,
    );
  }
  return cert;
};
