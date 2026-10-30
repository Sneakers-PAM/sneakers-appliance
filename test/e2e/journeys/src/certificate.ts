// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash, type X509Certificate } from "node:crypto";
import { request } from "node:http";
import { connect } from "node:tls";

import { consoleFingerprint } from "@/console";
import { boxAddress, need } from "@/env";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * One TLS handshake with the box on a port, through the driver's proxy (JOURNEYS_PROXY), the
 * way the browser reaches it, and the certificate it served. Nothing is sent over the
 * connection: the certificate is only trusted once its fingerprint matches the console's.
 */
const handshake = (port: number): Promise<X509Certificate> =>
  new Promise((resolve, reject) => {
    const target = `${boxAddress()}:${String(port)}`;
    const proxy = new URL(need("JOURNEYS_PROXY"));
    const tunnel = request({ host: proxy.hostname, method: "CONNECT", path: target, port: proxy.port, timeout: 15_000 });
    tunnel.on("connect", (response, raw) => {
      if (response.statusCode !== 200) {
        raw.destroy();
        reject(new Error(`the proxy answered ${String(response.statusCode)} for ${target}`));
        return;
      }
      const socket = connect({ rejectUnauthorized: false, socket: raw }, () => {
        const cert = socket.getPeerX509Certificate();
        socket.destroy();
        if (cert) resolve(cert);
        else reject(new Error(`${target} served no certificate`));
      });
      socket.setTimeout(15_000, () => {
        socket.destroy();
        reject(new Error(`${target} didn't finish a TLS handshake in 15s`));
      });
      socket.on("error", reject);
    });
    tunnel.on("timeout", () => tunnel.destroy(new Error(`the proxy didn't connect to ${target} in 15s`)));
    tunnel.on("error", reject);
    tunnel.end();
  });

/**
 * The certificate the box serves on a port. A port that isn't up yet (QEMU takes the
 * connection, and the box doesn't answer) is tried again until the deadline.
 */
export const servedCertificate = async (port: number, timeoutMs = 3 * 60_000): Promise<X509Certificate> => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return await handshake(port);
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await sleep(5000);
    }
  }
};

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
  const cert = await servedCertificate(port);
  const onConsole = await consoleFingerprint();
  const served = fingerprintOf(cert);
  if (served !== onConsole) {
    throw new Error(
      `${boxAddress()}:${String(port)} serves a certificate with fingerprint ${served}, but the console shows ${onConsole}`,
    );
  }
  return cert;
};

/**
 * The :8443 certificate once it has settled. A new box makes its certificate again as its
 * addresses come in (SLAAC's after DHCP's), and the console follows, so the certificate
 * trusted is the one the console and :8443 still agree on a while later.
 */
export const settledCertificate = async (port: number, timeoutMs = 5 * 60_000, quietMs = 30_000): Promise<X509Certificate> => {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  for (;;) {
    let cert: X509Certificate | undefined;
    try {
      cert = await checkedCertificate(port);
    } catch (error) {
      if (Date.now() > deadline) throw error;
    }
    if (cert) {
      const fingerprint = fingerprintOf(cert);
      if (fingerprint === last) return cert;
      last = fingerprint;
    }
    if (Date.now() > deadline) throw new Error(`the :${String(port)} certificate didn't settle in ${String(timeoutMs / 1000)}s`);
    await sleep(quietMs);
  }
};
