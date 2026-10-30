// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { need } from "@/env";

/**
 * The mail catcher on the runner (Mailpit, build/journeys/mail.sh): the box's relay for the
 * journeys. The box reaches it at JOURNEYS_MAIL_RELAY through QEMU's guest forward, with
 * STARTTLS on a certificate from the run's own CA (JOURNEYS_MAIL_CA), so the box checks the
 * relay's certificate as it would a real one. The journeys read what arrived through its API.
 */
export const relay = (): { ca: string; host: string; port: string } => {
  const [host = "", port = ""] = need("JOURNEYS_MAIL_RELAY").split(":");
  return { ca: readFileSync(need("JOURNEYS_MAIL_CA"), "utf8"), host, port };
};

interface Summary {
  Created: string;
  ID: string;
  Subject: string;
  To: { Address: string }[];
}

export interface Mail {
  subject: string;
  text: string;
}

const api = (path: string) => `${need("JOURNEYS_MAIL_API")}${path}`;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for a message to an address that arrived after a time, and answers its subject and text. */
export const waitForMail = async (to: string, after: Date, timeoutMs = 3 * 60_000): Promise<Mail> => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const response = await fetch(api(`/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`));
    if (response.ok) {
      const { messages } = (await response.json()) as { messages: Summary[] };
      const found = messages.find((m) => new Date(m.Created) >= after);
      if (found) {
        const message = (await (await fetch(api(`/api/v1/message/${found.ID}`))).json()) as {
          Subject: string;
          Text: string;
        };
        return { subject: message.Subject, text: message.Text };
      }
    }
    if (Date.now() > deadline) {
      throw new Error(`no mail to ${to} reached the mail catcher in ${String(timeoutMs / 1000)}s`);
    }
    await sleep(2000);
  }
};

/** The six-digit code in a message, as the product's one-time code mails carry it. */
export const codeIn = (mail: Mail): string => {
  const match = mail.text.match(/\b(\d{3}[ -]?\d{3})\b/);
  if (!match?.[1]) throw new Error(`the mail "${mail.subject}" carries no six-digit code`);
  return match[1].replaceAll(/\D/g, "");
};
