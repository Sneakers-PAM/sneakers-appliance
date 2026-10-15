# Product email

The product sends mail (for Sneakers: password resets, one-time codes and notices) through a relay
an admin sets on the box, on :8443's **Email** page in the product's section. No bundle carries a
relay: the box keeps the settings on its encrypted state volume and hands them to the product.

> **Warning:** with TLS set to **None**, or with **Verify the certificate** off, mail and the relay
> password are sent unencrypted, or to a relay whose identity isn't checked. Anyone on the path
> between the box and the relay can read them, or pose as the relay. Use STARTTLS or TLS with
> verification on wherever the relay supports it. The Email page shows the same warning whenever
> either is off.

## The settings

| Setting | Default | Meaning |
|---|---|---|
| Relay host | (none) | Host name or address of the relay. Empty: no relay, the product sends no mail. |
| Port | 587 | The relay's port: 587 for submission, 465 for TLS, 25 for plain relaying. |
| From address | (none) | The address mail is sent from; required with a relay. |
| TLS | STARTTLS | **None** (plain), **STARTTLS** (upgraded before anything is sent; a relay that doesn't offer it is refused) or **TLS** (TLS from the first byte, usually 465). |
| Verify the certificate | on | Checks the relay's certificate against the system roots and the relay CA. |
| Relay CA | (none) | A PEM CA, trusted for the relay on top of the system roots, for a relay signed by a private CA. |
| Username, password | (none) | AUTH (PLAIN, or LOGIN when the relay offers only that). The password is write-only: the page shows only whether one is saved, and can replace or clear it. |

Saving needs a step-up. It is audited as `product.email.set` with every setting but the password
(the entry says only whether the password was set, kept or cleared), applies the product again
under the same maintenance gate as a product update (an open elevated shell refuses it, and an
owner may override), and, once k0s has applied the change, restarts the workloads the product
names (`email.restart`). **Send test email** sends a short message to an address you type, through
the settings on the page (with the saved password unless you type one), the same way the product
sends; it needs a step-up and is audited as `product.email.test-send`. The test changes nothing.

## Send test email: failures

Every failure `Send` (`internal/boxsettings/send.go`) can return, what it means, and the likely
fix:

| Message | Cause | Fix |
|---|---|---|
| `no relay is set` | `Host` is empty. | Set a relay host (and the rest of the settings) and save before testing. |
| `the test address %q isn't a plain email address` | The typed test address doesn't parse as one plain address. | Retype it as a single address, no display name. |
| `the relay <addr> can't be reached: ...` | The TCP dial to `host:port` failed. | Check the host and port, and that the box can reach that address and port. |
| `TLS with the relay failed: ...` | The implicit-TLS handshake failed (`TLS == tls`). | Confirm the relay speaks TLS on that port; add its CA to Relay CA if it's privately signed, or accept the risk and turn off Verify. |
| `the relay didn't greet: ...` | `smtp.NewClient` failed: the box connected but got no valid SMTP greeting. | Confirm the port is actually the relay's SMTP port. |
| `the relay doesn't offer STARTTLS; nothing was sent` | `TLS == starttls`, but the relay's `EHLO` doesn't list the `STARTTLS` extension. | Pick the TLS mode the relay actually supports on that port. |
| `STARTTLS with the relay failed: ...` | The STARTTLS upgrade itself failed. | Same as the implicit-TLS failure: check the certificate, the Relay CA, or Verify. |
| `the relay offers no AUTH, and a username is set` | `Username` is set, but the relay's `EHLO` lists no `AUTH` extension. | Clear the username and password if this relay needs none, or confirm the relay and port. |
| `the relay refused the username and password: ...` (password scrubbed) | `c.Auth` failed: the relay rejected PLAIN or LOGIN with this username and password. | Re-check the username, and re-enter and save the password. |
| `the relay refused the from address: ...` | `c.Mail(e.From)` was refused. | Set From to an address the relay account may send as. |
| `the relay refused the test address: ...` | `c.Rcpt(to)` was refused. | Try a different recipient, or check the relay's own rules on who it will relay to. |
| `the relay refused the message: ...` | `c.Data()` was refused. | Check the relay's own policy, size or content-filtering logs. |
| `the message didn't go out: ...` | Writing the message body failed (the connection dropped mid-send). | Check the network path to the relay, then retry. |
| `the relay didn't take the message: ...` | Closing the data writer got a non-OK final response. | Check the relay's own delivery logs for the rejection reason. |

## How the product reads them

`product.yaml` declares what the product reads ([release.md](release.md#productyaml)):

```yaml
email:
  label: Password resets, one-time codes and notices
  restart: [sneakers/deployment/sneakers-identity]
box_settings:                       # ConfigMaps the box writes; never a secret setting
  - configmap: sneakers/sneakers-email
    keys:
      - {key: SMTP_HOST, setting: email.host}
      - {key: SMTP_TLS_MODE, setting: email.tls}
box_secrets:
  - secret: sneakers/sneakers-email
    keys:
      - {key: SMTP_PASS, setting: email.password}
```

The settings are `email.host`, `email.port`, `email.from`, `email.username`, `email.tls` (`none`,
`starttls` or `tls`), `email.skip_verify` (`true` when verification is off), `email.ca_pem` (PEM or
empty), and the two secret ones, `email.password` and `email.uri`: the relay as one URI with the
account in it, in the form Ory's courier reads (`smtps://` for TLS, else `smtp://`;
`disable_starttls=true` for no TLS; `skip_ssl_verify=true` with verification off; with no relay,
`smtp://localhost:25/?disable_starttls=true`, where nothing listens). A secret setting goes only
into a box secret: the box refuses a `product.yaml` that puts one in a ConfigMap, and the stack
tool refuses a render whose ConfigMap carries a key a box secret holds. An unset setting has its
default, so no stack is left with a placeholder. The box writes the ConfigMaps and Secrets into the
`sneakers-appliance-secrets` stack; every object carries the stack's revision
(`sneakers-appliance/revision`), which the restart waits for in the cluster.

The settings live in `/var/lib/sneakers/platform/box-settings.json` (mode 0600). They are never
logged.

The Sneakers bundle's mail goes out through its identity service, which loads the `sneakers-email`
ConfigMap and reads `SMTP_PASS` from the `sneakers-email` Secret; the Kratos courier (not run) gets
`email.uri`. Ory's URI has no CA parameter, so the relay CA reaches the identity service only.
