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
