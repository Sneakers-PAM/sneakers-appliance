# Error codes

Every coded error carries a number and a stable symbol. The kit prints `SYMBOL (code): sentence`;
on the box the console and init's log show the same. 1xxx are the kit and the verification chain it
shares with `Image.Stage`; 2xxx are boot.

## First boot and access (3xxx)

30xx are the access store, 31xx SSH login, 32xx the :8443 sign-in, 33xx elevation, 34xx the
network, 35xx the setup steps, 36xx the factory reset and power, and 37xx the closed shell. The
shell, the console and :8443 show the same sentence.

| Code | Symbol | Meaning |
|---|---|---|
| 3001 | `ACCESS_KEY_TYPE` | the key isn't an OpenSSH public key of an accepted type (recovery keys: `ssh-ed25519` or `ssh-rsa` only, never `sk-`) |
| 3002 | `ACCESS_KEY_WEAK` | the key is DSA or RSA shorter than 3072 bits |
| 3003 | `ACCESS_KEY_DUPLICATE` | the key is already a login key of an admin or a recovery key |
| 3004 | `ACCESS_NAME` | the admin name doesn't match `^[a-z][a-z0-9_-]{1,30}$`, is reserved, or is taken |
| 3006 | `ACCESS_LAST_OWNER` | the change would leave no owner |
| 3007 | `ACCESS_LAST_RECOVERY_KEY` | the last recovery key can't be removed; add its replacement first |
| 3008 | `ACCESS_RECOVERY_KEY_LIMIT` | three recovery keys are already set |
| 3009 | `ACCESS_FORBIDDEN` | the role or the origin doesn't allow it |
| 3010 | `ACCESS_STEPUP_REQUIRED` | a sign-in no older than 5 minutes is needed |
| 3012 | `ACCESS_STORE_INVALID` | the access store doesn't parse |
| 3013 | `ACCESS_SESSION` | no :8443 session: signed out, idle for 15 minutes, past 8 hours, or its key or admin was removed |
| 3014 | `ACCESS_CONFIRM` | the typed confirmation (the host name) doesn't match |
| 3015 | `ACCESS_KEY_REVOKED` | the key was removed and is on the revocation list; an owner un-revokes it first |
| 3016 | `ACCESS_PASSWORD` | the password is shorter than 12 characters, on the breached-password list, or the admin's name |
| 3017 | `ACCESS_CREDENTIALS` | the name, password or TOTP code is wrong, or the TOTP code was used already |
| 3018 | `ACCESS_LOCKED` | the account is locked after 3 failures in 15 minutes, for 15 minutes or until an owner unlocks it |
| 3019 | `ACCESS_THROTTLED` | this source failed too often; it may try again after the time given |
| 3020 | `ACCESS_NO_ADMIN` | sshd was asked to start while no admin has a password and a TOTP secret |
| 3021 | `ACCESS_POLICY` | an access setting is out of its bounds |
| 3022 | `ACCESS_QUORUM` | the root-operator roster would be empty, name someone who isn't an admin, or have a threshold out of range |
| 3303 | `ELEV_EXPIRED` | the request or certificate expired |
| 3304 | `ELEV_USED` | the certificate was already used |
| 3305 | `ELEV_MAINTENANCE` | an upgrade is in progress |
| 3307 | `ELEV_UNKNOWN` | no elevation request or certificate has that id |
| 3308 | `ROOT_CHALLENGE` | the root-shell challenge is unknown, expired, closed or someone else's |
| 3309 | `ROOT_CODE` | the code doesn't match the challenge |
| 3401 | `NET_INVALID` | a setting fails validation (the error names the field) |
| 3402 | `NET_NO_ADDRESS` | the management interface has no usable address |
| 3403 | `NET_DHCP_TIMEOUT` | no DHCP server answered in time |
| 3404 | `NET_GATEWAY` | the gateway didn't answer ARP or neighbour discovery |
| 3405 | `NET_DNS` | a DNS server didn't answer |
| 3406 | `NET_NTP` | no NTP server gave a usable time |
| 3407 | `NET_REVERTED` | a change wasn't confirmed in 120 seconds and was undone |
| 3501 | `SETUP_INCOMPLETE` | a setup step is still open (the error names it) |
| 3502 | `SETUP_CODE` | a wrong, used or expired one-time code (setup, invitation or Recover access) |
| 3503 | `SETUP_DONE` | setup is done: a setup-only call, or a call with a setup code's session |
| 3601 | `RESET_UNAVAILABLE` | no factory reset: a single admin, a roster that can't reach its threshold, or one already in progress |
| 3602 | `RESET_APPROVED` | this admin's approval is already counted, or they aren't on the roster |
| 3603 | `RESET_CANCELLED` | the factory reset was cancelled, expired or never started |
| 3604 | `POWER_FORCED_CONFIRM` | a forced reboot or shutdown needs its second, explicit confirmation |
| 3605 | `RESET_VERIFY` | the factory reset's check failed (a partition or a LUKS, filesystem or GPT signature is still there); the box doesn't reboot |
| 3606 | `RESET_QUORUM` | init refused the factory reset: not armed, approvals that aren't a quorum of the roster, the delay not over, or expired |
| 3607 | `RESET_FAILED` | a factory reset step failed (the error names it); the reset carries on at the next boot |
| 3608 | `POWER_CALLER` | init takes power and reset requests only from osadmin and the closed shell |
| 3609 | `POWER_BUSY` | a reboot, shutdown or factory reset is already under way |
| 3610 | `POWER_AUDIT` | the OS audit log can't be written, so init doesn't act on the request |
| 3701 | `SHELL_PARSE` | the command line doesn't parse: an open quote, a control character, or longer than 64 KiB |
| 3702 | `SHELL_UNKNOWN` | there is no such command; `help` lists them |
| 3703 | `NOT_AVAILABLE` | not available in this release, or the appliance services aren't answering |

## Certificates (38xx)

| Code | Symbol | Cause |
|---|---|---|
| 3801 | `TLS_INVALID` | a field of the request fails validation (the error names it) |
| 3802 | `TLS_FORMAT` | a certificate, key or PKCS#12 file doesn't parse, is encrypted, or the PKCS#12 password is wrong |
| 3803 | `TLS_KEY_MISMATCH` | the certificate isn't for the private key given, or for the CSR's key |
| 3804 | `TLS_KEY_TYPE` | the key isn't RSA of 3072 bits or more, or ECDSA P-256 or P-384 |
| 3805 | `TLS_CHAIN` | the chain doesn't build to a root (the error names the missing issuer) or a certificate in it is invalid |
| 3806 | `TLS_NAMES` | the certificate's SANs cover none of the box's management names and addresses, or of the endpoint's |
| 3807 | `TLS_VALIDITY` | the certificate has expired or isn't valid yet |
| 3808 | `TLS_USAGE` | the certificate is a CA certificate or isn't for TLS servers |
| 3809 | `TLS_UNKNOWN` | no certificate, CSR or endpoint has that id |
| 3810 | `TLS_IN_USE` | the certificate is in use by an endpoint, or is the box's self-signed one |
| 3811 | `TLS_LIMIT` | the store already holds 32 certificates or 8 pending CSRs |
| 3812 | `TLS_ENDPOINT_UNAVAILABLE` | the endpoint isn't on this box yet (the product endpoint needs the product installed) |
| 3813 | `TLS_NOT_SERVED` | the new certificate wasn't served within 15 seconds, so the previous one was put back |
| 3814 | `TLS_ACME_UNAVAILABLE` | ACME through cert-manager isn't available yet; it comes with the product bundle |
| 3815 | `TLS_NO_HOSTNAME` | the box has no host name, so the certificate was checked against the management addresses only and covers none of them; set the host name on Network |

## Build kit and boot (1xxx and 2xxx)

| Code | Symbol | Meaning |
|---|---|---|
| 1001 | `KIT_PIN_MISSING` | this kit was built without one of its pins, or with a channel other than production or lab |
| 1002 | `KIT_SIG_MISSING` | the artifact or `release.yaml` has no signature |
| 1003 | `KIT_WRONG_SIGNER` | signed, but not by the pinned key |
| 1004 | `KIT_CHANNEL` | the manifest's channel isn't the kit's |
| 1005 | `KIT_KIT_TOO_OLD` | `kitMin` is above this kit's version |
| 1006 | `KIT_DIGEST_MISMATCH` | a layer's SHA-256 differs from `appliance.yaml` |
| 1007 | `KIT_AUTHENTICODE` | the UKI or loader doesn't verify against the pinned db certificate |
| 1008 | `KIT_VERITY_MISMATCH` | the root image doesn't match the UKI's root hash |
| 1009 | `KIT_BUNDLE_MISMATCH` | the bundle and `release.yaml` differ, or k0s isn't the pinned binary |
| 1010 | `KIT_IMAGE_UNSIGNED` | a bundled image lacks a valid org signature |
| 1011 | `KIT_TOOL_MISSING` | a tool the format needs isn't available |
| 1012 | `KIT_MANIFEST_INVALID` | `appliance.yaml` doesn't parse or breaks a structural rule |
| 1013 | `KIT_SOURCE_UNREADABLE` | the artifact can't be resolved or read |
| 2001 | `ROOT_NOT_FOUND` | no root slot matches the signed root hash, and no install medium holds the root image |
| 2101 | `SERVICE_TABLE_INVALID` | a service table entry doesn't parse, names an unknown service, or loops through `after:` |
| 2102 | `SERVICE_UNKNOWN` | the service table has no service of that name |
| 2103 | `SERVICE_NOT_ON_DEMAND` | only on-demand services are started and stopped through the Services API |
| 2104 | `SERVICE_PRE_START` | the service's pre-start hook failed, so it wasn't started |
| 2105 | `SERVICE_WAITING` | the service waits for a start-when path that doesn't exist yet |
| 2201 | `SB_NO_EFIVARFS` | efivarfs isn't mounted or can't be read, so the Secure Boot state is unknown |
| 2202 | `SB_NOT_SETUP_MODE` | the firmware isn't in Setup Mode, so the org keys can't be enrolled; nothing was written |
| 2203 | `SB_ENROL_FAILED` | writing a Secure Boot key variable failed or didn't read back |
| 2301 | `KEYCUSTODY_NO_TPM` | TPM mode was chosen on a box without a TPM |
| 2302 | `KEYCUSTODY_INVALID` | an unknown mode or choice, a second Initialize, or a disk too small for first boot |
| 2303 | `KEYCUSTODY_NOT_INITIALIZED` | the state volume has no custody header yet |
| 2304 | `KEYCUSTODY_LOCKED` | the state key can't be recovered: no sealed copy unseals, or the key file is missing |
| 2305 | `KEYCUSTODY_NOT_FOUND` | there's no sealed item of that name |
| 2306 | `KEYCUSTODY_RECIPIENTS` | the escrow takes one to three ssh-ed25519 or ssh-rsa recovery keys |
| 2307 | `KEYCUSTODY_PHASE` | an escrow is imported only in firstboot, before any root secret is sealed |
| 2501 | `UPGRADE_DOWNGRADE` | the release isn't newer than the running one |
| 2502 | `UPGRADE_UNPREDICTABLE` | the release's UKI isn't one whose PCR 11 the box can predict |
| 2503 | `UPGRADE_NO_PREVIOUS` | there's no previous release to roll back to |
| 2504 | `UPGRADE_FORMAT` | the file isn't a sneakers-appliance update package, or its header breaks the format's rules |
| 2505 | `UPGRADE_SIGNATURE` | the update package isn't signed by this box's release key, or it changed after it was signed |
| 2506 | `UPGRADE_DECRYPT` | the update package doesn't decrypt with this box's update key, or the booted UKI carries no update key |
| 2507 | `UPGRADE_CHANNEL` | a lab package never installs on a production box, and a production package never on a lab box |
| 2508 | `UPGRADE_PATCH_BASE` | the patch is for other base versions than the one this box runs |
| 2509 | `UPGRADE_AIR_GAPPED` | no mirror is configured, so the box fetches nothing; upload the `.bin` instead |
| 2510 | `UPGRADE_UPLOAD` | the upload or fetch is unknown, too large, or failed |
| 2511 | `UPGRADE_NOT_STAGED` | no release is staged to apply |
| 2512 | `UPGRADE_ELEVATED` | an elevated shell is open (the refusal names it); it ends, or an owner terminates it or overrides it (which ends it), before an update applies or reverts |
| 2513 | `UPGRADE_PRODUCT_BASE` | the product bundle doesn't fit the base version this box runs |
