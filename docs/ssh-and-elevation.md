# SSH and elevation

SSH on the box takes only keys the box issued. Every admin logs in with their own name into the
closed shell and gives a TOTP code first; a root shell is opened through a one-time challenge and a
code from :8443. There are no SSH password logins, no admin-supplied login keys, no operator
(client) certificates and no recovery codes in this release.

### The first SSH login

SSH needs a key from :8443 first, and sshd takes it only with its certificate. A client without
one is refused with `No supported authentication methods available (server sent: publickey)`,
after the banner below.

1. Sign in to :8443 (name, password and TOTP code), open **Access** and choose **Get an SSH key**
   (it asks for a fresh TOTP code). The box keeps neither the private key nor any of the files.
   Each key has three downloads, all named after the key's serial so they always pair and a
   browser never adds " (1)": `id_ed25519_<name>_sneakers_<serial>` (the OpenSSH private key),
   `<that>-cert.pub` (its certificate), `<that>.ppk` (the same key for PuTTY and MobaXterm, with
   the certificate in it), `<that>.pem` (the same key as PEM PKCS#8, for other tools; use it with
   the `-cert.pub`) and `<that>.pub` (the public key all three share).
2. Log in with your own name, sending the certificate with the key:
   - **OpenSSH:** `ssh -i <key> -o CertificateFile=<key>-cert.pub <name>@192.0.2.10`. OpenSSH
     also finds the certificate on its own when it sits next to the key under exactly
     `<key>-cert.pub`; the `CertificateFile` option makes it explicit.
   - **PuTTY 0.78 or later:** use the `.ppk` download (Connection > SSH > Auth > Credentials,
     "Private key file for authentication"). To build one yourself from the OpenSSH pair: in
     PuTTYgen, Conversions > Import key, then Key > Add certificate to key, then Save private key;
     or keep the key and set Connection > SSH > Auth > Credentials > "Certificate to use".
     Earlier PuTTY releases can't read a certificate and are refused.
   - **MobaXterm:** Session (or User sessions > New session), then SSH; Remote host: the box's
     address; Username: your admin name; Port: 22. Under Advanced SSH settings tick "Use private
     key" and browse to the box's `.ppk`. Connect. MobaXterm reads PPK format 3 since v21.5 and
     has its own certificate field (expert settings) since v25.1; use v25.1 or later.
3. The closed shell asks for a TOTP code, under the same lockout as :8443, then shows the menu for
   your role.

There is no way to skip the TOTP code on SSH and no SSH password login: the key is one factor and
the code the other. A bare box-issued key, sent without its certificate, is never accepted: sshd
refuses it, and `sneakers-sshd-run` audits the refusal (below), so :8443's audit log shows why the
login failed.

## sshd's configuration

accessd and `sneakers-sshd-run` render sshd's files from the access store into a staging directory,
check them with the pinned `sshd -t` and swap them into `/run/sneakers/ssh/` only when sshd accepts
them (`sshconfig.Install`, under an flock on `/run/sneakers/ssh.lock`). Beside `sshd_config` it
writes `banner`, which sshd sends before authentication (`Banner`): SSH takes only keys the box
issued, each with its certificate, then a TOTP code; a key comes from :8443, Access, "Get an SSH
key"; and it gives the OpenSSH command with `-o CertificateFile=<key>-cert.pub` and the PuTTY and
MobaXterm way (the `.ppk`). A config that fails the check
is never used, and the previous one stays.

- `AuthenticationMethods publickey`, `AuthorizedKeysFile none` and `TrustedUserCAKeys
  /var/lib/sneakers/ssh/root_key.pub`: the only keys sshd takes are certificates the box's root key
  signed for the admin's name ([access.md](access.md#issued-ssh-keys)). Password,
  keyboard-interactive and empty-password logins are off, and so is `PermitRootLogin`.
- `RevokedKeys /var/lib/sneakers/ssh/revoked.krl`: removed keys, as keys and as certificate serials.
- `DisableForwarding yes`, `PermitTunnel no`, `PermitUserRC no`, `PermitUserEnvironment no`, and no
  `Subsystem` line, so there is no sftp or scp.
- `ForceCommand /usr/bin/sneakers-shell` and `ExposeAuthInfo yes`, so the closed shell learns which
  key signed in.
- `AllowUsers` lists the admins who can sign in; with none, `DenyUsers *`.
- The algorithms are the modern set only: ed25519, ECDSA P-256 and P-384, RSA with SHA-2 signatures,
  and their certificate types; ML-KEM and sntrup761 hybrid key exchange or curve25519;
  ChaCha20-Poly1305 and AES-GCM; encrypt-then-MAC SHA-2 MACs.

The tests run the pinned static sshd's `sshd -t` on the rendered config, and
`TestRealSshdTakesOnlyTheRootKeysCertificates` logs in against it: a certificate from the root key
works, a plain key or another CA's certificate doesn't, and a revoked serial is refused.
`TestRealSshdAuditsABareIssuedKey` sends an issued key without its certificate and checks the
audit entry. The Static tools workflow runs them with `SNEAKERS_TEST_SSHD` pointing at the binary
it built.

### A key without its certificate

sshd's log (`LogLevel VERBOSE`, on `sneakers-sshd-run`'s stderr) passes through a watch on its way
out. For each `Failed publickey for <user> from <address> ... ssh2: ED25519 SHA256:<fingerprint>`
line whose fingerprint is a box-issued key in the access store, it writes an OS audit entry:
action `ssh.login`, outcome `refused`, code `ACCESS_KEY_NO_CERTIFICATE`, the login name as the
actor, the source address, the key's fingerprint, the key's owner as the target and its serial.
A certificate that's refused (expired, revoked, for another name) logs as `ED25519-CERT` and isn't
counted here, and neither is a key the box never issued. The log itself is passed on unchanged.

## sneakers-sshd-run

sshd runs under `sneakers-sshd-run --config-dir /run/sneakers/ssh` (`os/rootfs/services.d/sshd.yaml`:
in first boot accessd asks init to start it once the first admin exists, and at its own start when an
admin can sign in; always in normal operation, after netd and accessd, restarted whenever it stops).
It:

1. reads the access store and exits with `ACCESS_NO_ADMIN` while no admin can sign in;
2. waits until netd reports a management address, then renders, checks with `sshd -t` and swaps the
   files in;
3. writes its pid to `/run/sneakers/sshd.pid` and runs `sshd -D -e -f /run/sneakers/ssh/sshd_config`
   as its child (sshd's own `PidFile` is `none`), so every reload passes `sshd -t` first;
4. on a `SIGHUP` (accessd sends one when `sshd_config` changed) or a new address list on netd's
   `Watch` stream, renders and checks again, and sends sshd a `SIGHUP` only when the check passed and
   the config changed. A render sshd refuses is logged and audited (`sshd.config`, outcome
   `refused`); sshd keeps the config it has;
5. on `SIGTERM` stops sshd (`SIGTERM`, then `SIGKILL` after 10 seconds); when sshd exits on its own
   sshd-run exits with it and init restarts both.

Flags: `--config-dir`, `--state` (`/var/lib/sneakers`), `--sshd` (`/usr/sbin/sshd`), `--netd-socket`
and `--pid-file` (`/run/sneakers/sshd.pid`).

## The closed shell

`sneakers-shell` is every admin's login shell and sshd's `ForceCommand`. It first asks for a TOTP
code (`SshLoginService.VerifyTotp`, under the same lockout as :8443 sign-in,
[access.md](access.md#lockout-and-throttling)) and closes the connection when it is wrong or the
account is locked; then it offers only the appliance commands below, interactively (with `help`, line editing and tab completion) or one per connection
through the SSH command line:

```sh
ssh alice@192.0.2.10 status -o json
```

The interactive shell needs a terminal; without one it takes only a command on the SSH command line.
With no terminal, the code is one line of standard input, ended by Enter as LF, CRLF or a bare CR.

The shell splits the line itself; nothing is passed to `/bin/sh`, and the binary links nothing that
can start a program. Spaces and tabs separate words, single quotes keep everything to the next single
quote, double quotes keep everything to the next unescaped double quote (`\"` and `\\` are the only
escapes inside them), and a backslash outside quotes keeps the next character. `$`, `` ` ``, `;`,
`|`, `&`, `<`, `>`, `*` and `?` are ordinary characters: `status; id` is the unknown command
`status;`. A line longer than 64 KiB, with an open quote, a trailing backslash, invalid UTF-8 or a
control character is refused with `SHELL_PARSE`; an unknown command is `SHELL_UNKNOWN`.

| Command | Console | SSH | In this release |
|---|---|---|---|
| `status` | yes | yes | accessd |
| `network show`, `network set key=value...`, `network confirm <token>` | yes | yes | accessd; `set` reverts in 120 s unless kept |
| `network allow-list reset` | yes | no | accessd; typed `reset` |
| `keys list` | yes | yes | accessd; keys are issued on :8443 |
| `admins list` | yes | yes | accessd; admins are managed on :8443 |
| `recovery-key add` | yes | no | accessd |
| `setup recovery-key` | no | yes | accessd; first boot only |
| `shell` | no | yes | accessd; root operators; see [The root shell](#the-root-shell) |
| `tls show`, `backup ...`, `restore ...`, `upgrade ...`, `resources ...` | yes | yes | Not available in this release |
| `logs export`, `support-bundle` | no | yes | Not available in this release |
| `reboot`, `poweroff` | yes | yes | init, over `/run/sneakers/power.sock`; typed `reboot` or `poweroff`; always graceful |
| `<product> mcp ...` (`sneakers mcp ...`) | no | yes | Only while a product is installed; Not available in this release |

A command offered only in the other origin is refused with `ACCESS_FORBIDDEN` and isn't listed by
`help` or completed. `-o json` prints a command's result, or its error as
`{"error": {"code", "number", "message"}}`. The commands of later specs answer `NOT_AVAILABLE`
("Not available in this release.") until their services are on the box. The accessd commands go to
`/run/sneakers/access.sock`, which knows the login by its uid ([access.md](access.md#accesssock));
`network set` takes `hostname`, `dns`, `search`, `ntp`, `allow-list` (comma-separated lists),
`time-zone` and `https-proxy` on top of the current settings. While accessd is down they answer
`NOT_AVAILABLE` ("the appliance services are unavailable"), and `status` shows the last status
accessd kept, with the time it was taken.

### Product commands

The commands above are the base appliance's, and they are the same on every box. An installed
product adds its own commands in a group named after it, listed by `help` under its own heading
("Sneakers commands (the installed product)") and completed like the others. The shell reads the
product's name from the current product slot's header (`/var/lib/sneakers/product/current/bundle.json`,
the `<name>-product` header name without `-product`) when the login starts. With no product
installed there is no group: nothing in `help` or completion names a product command, and `mcp` or
`sneakers mcp` is `SHELL_UNKNOWN`. Today the product group holds `mcp`, which answers
`NOT_AVAILABLE` until the product's MCP switch lands.

## The root shell

A root operator ([access.md](access.md#roles-the-roster-and-step-up)) opens a root shell from the
closed shell:

1. `shell` asks accessd (`ElevationService.BeginRootShell`) for a challenge: 16 Crockford characters,
   shown with the time it is good until (the policy's minutes, 10 by default).
2. On :8443, signed in with a fresh step-up, the admin types the challenge
   (`RootShellService.IssueRootShellCode`) and gets an 8-character code: the first 40 bits of the root
   key's ed25519 signature over the challenge, the admin, the SSH source and the expiry. It is bound
   to that login and works once.
3. The admin types the code into the SSH session (`OpenRootShell`). Three wrong codes close the
   challenge, and they count toward the account's lockout. A right one gives a one-minute ticket.
4. The shell connects to `/run/sneakers/rootshell.sock` with the ticket and the terminal size; accessd
   starts `/usr/libexec/sneakers-elevated` as root with the connection as its terminal and relays
   data and resizes. The session ends after the policy's minutes, after 10 minutes idle, when the SSH
   client goes away, or when an owner ends it on the Sessions page.

The root shell is busybox ash. Its prompt, `[root@<host> <n> min left] <dir> # `, shows the kernel
host name ([network.md](network.md#dns-ntp-and-the-host-name): the configured name, else the DHCP
name, else the box's own `sneakers-<8 hex>`), the minutes left and the working directory; busybox is
built with the shell arithmetic and prompt escapes it needs (`build/busybox/busybox.config`).

With a product installed, `kubectl` and `helm` work in the root shell against its k0s with no setup:
`KUBECONFIG` is k0s's admin kubeconfig ([k0s.md](k0s.md#kubectl-and-helm-in-the-root-shell)).
Without one, the shell says so once at its start.

Every step is audited (`rootshell.begin`, `rootshell.code.issue`, `rootshell.open`, `rootshell.end`).
Removing an admin's key ends a root shell it opened.
